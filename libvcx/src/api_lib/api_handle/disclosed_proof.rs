use serde_json;

use agency_client::mocking::AgencyMockDecrypted;

use crate::api_lib::api_handle::connection;
use crate::api_lib::api_handle::object_cache::ObjectCache;
use crate::aries::{
    handlers::proof_presentation::prover::prover::Prover,
    messages::proof_presentation::presentation_request::PresentationRequest,
};
use crate::aries::messages::a2a::A2AMessage;
use crate::error::prelude::*;
use crate::settings::indy_mocks_enabled;
use crate::utils::constants::GET_MESSAGES_DECRYPTED_RESPONSE;
use crate::utils::error;
use crate::utils::mockdata::mockdata_proof::ARIES_PROOF_REQUEST_PRESENTATION;

lazy_static! {
    static ref HANDLE_MAP: ObjectCache<Prover> = ObjectCache::<Prover>::new("disclosed-proofs-cache");
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "version", content = "data")]
enum DisclosedProofs {
    #[serde(rename = "2.0")]
    V3(Prover),
}

fn handle_err(err: VcxError) -> VcxError {
    if err.kind() == VcxErrorKind::InvalidHandle {
        VcxError::from(VcxErrorKind::InvalidDisclosedProofHandle)
    } else {
        err
    }
}

pub fn create_proof(source_id: &str, proof_req: &str) -> VcxResult<u32> {
    trace!("create_proof >>> source_id: {}, proof_req: {}", source_id, proof_req);
    debug!("creating disclosed proof with id: {}", source_id);

    let presentation_request: PresentationRequest = serde_json::from_str(proof_req)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson,
                                          format!("Strict `aries` protocol is enabled. Can not parse `aries` formatted Presentation Request: {}\nError: {}", proof_req, err)))?;

    let proof = Prover::create(source_id, presentation_request)?;
    HANDLE_MAP.add(proof)
}

pub fn create_proof_with_msgid(source_id: &str, connection_handle: u32, msg_id: &str) -> VcxResult<(u32, String)> {
    if !connection::is_v3_connection(connection_handle)? {
        return Err(VcxError::from_msg(VcxErrorKind::InvalidConnectionHandle, format!("Connection can not be used for Proprietary Issuance protocol")));
    };

    let proof_request = get_proof_request(connection_handle, &msg_id)?;

    let presentation_request: PresentationRequest = serde_json::from_str(&proof_request)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson,
                                          format!("Strict `aries` protocol is enabled. Can not parse `aries` formatted Presentation Request: {}\nError: {}", proof_request, err)))?;

    let proof = Prover::create(source_id, presentation_request)?;

    let handle = HANDLE_MAP.add(proof)?;

    debug!("inserting disclosed proof {} into handle map", source_id);
    Ok((handle, proof_request))
}

pub fn get_state(handle: u32) -> VcxResult<u32> {
    HANDLE_MAP.get(handle, |proof| {
        Ok(proof.get_state().into())
    }).or(Err(VcxError::from(VcxErrorKind::InvalidConnectionHandle)))
}

pub fn update_state(handle: u32, message: Option<&str>, connection_handle: u32) -> VcxResult<u32> {
    HANDLE_MAP.get_mut(handle, |proof| {
        trace!("disclosed_proof::update_state >>> connection_handle: {:?}, message: {:?}", connection_handle, message);
        if !proof.has_transitions() {
            trace!("disclosed_proof::update_state >> found no available transition");
            return Ok(proof.get_state().into());
        }
        let send_message = connection::send_message_closure(connection_handle)?;

        if let Some(message) = message {
            let message: A2AMessage = serde_json::from_str(message)
                .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidOption, format!("Can not updated state with message: Message deserialization failed: {:?}", err)))?;
            trace!("disclosed_proof::update_state >>> updating using message {:?}", message);
            proof.handle_message(message.into(), Some(&send_message))?;
        } else {
            let messages = connection::get_messages(connection_handle)?;
            trace!("disclosed_proof::update_state >>> found messages: {:?}", messages);
            if let Some((uid, message)) = proof.find_message_to_handle(messages) {
                proof.handle_message(message.into(), Some(&send_message))?;
                connection::update_message_status(connection_handle, uid)?;
            };
        }
        Ok(proof.get_state().into())
    })
}

pub fn to_string(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |proof| {
        serde_json::to_string(&DisclosedProofs::V3(proof.clone()))
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidState, format!("cannot serialize DisclosedProof proofect: {:?}", err)))
    })
}

pub fn from_string(proof_data: &str) -> VcxResult<u32> {
    let proof: DisclosedProofs = serde_json::from_str(proof_data)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("cannot deserialize DisclosedProofs object: {:?}", err)))?;

    match proof {
        DisclosedProofs::V3(proof) => HANDLE_MAP.add(proof)
    }
}

pub fn release(handle: u32) -> VcxResult<()> {
    HANDLE_MAP.release(handle).map_err(handle_err)
}

pub fn release_all() {
    HANDLE_MAP.drain().ok();
}

pub fn generate_proof_msg(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |proof| {
        proof.generate_presentation_msg()
    })
}

pub fn send_proof(handle: u32, connection_handle: u32) -> VcxResult<u32> {
    HANDLE_MAP.get_mut(handle, |proof| {
        let send_message = connection::send_message_closure(connection_handle)?;
        proof.send_presentation(&send_message)?;
        let new_proof = proof.clone();
        *proof = new_proof;
        Ok(error::SUCCESS.code_num)
    })
}

pub fn generate_reject_proof_msg(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get_mut(handle, |_| {
        Err(VcxError::from_msg(VcxErrorKind::ActionNotSupported,
                               "Action generate_reject_proof_msg is not implemented for V3 disclosed proof."))
    })
}

pub fn reject_proof(handle: u32, connection_handle: u32) -> VcxResult<u32> {
    HANDLE_MAP.get_mut(handle, |proof| {
        let send_message = connection::send_message_closure(connection_handle)?;
        proof.decline_presentation_request(&send_message, Some(String::from("Presentation Request was rejected")), None)?;
        let new_proof = proof.clone();
        *proof = new_proof;
        Ok(error::SUCCESS.code_num)
    })
}

pub fn generate_proof(handle: u32, credentials: String, self_attested_attrs: String) -> VcxResult<u32> {
    HANDLE_MAP.get_mut(handle, |proof| {
        proof.generate_presentation(credentials.clone(), self_attested_attrs.clone())?;
        Ok(error::SUCCESS.code_num)
    }).map(|_| error::SUCCESS.code_num)
}

pub fn decline_presentation_request(handle: u32, connection_handle: u32, reason: Option<String>, proposal: Option<String>) -> VcxResult<u32> {
    HANDLE_MAP.get_mut(handle, |proof| {
        let send_message = connection::send_message_closure(connection_handle)?;
        proof.decline_presentation_request(&send_message, reason.clone(), proposal.clone())?;
        let new_proof = proof.clone();
        *proof = new_proof;
        Ok(error::SUCCESS.code_num)
    }).map(|_| error::SUCCESS.code_num)
}

pub fn retrieve_credentials(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get_mut(handle, |proof| {
        proof.retrieve_credentials()
    })
}

pub fn get_proof_request_data(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get_mut(handle, |proof| {
        proof.presentation_request_data()
    })
}

pub fn get_proof_request_attachment(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get_mut(handle, |proof| {
        proof.get_proof_request_attachment()
    })
}

pub fn is_valid_handle(handle: u32) -> bool {
    HANDLE_MAP.has_handle(handle)
}

fn get_proof_request(connection_handle: u32, msg_id: &str) -> VcxResult<String> {
    if !connection::is_v3_connection(connection_handle)? {
        return Err(VcxError::from_msg(VcxErrorKind::InvalidConnectionHandle, format!("Connection can not be used for Proprietary Issuance protocol")));
    };

    if indy_mocks_enabled() {
        AgencyMockDecrypted::set_next_decrypted_response(GET_MESSAGES_DECRYPTED_RESPONSE);
        AgencyMockDecrypted::set_next_decrypted_message(ARIES_PROOF_REQUEST_PRESENTATION);
    }

    let presentation_request = {
        trace!("Prover::get_presentation_request >>> connection_handle: {:?}, msg_id: {:?}", connection_handle, msg_id);

        let message = connection::get_message_by_id(connection_handle, msg_id.to_string())?;

        match message {
            A2AMessage::PresentationRequest(presentation_request) => presentation_request,
            msg => {
                return Err(VcxError::from_msg(VcxErrorKind::InvalidMessages,
                                              format!("Message of different type was received: {:?}", msg)));
            }
        }
    };
    serde_json::to_string_pretty(&presentation_request)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot serialize message: {}", err)))
}

pub fn get_proof_request_messages(connection_handle: u32) -> VcxResult<String> {
    trace!("get_proof_request_messages >>> connection_handle: {}", connection_handle);

    if !connection::is_v3_connection(connection_handle)? {
        return Err(VcxError::from_msg(VcxErrorKind::InvalidConnectionHandle, format!("Connection can not be used for Proprietary Issuance protocol")));
    }

    let presentation_requests: Vec<A2AMessage> =
        connection::get_messages(connection_handle)?
            .into_iter()
            .filter_map(|(_, message)| {
                match message {
                    A2AMessage::PresentationRequest(_) => Some(message),
                    _ => None
                }
            })
            .collect();

    Ok(json!(presentation_requests).to_string())
}

pub fn get_source_id(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |proof| {
        Ok(proof.get_source_id())
    }).map_err(handle_err)
}

pub fn get_presentation_status(handle: u32) -> VcxResult<u32> {
    HANDLE_MAP.get(handle, |proof| {
        Ok(proof.presentation_status())
    })
}

#[cfg(test)]
mod tests {
    extern crate serde_json;

    use serde_json::Value;

    use crate::aries::messages::proof_presentation::presentation_request::PresentationRequestData;
    use crate::utils;
    use crate::utils::constants::{ARIES_PROVER_CREDENTIALS, ARIES_PROVER_SELF_ATTESTED_ATTRS, GET_MESSAGES_DECRYPTED_RESPONSE};
    use crate::utils::devsetup::*;
    use crate::utils::mockdata::mock_settings::MockBuilder;
    use crate::utils::mockdata::mockdata_proof;
    use crate::utils::mockdata::mockdata_proof::{ARIES_PROOF_PRESENTATION_ACK, ARIES_PROOF_REQUEST_PRESENTATION};
    use crate::aries::handlers::proof_presentation::prover::prover::ProverState;

    use super::*;

    fn _get_proof_request_messages(connection_h: u32) -> String {
        let requests = get_proof_request_messages(connection_h).unwrap();
        let requests: Value = serde_json::from_str(&requests).unwrap();
        let requests = serde_json::to_string(&requests[0]).unwrap();
        requests
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_create_proof() {
        let _setup = SetupMocks::init();

        assert!(create_proof("1", ARIES_PROOF_REQUEST_PRESENTATION).unwrap() > 0);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_create_fails() {
        let _setup = SetupMocks::init();

        assert_eq!(create_proof("1", "{}").unwrap_err().kind(), VcxErrorKind::InvalidJson);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_proof_cycle() {
        let _setup = SetupMocks::init();

        let connection_h = connection::tests::build_test_connection_inviter_requested();

        AgencyMockDecrypted::set_next_decrypted_response(GET_MESSAGES_DECRYPTED_RESPONSE);
        AgencyMockDecrypted::set_next_decrypted_message(ARIES_PROOF_REQUEST_PRESENTATION);

        let request = _get_proof_request_messages(connection_h);

        let handle_proof = create_proof("TEST_CREDENTIAL", &request).unwrap();
        assert_eq!(ProverState::Initial as u32, get_state(handle_proof).unwrap());

        let _mock_builder = MockBuilder::init().
            set_mock_generate_indy_proof("{\"selected\":\"credentials\"}");

        generate_proof(handle_proof, String::from("{\"selected\":\"credentials\"}"), "{}".to_string()).unwrap();
        send_proof(handle_proof, connection_h).unwrap();
        assert_eq!(ProverState::PresentationSent as u32, get_state(handle_proof).unwrap());

        update_state(handle_proof, Some(ARIES_PROOF_PRESENTATION_ACK), connection_h).unwrap();
        assert_eq!(ProverState::Finished as u32, get_state(handle_proof).unwrap());
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_proof_update_state_v2() {
        let _setup = SetupMocks::init();

        let connection_handle = connection::tests::build_test_connection_inviter_requested();

        AgencyMockDecrypted::set_next_decrypted_response(GET_MESSAGES_DECRYPTED_RESPONSE);
        AgencyMockDecrypted::set_next_decrypted_message(mockdata_proof::ARIES_PRESENTATION_REQUEST);

        let request = _get_proof_request_messages(connection_handle);

        let handle = create_proof("TEST_CREDENTIAL", &request).unwrap();
        assert_eq!(ProverState::Initial as u32, get_state(handle).unwrap());

        generate_proof(handle, ARIES_PROVER_CREDENTIALS.to_string(), ARIES_PROVER_SELF_ATTESTED_ATTRS.to_string()).unwrap();
        assert_eq!(ProverState::PresentationPrepared as u32, get_state(handle).unwrap());

        send_proof(handle, connection_handle).unwrap();
        assert_eq!(ProverState::PresentationSent as u32, get_state(handle).unwrap());

        connection::release(connection_handle).unwrap();
        let connection_handle = connection::tests::build_test_connection_inviter_requested();

        AgencyMockDecrypted::set_next_decrypted_response(GET_MESSAGES_DECRYPTED_RESPONSE);
        AgencyMockDecrypted::set_next_decrypted_message(mockdata_proof::ARIES_PROOF_PRESENTATION_ACK);

        update_state(handle, None, connection_handle).unwrap();
        assert_eq!(ProverState::Finished as u32, get_state(handle).unwrap());
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_proof_reject_cycle() {
        let _setup = SetupMocks::init();

        let connection_h = connection::tests::build_test_connection_inviter_requested();

        AgencyMockDecrypted::set_next_decrypted_response(GET_MESSAGES_DECRYPTED_RESPONSE);
        AgencyMockDecrypted::set_next_decrypted_message(ARIES_PROOF_REQUEST_PRESENTATION);

        let request = _get_proof_request_messages(connection_h);

        let handle = create_proof("TEST_CREDENTIAL", &request).unwrap();
        assert_eq!(ProverState::Initial as u32, get_state(handle).unwrap());

        reject_proof(handle, connection_h).unwrap();
        assert_eq!(ProverState::Failed as u32, get_state(handle).unwrap());
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn get_state_test() {
        let _setup = SetupMocks::init();

        let handle = create_proof("id", ARIES_PROOF_REQUEST_PRESENTATION).unwrap();
        assert_eq!(ProverState::Initial as u32, get_state(handle).unwrap())
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn to_string_test() {
        let _setup = SetupMocks::init();

        let handle = create_proof("id", ARIES_PROOF_REQUEST_PRESENTATION).unwrap();

        let serialized = to_string(handle).unwrap();
        let j: Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(j["version"], utils::constants::V3_OBJECT_SERIALIZE_VERSION);

        let handle_2 = from_string(&serialized).unwrap();
        assert_ne!(handle, handle_2);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_deserialize_fails() {
        let _setup = SetupDefaults::init();

        assert_eq!(from_string("{}").unwrap_err().kind(), VcxErrorKind::InvalidJson);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_get_proof_request() {
        let _setup = SetupMocks::init();

        let connection_h = connection::tests::build_test_connection_invitee_completed();

        let request = get_proof_request(connection_h, "123").unwrap();
        let _request: PresentationRequest = serde_json::from_str(&request).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_deserialize_succeeds_with_self_attest_allowed() {
        let _setup = SetupDefaults::init();

        let handle = create_proof("id", ARIES_PROOF_REQUEST_PRESENTATION).unwrap();

        let serialized = to_string(handle).unwrap();
        from_string(&serialized).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_get_proof_request_attachment() {
        let _setup = SetupMocks::init();

        let connection_h = connection::tests::build_test_connection_inviter_requested();

        AgencyMockDecrypted::set_next_decrypted_response(GET_MESSAGES_DECRYPTED_RESPONSE);
        AgencyMockDecrypted::set_next_decrypted_message(ARIES_PROOF_REQUEST_PRESENTATION);

        let request = _get_proof_request_messages(connection_h);

        let handle = create_proof("TEST_CREDENTIAL", &request).unwrap();
        assert_eq!(ProverState::Initial as u32, get_state(handle).unwrap());

        let attrs = get_proof_request_attachment(handle).unwrap();
        let _attrs: PresentationRequestData = serde_json::from_str(&attrs).unwrap();
    }
}
