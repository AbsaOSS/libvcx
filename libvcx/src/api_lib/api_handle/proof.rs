use serde_json;

use crate::api_lib::api_handle::connection;
use crate::api_lib::api_handle::object_cache::ObjectCache;
use crate::aries::handlers::proof_presentation::verifier::verifier::Verifier;
use crate::aries::messages::a2a::A2AMessage;
use crate::error::prelude::*;
use crate::utils::error;

lazy_static! {
    static ref PROOF_MAP: ObjectCache<Verifier> = ObjectCache::<Verifier>::new("proofs-cache");
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "version", content = "data")]
enum Proofs {
    #[serde(rename = "2.0")]
    V3(Verifier),
}

pub fn create_proof(source_id: String,
                    requested_attrs: String,
                    requested_predicates: String,
                    revocation_details: String,
                    name: String) -> VcxResult<u32> {
    let verifier = Verifier::create(source_id, requested_attrs, requested_predicates, revocation_details, name)?;
    PROOF_MAP.add(verifier)
        .or(Err(VcxError::from(VcxErrorKind::CreateProof)))
}

pub fn is_valid_handle(handle: u32) -> bool {
    PROOF_MAP.has_handle(handle)
}

pub fn update_state(handle: u32, message: Option<&str>, connection_handle: u32) -> VcxResult<u32> {
    PROOF_MAP.get_mut(handle, |proof| {
        trace!("proof::update_state >>> handle: {}, message: {:?}, connection_handle: {}", handle, message, connection_handle);
        if !proof.has_transitions() { return Ok(proof.get_state().into()); }
        let send_message = connection::send_message_closure(connection_handle)?;

        if let Some(message) = message {
            let message: A2AMessage = serde_json::from_str(message)
                .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidOption, format!("Cannot updated state with message: Message deserialization failed: {:?}", err)))?;
            trace!("proof::update_state >>> updating using message {:?}", message);
            proof.handle_message(message.into(), Some(&send_message))?;
        } else {
            let messages = connection::get_messages(connection_handle)?;
            trace!("proof::update_state >>> found messages: {:?}", messages);
            if let Some((uid, message)) = proof.find_message_to_handle(messages) {
                proof.handle_message(message.into(), Some(&send_message))?;
                connection::update_message_status(connection_handle, uid)?;
            };
        }
        Ok(proof.get_state().into())
    })
}

pub fn get_state(handle: u32) -> VcxResult<u32> {
    PROOF_MAP.get(handle, |proof| {
        Ok(proof.get_state().into())
    })
}

pub fn get_proof_state(handle: u32) -> VcxResult<u32> {
    PROOF_MAP.get(handle, |proof| {
        Ok(proof.presentation_status())
    })
}

pub fn release(handle: u32) -> VcxResult<()> {
    PROOF_MAP.release(handle).or(Err(VcxError::from(VcxErrorKind::InvalidProofHandle)))
}

pub fn release_all() {
    PROOF_MAP.drain().ok();
}

pub fn to_string(handle: u32) -> VcxResult<String> {
    PROOF_MAP.get(handle, |proof| {
        serde_json::to_string(&Proofs::V3(proof.clone()))
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidState, format!("cannot serialize Proof proofect: {:?}", err)))
    })
}

pub fn get_source_id(handle: u32) -> VcxResult<String> {
    PROOF_MAP.get(handle, |proof| {
        Ok(proof.get_source_id())
    })
}

pub fn from_string(proof_data: &str) -> VcxResult<u32> {
    let proof: Proofs = serde_json::from_str(proof_data)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("cannot deserialize Proofs proofect: {:?}", err)))?;

    match proof {
        Proofs::V3(proof) => PROOF_MAP.add(proof)
    }
}

pub fn generate_proof_request_msg(handle: u32) -> VcxResult<String> {
    PROOF_MAP.get_mut(handle, |proof| {
        proof.generate_presentation_request_msg()
    })
}

pub fn send_proof_request(handle: u32, connection_handle: u32, comment: Option<String>) -> VcxResult<u32> {
    PROOF_MAP.get_mut(handle, |proof| {
        proof.send_presentation_request(connection::send_message_closure(connection_handle)?, comment.clone())?;
        Ok(error::SUCCESS.code_num)
    })
}

pub fn get_proof(handle: u32) -> VcxResult<String> {
    PROOF_MAP.get(handle, |proof| {
        proof.get_presentation()
    })
}

#[cfg(test)]
pub mod tests {
    use serde_json::Value;

    use agency_client::mocking::HttpClientMockResponse;

    use crate::api_lib::api_handle::connection::tests::build_test_connection_inviter_requested;
    use crate::api_lib::api_handle::proof;
    use crate::aries::handlers::proof_presentation::verifier::verifier::Verifier;
    use crate::aries::messages::proof_presentation::presentation::tests::_comment;
    use crate::utils::constants::*;
    use crate::utils::devsetup::*;
    use crate::utils::mockdata::mock_settings::MockBuilder;
    use crate::utils::mockdata::mockdata_proof;
    use crate::aries::handlers::proof_presentation::verifier::verifier::VerifierState;

    use super::*;

    fn create_default_proof() -> u32 {
        create_proof("1".to_string(),
                     REQUESTED_ATTRS.to_owned(),
                     REQUESTED_PREDICATES.to_owned(),
                     r#"{"support_revocation":false}"#.to_string(),
                     "Optional".to_owned()).unwrap()
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_create_proof_succeeds() {
        let _setup = SetupMocks::init();
        create_default_proof();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_revocation_details() {
        let _setup = SetupMocks::init();

        // No Revocation
        create_default_proof();

        // Support Revocation Success
        let revocation_details = json!({
            "to": 1234,
        });
        create_proof("1".to_string(),
                     REQUESTED_ATTRS.to_owned(),
                     REQUESTED_PREDICATES.to_owned(),
                     revocation_details.to_string(),
                     "Optional".to_owned()).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_to_string_succeeds() {
        let _setup = SetupMocks::init();

        let handle = create_default_proof();
        let proof_string = to_string(handle).unwrap();
        let s: Value = serde_json::from_str(&proof_string).unwrap();
        assert_eq!(s["version"], V3_OBJECT_SERIALIZE_VERSION);
        assert!(s["data"]["verifier_sm"].is_object());
        assert!(!proof_string.is_empty());
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_from_string_succeeds() {
        let _setup = SetupMocks::init();

        let handle = create_default_proof();
        let proof_data = to_string(handle).unwrap();
        let _hnadle2 = from_string(&proof_data).unwrap();
        let proof_data2 = to_string(handle).unwrap();
        assert_eq!(proof_data, proof_data2);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_release_proof() {
        let _setup = SetupMocks::init();

        let handle = create_default_proof();
        assert!(release(handle).is_ok());
        assert!(!is_valid_handle(handle));
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_send_proof_request() {
        let _setup = SetupMocks::init();

        let handle_conn = build_test_connection_inviter_requested();

        let handle_proof = create_default_proof();
        assert_eq!(send_proof_request(handle_proof, handle_conn, _comment()).unwrap(), error::SUCCESS.code_num);
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::PresentationRequestSent as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_get_proof_fails_with_no_proof() {
        let _setup = SetupMocks::init();

        let handle = create_default_proof();
        assert!(is_valid_handle(handle));
        assert!(get_proof(handle).is_err())
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_proof_update_state_v2() {
        let _setup = SetupMocks::init();
        let _mock_builder = MockBuilder::init().
            set_mock_result_for_validate_indy_proof(Ok(true));

        let handle_conn = build_test_connection_inviter_requested();
        let handle_proof = create_default_proof();

        send_proof_request(handle_proof, handle_conn, _comment()).unwrap();
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::PresentationRequestSent as u32);

        connection::release(handle_conn).unwrap();
        let handle_conn = build_test_connection_inviter_requested();

        update_state(handle_proof, Some(mockdata_proof::ARIES_PROOF_PRESENTATION), handle_conn).unwrap();

        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::Finished as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_update_state() {
        let _setup = SetupMocks::init();
        let _mock_builder = MockBuilder::init().
            set_mock_result_for_validate_indy_proof(Ok(true));

        let handle_conn = build_test_connection_inviter_requested();
        let handle_proof = create_default_proof();

        send_proof_request(handle_proof, handle_conn, _comment()).unwrap();
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::PresentationRequestSent as u32);

        update_state(handle_proof, Some(mockdata_proof::ARIES_PROOF_PRESENTATION), handle_conn).unwrap();
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::Finished as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_proof_validation_with_predicate() {
        let _setup = SetupMocks::init();
        let _mock_builder = MockBuilder::init().
            set_mock_result_for_validate_indy_proof(Ok(true));

        let handle_conn = build_test_connection_inviter_requested();
        let handle_proof = create_default_proof();

        send_proof_request(handle_proof, handle_conn, _comment()).unwrap();
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::PresentationRequestSent as u32);

        update_state(handle_proof, Some(mockdata_proof::ARIES_PROOF_PRESENTATION), handle_conn).unwrap();
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::Finished as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_update_state_with_reject_message() {
        let _setup = SetupMocks::init();

        let handle_conn = build_test_connection_inviter_requested();
        let handle_proof = create_default_proof();

        send_proof_request(handle_proof, handle_conn, _comment()).unwrap();

        update_state(handle_proof, Some(PROOF_REJECT_RESPONSE_STR_V2), handle_conn).unwrap();
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::Failed as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_send_presentation_request() {
        let _setup = SetupMocks::init();

        let handle_conn = build_test_connection_inviter_requested();
        let handle_proof = create_default_proof();

        send_proof_request(handle_proof, handle_conn, _comment()).unwrap();
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::PresentationRequestSent as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_get_proof() {
        let _setup = SetupMocks::init();
        let _mock_builder = MockBuilder::init().
            set_mock_result_for_validate_indy_proof(Ok(true));

        let handle_conn = build_test_connection_inviter_requested();
        let handle_proof = create_default_proof();

        send_proof_request(handle_proof, handle_conn, _comment()).unwrap();
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::PresentationRequestSent as u32);

        update_state(handle_proof, Some(mockdata_proof::ARIES_PROOF_PRESENTATION), handle_conn).unwrap();
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::Finished as u32);

        let proof_str = get_proof(handle_proof).unwrap();
        assert_eq!(proof_str, mockdata_proof::ARIES_PROOF_PRESENTATION.replace("\n", "").replace(" ", ""));
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_release_all() {
        let _setup = SetupMocks::init();

        let h1 = create_proof("1".to_string(), REQUESTED_ATTRS.to_owned(), REQUESTED_PREDICATES.to_owned(), r#"{"support_revocation":false}"#.to_string(), "Optional".to_owned()).unwrap();
        let h2 = create_proof("1".to_string(), REQUESTED_ATTRS.to_owned(), REQUESTED_PREDICATES.to_owned(), r#"{"support_revocation":false}"#.to_string(), "Optional".to_owned()).unwrap();
        let h3 = create_proof("1".to_string(), REQUESTED_ATTRS.to_owned(), REQUESTED_PREDICATES.to_owned(), r#"{"support_revocation":false}"#.to_string(), "Optional".to_owned()).unwrap();
        let h4 = create_proof("1".to_string(), REQUESTED_ATTRS.to_owned(), REQUESTED_PREDICATES.to_owned(), r#"{"support_revocation":false}"#.to_string(), "Optional".to_owned()).unwrap();
        let h5 = create_proof("1".to_string(), REQUESTED_ATTRS.to_owned(), REQUESTED_PREDICATES.to_owned(), r#"{"support_revocation":false}"#.to_string(), "Optional".to_owned()).unwrap();
        release_all();
        assert_eq!(release(h1).unwrap_err().kind(), VcxErrorKind::InvalidProofHandle);
        assert_eq!(release(h2).unwrap_err().kind(), VcxErrorKind::InvalidProofHandle);
        assert_eq!(release(h3).unwrap_err().kind(), VcxErrorKind::InvalidProofHandle);
        assert_eq!(release(h4).unwrap_err().kind(), VcxErrorKind::InvalidProofHandle);
        assert_eq!(release(h5).unwrap_err().kind(), VcxErrorKind::InvalidProofHandle);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_send_proof_request_can_be_retried() {
        let _setup = SetupMocks::init();

        let handle_conn = build_test_connection_inviter_requested();
        let handle_proof = create_default_proof();

        let _request = generate_proof_request_msg(handle_proof).unwrap();
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::Initial as u32);

        HttpClientMockResponse::set_next_response(agency_client::error::AgencyClientResult::Err(agency_client::error::AgencyClientError::from_msg(agency_client::error::AgencyClientErrorKind::IOError, "Sending message timeout.")));
        assert_eq!(send_proof_request(handle_proof, handle_conn, _comment()).unwrap_err().kind(), VcxErrorKind::IOError);
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::Initial as u32);

        // Retry sending proof request
        assert_eq!(send_proof_request(handle_proof, handle_conn, _comment()).unwrap(), 0);
        assert_eq!(get_state(handle_proof).unwrap(), VerifierState::PresentationRequestSent as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_proof_accepted() {
        let _setup = SetupMocks::init();
        let _mock_builder = MockBuilder::init().
            set_mock_result_for_validate_indy_proof(Ok(true));

        let handle_conn = build_test_connection_inviter_requested();
        let handle_proof = create_default_proof();

        let _request = generate_proof_request_msg(handle_proof).unwrap();
        send_proof_request(handle_proof, handle_conn, _comment()).unwrap();
        update_state(handle_proof, Some(mockdata_proof::ARIES_PROOF_PRESENTATION), handle_conn).unwrap();
        assert_eq!(proof::get_state(handle_proof).unwrap(), VerifierState::Finished as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_proof_errors() {
        let _setup = SetupMocks::init();

        let handle_conn = build_test_connection_inviter_requested();
        let handle_proof = create_default_proof();

        let bad_handle = 100000;
        let empty = r#""#;

        assert_eq!(send_proof_request(bad_handle, handle_conn, _comment()).unwrap_err().kind(), VcxErrorKind::InvalidHandle);
        assert_eq!(get_proof_state(handle_proof).unwrap(), 0);
        assert_eq!(create_proof("my source id".to_string(),
                                empty.to_string(),
                                "{}".to_string(),
                                r#"{"support_revocation":false}"#.to_string(),
                                "my name".to_string()).unwrap_err().kind(), VcxErrorKind::InvalidJson);
        assert_eq!(to_string(bad_handle).unwrap_err().kind(), VcxErrorKind::InvalidHandle);
        assert_eq!(get_source_id(bad_handle).unwrap_err().kind(), VcxErrorKind::InvalidHandle);
        assert_eq!(from_string(empty).unwrap_err().kind(), VcxErrorKind::InvalidJson);
    }
}
