use serde_json;

use agency_client::mocking::AgencyMockDecrypted;

use crate::api_lib::api_handle::connection;
use crate::api_lib::api_handle::object_cache::ObjectCache;
use crate::aries::{
    handlers::issuance::holder::holder::Holder,
    messages::a2a::A2AMessage,
    messages::issuance::credential_offer::CredentialOffer,
};
use crate::error::prelude::*;
use crate::settings::indy_mocks_enabled;
use crate::utils::constants::GET_MESSAGES_DECRYPTED_RESPONSE;
use crate::utils::error;
use crate::utils::mockdata::mockdata_credex::ARIES_CREDENTIAL_OFFER;

lazy_static! {
    static ref HANDLE_MAP: ObjectCache<Holder> = ObjectCache::<Holder>::new("credentials-cache");
}

// This enum is left only to avoid making breaking serialization changes
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "version", content = "data")]
enum Credentials {
    #[serde(rename = "2.0")]
    V3(Holder)
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Credential {}

fn handle_err(err: VcxError) -> VcxError {
    if err.kind() == VcxErrorKind::InvalidHandle {
        VcxError::from(VcxErrorKind::InvalidCredentialHandle)
    } else {
        err
    }
}

fn create_credential(source_id: &str, offer: &str) -> VcxResult<Option<Holder>> {
    trace!("create_credential >>> source_id: {}, offer: {}", source_id, secret!(&offer));

    let offer_message = serde_json::from_str::<serde_json::Value>(offer)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize Message: {:?}", err)))?;

    let offer_message = match offer_message {
        serde_json::Value::Array(_) => return Err(VcxError::from_msg(VcxErrorKind::InvalidJson, "Received offer in legacy format")),
        offer => offer
    };

    if let Ok(cred_offer) = serde_json::from_value::<CredentialOffer>(offer_message) {
        return Ok(Some(Holder::create(cred_offer, source_id)?));
    }

    // TODO: Return error in case of error
    Ok(None)
}

pub fn credential_create_with_offer(source_id: &str, offer: &str) -> VcxResult<u32> {
    trace!("credential_create_with_offer >>> source_id: {}, offer: {}", source_id, secret!(&offer));

    let cred_offer: CredentialOffer = serde_json::from_str(offer)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson,
                                          format!("Strict `aries` protocol is enabled. Can not parse `aries` formatted Credential Offer: {}", err)))?;

    let holder = Holder::create(cred_offer, source_id)?;
    return HANDLE_MAP.add(holder);
}

pub fn credential_create_with_msgid(source_id: &str, connection_handle: u32, msg_id: &str) -> VcxResult<(u32, String)> {
    trace!("credential_create_with_msgid >>> source_id: {}, connection_handle: {}, msg_id: {}", source_id, connection_handle, secret!(&msg_id));

    let offer = get_credential_offer_msg(connection_handle, &msg_id)?;
    trace!("credential_create_with_msgid ::: for msg_id {} found offer {}", msg_id, offer);

    let credential = create_credential(source_id, &offer)?
        .ok_or(VcxError::from_msg(VcxErrorKind::InvalidConnectionHandle, format!("Connection can not be used for Proprietary Issuance protocol")))?;

    let handle = HANDLE_MAP.add(credential)?;

    debug!("inserting credential {} into handle map", source_id);
    Ok((handle, offer))
}

pub fn update_state(handle: u32, message: Option<&str>, connection_handle: u32) -> VcxResult<u32> {
    HANDLE_MAP.get_mut(handle, |credential| {
        trace!("credential::update_state >>> ");
        if credential.is_terminal_state() { return Ok(credential.get_state().into()); }
        let send_message = connection::send_message_closure(connection_handle)?;

        if let Some(message) = message {
            let message: A2AMessage = serde_json::from_str(&message)
                .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidOption, format!("Cannot update state: Message deserialization failed: {:?}", err)))?;
            credential.step(message.into(), Some(&send_message))?;
        } else {
            let messages = connection::get_messages(connection_handle)?;
            if let Some((uid, msg)) = credential.find_message_to_handle(messages) {
                credential.step(msg.into(), Some(&send_message))?;
                connection::update_message_status(connection_handle, uid)?;
            }
        }
        Ok(credential.get_state().into())
    })
}

pub fn get_credential(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |credential| {
        Ok(json!(credential.get_credential()?.1).to_string())
    })
}

pub fn get_attributes(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |credential| {
        credential.get_attributes()
    })
}

pub fn get_attachment(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |credential| {
        credential.get_attachment()
    })
}

pub fn get_tails_location(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |credential| {
        credential.get_tails_location()
    })
}

pub fn get_tails_hash(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |credential| {
        credential.get_tails_hash()
    })
}

pub fn get_rev_reg_id(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |credential| {
        credential.get_rev_reg_id()
    })
}

pub fn is_revokable(handle: u32) -> VcxResult<bool> {
    HANDLE_MAP.get(handle, |credential| {
        credential.is_revokable()
    })
}

pub fn delete_credential(handle: u32) -> VcxResult<u32> {
    let source_id = get_source_id(handle).unwrap_or_default();
    trace!("Credential::delete_credential >>> credential_handle: {}, source_id: {}", handle, source_id);

    HANDLE_MAP.get(handle, |credential| {
        trace!("Deleting a credential: credential_handle {}, source_id {}", handle, source_id);

        credential.delete_credential()?;
        Ok(error::SUCCESS.code_num)
    })
        .map(|_| error::SUCCESS.code_num)
        .or(Err(VcxError::from(VcxErrorKind::InvalidCredentialHandle)))
        .and(release(handle))
        .and_then(|_| Ok(error::SUCCESS.code_num))
}

pub fn get_credential_offer(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |_credential| {
        Err(VcxError::from(VcxErrorKind::InvalidCredentialHandle)) // TODO: implement
    })
}

pub fn get_state(handle: u32) -> VcxResult<u32> {
    HANDLE_MAP.get(handle, |credential| {
        Ok(credential.get_state().into())
    }).map_err(handle_err)
}

/// #Returns
/// Credential request message serialized as String
pub fn generate_credential_request_msg(handle: u32, _my_pw_did: &str, _their_pw_did: &str) -> VcxResult<String> {
    HANDLE_MAP.get_mut(handle, |_credential| {
        Err(VcxError::from_msg(VcxErrorKind::ActionNotSupported, "This action is not implemented yet")) // TODO: implement
    }).map_err(handle_err)
}

pub fn send_credential_request(handle: u32, connection_handle: u32) -> VcxResult<u32> {
    trace!("Credential::send_credential_request >>> credential_handle: {}, connection_handle: {}", handle, connection_handle);
    HANDLE_MAP.get_mut(handle, |credential| {
        let my_pw_did = connection::get_pw_did(connection_handle)?;
        let send_message = connection::send_message_closure(connection_handle)?;
        credential.send_request(my_pw_did, send_message)?;
        let new_credential = credential.clone(); // TODO: Why are we doing this exactly?
        *credential = new_credential;
        Ok(error::SUCCESS.code_num)
    }).map_err(handle_err)
}

fn get_credential_offer_msg(connection_handle: u32, msg_id: &str) -> VcxResult<String> {
    trace!("get_credential_offer_msg >>> connection_handle: {}, msg_id: {}", connection_handle, msg_id);

    if indy_mocks_enabled() {
        AgencyMockDecrypted::set_next_decrypted_response(GET_MESSAGES_DECRYPTED_RESPONSE);
        AgencyMockDecrypted::set_next_decrypted_message(ARIES_CREDENTIAL_OFFER);
    }
    let credential_offer = match connection::get_message_by_id(connection_handle, msg_id.to_string()) {
        Ok(message) => match message {
            A2AMessage::CredentialOffer(_) => Ok(message),
            msg => {
                return Err(VcxError::from_msg(VcxErrorKind::InvalidMessages,
                                              format!("Message of different type was received: {:?}", msg)));
            }
        }
        Err(err) => Err(err)
    }?;

    return serde_json::to_string(&credential_offer).
        map_err(|err| {
            VcxError::from_msg(VcxErrorKind::InvalidState, format!("Cannot serialize Offers: {:?}", err))
        });
}

pub fn get_credential_offer_messages(connection_handle: u32) -> VcxResult<String> {
    trace!("Credential::get_credential_offer_messages >>> connection_handle: {}", connection_handle);

    AgencyMockDecrypted::set_next_decrypted_response(GET_MESSAGES_DECRYPTED_RESPONSE);
    AgencyMockDecrypted::set_next_decrypted_message(ARIES_CREDENTIAL_OFFER);

    let credential_offers: Vec<A2AMessage> = connection::get_messages(connection_handle)?
        .into_iter()
        .filter_map(|(_, a2a_message)| {
            match a2a_message {
                A2AMessage::CredentialOffer(_) => Some(a2a_message),
                _ => None
            }
        })
        .collect();

    Ok(json!(credential_offers).to_string())
}

pub fn release(handle: u32) -> VcxResult<()> {
    HANDLE_MAP.release(handle).map_err(handle_err)
}

pub fn release_all() {
    HANDLE_MAP.drain().ok();
}

pub fn is_valid_handle(handle: u32) -> bool {
    HANDLE_MAP.has_handle(handle)
}

pub fn to_string(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |credential| {
        serde_json::to_string(&Credentials::V3(credential.clone()))
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidState, format!("cannot serialize Credential credentialect: {:?}", err)))
    })
}

pub fn get_source_id(handle: u32) -> VcxResult<String> {
    HANDLE_MAP.get(handle, |credential| {
        Ok(credential.get_source_id())
    }).map_err(handle_err)
}

pub fn from_string(credential_data: &str) -> VcxResult<u32> {
    let credential: Credentials = serde_json::from_str(credential_data)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize Credential: {:?}", err)))?;

    match credential {
        Credentials::V3(credential) => HANDLE_MAP.add(credential)
    }
}

pub fn is_payment_required(handle: u32) -> VcxResult<bool> {
    HANDLE_MAP.get(handle, |_| {
        Ok(false)
    }).map_err(handle_err)
}

pub fn get_credential_status(handle: u32) -> VcxResult<u32> {
    HANDLE_MAP.get(handle, |credential| {
        credential.get_credential_status()
    })
}

#[cfg(test)]
pub mod tests {
    use crate::api_lib::api_handle::connection;
    use crate::api_lib::api_handle::credential::{credential_create_with_offer, get_attributes, get_credential, send_credential_request};
    use crate::aries::messages::issuance::credential::Credential;
    use crate::error::VcxErrorKind;
    use crate::utils::devsetup::*;
    use crate::utils::mockdata::mockdata_credex::{ARIES_CREDENTIAL_OFFER, ARIES_CREDENTIAL_OFFER_JSON_FORMAT, ARIES_CREDENTIAL_RESPONSE, CREDENTIAL_SM_FINISHED, CREDENTIAL_SM_OFFER_RECEIVED};
    use crate::utils::mockdata::mockdata_credex;
    use crate::aries::handlers::issuance::holder::holder::HolderState;

    use super::*;

    pub const BAD_CREDENTIAL_OFFER: &str = r#"{"version": "0.1","to_did": "LtMgSjtFcyPwenK9SHCyb8","from_did": "LtMgSjtFcyPwenK9SHCyb8","claim": {"account_num": ["8BEaoLf8TBmK4BUyX8WWnA"],"name_on_account": ["Alice"]},"schema_seq_no": 48,"issuer_did": "Pd4fnFtRBcMKRVC2go5w3j","claim_name": "Account Certificate","claim_id": "3675417066","msg_ref_id": "ymy5nth"}"#;

    fn _get_offer(handle: u32) -> String {
        let offers = get_credential_offer_messages(handle).unwrap();
        let offers: serde_json::Value = serde_json::from_str(&offers).unwrap();
        let offer = serde_json::to_string(&offers[0]).unwrap();
        offer
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_credential_create_with_offer() {
        let _setup = SetupDefaults::init();

        let handle = credential_create_with_offer("test_credential_create_with_offer", ARIES_CREDENTIAL_OFFER).unwrap();
        assert!(handle > 0);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_credential_create_with_offer_with_json_attach() {
        let _setup = SetupDefaults::init();

        let handle = credential_create_with_offer("test_credential_create_with_offer", ARIES_CREDENTIAL_OFFER_JSON_FORMAT).unwrap();
        assert!(handle > 0);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_credential_create_with_bad_offer() {
        let _setup = SetupDefaults::init();

        let err = credential_create_with_offer("test_credential_create_with_bad_offer", BAD_CREDENTIAL_OFFER).unwrap_err();
        assert_eq!(err.kind(), VcxErrorKind::InvalidJson);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_credential_serialize_deserialize() {
        let _setup = SetupDefaults::init();

        let handle1 = credential_create_with_offer("test_credential_serialize_deserialize", ARIES_CREDENTIAL_OFFER).unwrap();
        let cred_original_state = get_state(handle1).unwrap();
        let cred_original_serialized = to_string(handle1).unwrap();
        release(handle1).unwrap();

        let handle2 = from_string(&cred_original_serialized).unwrap();
        let cred_restored_serialized = to_string(handle2).unwrap();
        let cred_restored_state = get_state(handle2).unwrap();

        assert_eq!(cred_original_state, cred_restored_state);
        assert_eq!(cred_original_serialized, cred_restored_serialized);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn full_credential_test() {
        let _setup = SetupMocks::init();

        info!("full_credential_test:: going to build_test_connection");
        let handle_conn = connection::tests::build_test_connection_inviter_requested();

        info!("full_credential_test:: going to _get_offer");
        let offer = _get_offer(handle_conn);

        info!("full_credential_test:: going to credential_create_with_offer");
        let handle_cred = credential_create_with_offer("TEST_CREDENTIAL", &offer).unwrap();
        assert_eq!(HolderState::OfferReceived as u32, get_state(handle_cred).unwrap());

        info!("full_credential_test:: going get offered attributes from offer received state");
        let offer_attrs: String = get_attributes(handle_cred).unwrap();
        info!("full_credential_test:: obtained offered attributes: {}", offer_attrs);
        let offer_attrs: serde_json::Value = serde_json::from_str(&offer_attrs).unwrap();
        let offer_attrs_expected: serde_json::Value = serde_json::from_str(mockdata_credex::OFFERED_ATTRIBUTES).unwrap();
        assert_eq!(offer_attrs, offer_attrs_expected);

        info!("full_credential_test:: going to send_credential_request");
        send_credential_request(handle_cred, handle_conn).unwrap();
        assert_eq!(HolderState::RequestSent as u32, get_state(handle_cred).unwrap());

        AgencyMockDecrypted::set_next_decrypted_response(GET_MESSAGES_DECRYPTED_RESPONSE);
        AgencyMockDecrypted::set_next_decrypted_message(ARIES_CREDENTIAL_RESPONSE);

        info!("full_credential_test:: going to update_state, should receive credential");
        update_state(handle_cred, None, handle_conn).unwrap();
        assert_eq!(get_state(handle_cred).unwrap(), HolderState::Finished as u32);

        info!("full_credential_test:: going to get_credential");
        let msg = get_credential(handle_cred).unwrap();
        info!("full_credential_test:: get_credential returned {}", msg);
        let msg_value: serde_json::Value = serde_json::from_str(&msg).unwrap();

        info!("full_credential_test:: going to deserialize credential: {:?}", msg_value);
        let _credential_struct: Credential = serde_json::from_str(msg_value.to_string().as_str()).unwrap();

        info!("full_credential_test:: going get offered attributes from final state");
        let offer_attrs: String = get_attributes(handle_cred).unwrap();
        info!("full_credential_test:: obtained offered attributes: {}", offer_attrs);
        let offer_attrs: serde_json::Value = serde_json::from_str(&offer_attrs).unwrap();
        let offer_attrs_expected: serde_json::Value = serde_json::from_str(mockdata_credex::OFFERED_ATTRIBUTES).unwrap();
        assert_eq!(offer_attrs, offer_attrs_expected);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_get_attributes_json_attach() {
        let _setup = SetupMocks::init();

        let handle_cred = credential_create_with_offer("TEST_CREDENTIAL", ARIES_CREDENTIAL_OFFER_JSON_FORMAT).unwrap();
        assert_eq!(HolderState::OfferReceived as u32, get_state(handle_cred).unwrap());

        let offer_attrs: String = get_attributes(handle_cred).unwrap();
        let offer_attrs: serde_json::Value = serde_json::from_str(&offer_attrs).unwrap();
        let offer_attrs_expected: serde_json::Value = serde_json::from_str(mockdata_credex::OFFERED_ATTRIBUTES).unwrap();
        assert_eq!(offer_attrs, offer_attrs_expected);
    }

    #[test]
    #[cfg(feature = "general_test")]
    #[cfg(feature = "to_restore")] // todo: generate_credential_request_msg is not implemented for v3
    fn test_get_request_msg() {
        let _setup = SetupMocks::init();

        let connection_h = connection::tests::build_test_connection_inviter_invited();

        let offer = _get_offer(connection_h);

        let my_pw_did = connection::get_pw_did(connection_h).unwrap();
        let their_pw_did = connection::get_their_pw_did(connection_h).unwrap();

        let c_h = credential_create_with_offer("TEST_CREDENTIAL", &offer).unwrap();
        assert_eq!(HolderState::OfferReceived as u32, get_state(c_h).unwrap());

        let msg = generate_credential_request_msg(c_h, &my_pw_did, &their_pw_did).unwrap();
        // serde_json::from_str::<CredentialRequest>(&msg).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_get_credential_offer() {
        let _setup = SetupMocks::init();

        let connection_h = connection::tests::build_test_connection_invitee_completed();

        let offer = get_credential_offer_messages(connection_h).unwrap();
        let o: serde_json::Value = serde_json::from_str(&offer).unwrap();
        debug!("Serialized credential offer: {:?}", &o[0]);
        let _credential_offer: CredentialOffer = serde_json::from_str(&o[0].to_string()).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    #[cfg(feature = "to_restore")] // get_credential_offer not implemented for aries
    fn test_get_credential_offer_and_deserialize() {
        let _setup = SetupMocks::init();

        let handle = from_string(CREDENTIAL_SM_OFFER_RECEIVED).unwrap();
        let offer_string = get_credential_offer(handle).unwrap();
        serde_json::Value::from(offer_string);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_get_credential_and_deserialize() {
        let _setup = SetupMocks::init();

        let handle = from_string(CREDENTIAL_SM_FINISHED).unwrap();
        let cred_string: String = get_credential(handle).unwrap();
        let cred_value: serde_json::Value = serde_json::from_str(&cred_string).unwrap();
        let _credential_struct: Credential = serde_json::from_str(cred_value.to_string().as_str()).unwrap();
    }
}
