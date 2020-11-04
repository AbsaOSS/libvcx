use serde_json;

use aries::handlers::issuance::issuer::issuer::Issuer;
use aries::messages::a2a::A2AMessage;
use connection;
use error::prelude::*;
use utils::error;
use utils::object_cache::ObjectCache;

lazy_static! {
    static ref ISSUER_CREDENTIAL_MAP: ObjectCache<Issuer> = ObjectCache::<Issuer>::new("issuer-credentials-cache");
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "version", content = "data")]
enum IssuerCredentials {
    #[serde(rename = "2.0")]
    V3(Issuer),
}

pub fn issuer_credential_create(cred_def_handle: u32,
                                source_id: String,
                                issuer_did: String,
                                credential_name: String,
                                credential_data: String,
                                price: u64) -> VcxResult<u32> {
    trace!("issuer_credential_create >>> cred_def_handle: {}, source_id: {}, issuer_did: {}, credential_name: {}, credential_data: {}, price: {}",
           cred_def_handle, source_id, issuer_did, credential_name, secret!(&credential_data), price);

    let issuer = Issuer::create(cred_def_handle, &credential_data, &source_id)?;
    ISSUER_CREDENTIAL_MAP.add(issuer)
}

pub fn update_state(handle: u32, message: Option<&str>, connection_handle: Option<u32>) -> VcxResult<u32> {
    ISSUER_CREDENTIAL_MAP.get_mut(handle, |credential| {
        trace!("issuer_credential::update_state >>> ");

        if credential.is_terminal_state() { return credential.get_state(); }

        if let Some(message) = message {
            let message: A2AMessage = ::serde_json::from_str(&message)
                .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidOption, format!("Cannot update state: Message deserialization failed: {:?}", err)))?;

            credential.step(message.into())?;
            return credential.get_state();
        }

        let conn_handle = credential.maybe_update_connection_handle(connection_handle);

        let messages = connection::get_messages(conn_handle)?;

        match credential.find_message_to_handle(messages) {
            Some((uid, msg)) => {
                credential.step(msg.into())?;
                connection::update_message_status(conn_handle, uid)?;
                credential.get_state()
            }
            None => credential.get_state()
        }
    })
}

pub fn get_state(handle: u32) -> VcxResult<u32> {
    ISSUER_CREDENTIAL_MAP.get(handle, |credential| {
        credential.get_state()
    })
}

pub fn get_credential_status(handle: u32) -> VcxResult<u32> {
    ISSUER_CREDENTIAL_MAP.get(handle, |credential| {
        credential.get_credential_status()
    })
}

pub fn release(handle: u32) -> VcxResult<()> {
    ISSUER_CREDENTIAL_MAP.release(handle)
        .or(Err(VcxError::from(VcxErrorKind::InvalidIssuerCredentialHandle)))
}

pub fn release_all() {
    ISSUER_CREDENTIAL_MAP.drain().ok();
}

pub fn is_valid_handle(handle: u32) -> bool {
    ISSUER_CREDENTIAL_MAP.has_handle(handle)
}

pub fn to_string(handle: u32) -> VcxResult<String> {
    ISSUER_CREDENTIAL_MAP.get(handle, |credential| {
        serde_json::to_string(&IssuerCredentials::V3(credential.clone()))
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidState, format!("cannot serialize IssuerCredential credentialect: {:?}", err)))
    })
}

pub fn from_string(credential_data: &str) -> VcxResult<u32> {
    let issuer_credential: IssuerCredentials = serde_json::from_str(credential_data)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize IssuerCredential: {:?}", err)))?;

    match issuer_credential {
        IssuerCredentials::V3(credential) => ISSUER_CREDENTIAL_MAP.add(credential)
    }
}

pub fn generate_credential_offer_msg(handle: u32) -> VcxResult<(String, String)> {
    ISSUER_CREDENTIAL_MAP.get_mut(handle, |_| {
        Err(VcxError::from_msg(VcxErrorKind::ActionNotSupported, "Not implemented yet"))
    })
}

pub fn send_credential_offer(handle: u32, connection_handle: u32, comment: Option<String>) -> VcxResult<u32> {
    ISSUER_CREDENTIAL_MAP.get_mut(handle, |credential| {
        credential.send_credential_offer(connection_handle, comment.clone())?;
        let new_credential = credential.clone();
        *credential = new_credential;
        Ok(error::SUCCESS.code_num)
    })
}

pub fn generate_credential_msg(handle: u32, _my_pw_did: &str) -> VcxResult<String> {
    ISSUER_CREDENTIAL_MAP.get_mut(handle, |_| {
        Err(VcxError::from_msg(VcxErrorKind::ActionNotSupported, "Not implemented yet")) // TODO: implement
    })
}

pub fn send_credential(handle: u32, connection_handle: u32) -> VcxResult<u32> {
    ISSUER_CREDENTIAL_MAP.get_mut(handle, |credential| {
        credential.send_credential(connection_handle)?;
        Ok(error::SUCCESS.code_num)
    })
}

pub fn revoke_credential(handle: u32) -> VcxResult<()> {
    trace!("revoke_credential >>> handle: {}", handle);
    ISSUER_CREDENTIAL_MAP.get_mut(handle, |credential| {
        credential.revoke_credential(true)
    })
}

pub fn revoke_credential_local(handle: u32) -> VcxResult<()> {
    ISSUER_CREDENTIAL_MAP.get_mut(handle, |credential| {
        credential.revoke_credential(false)
    })
}

pub fn convert_to_map(s: &str) -> VcxResult<serde_json::Map<String, serde_json::Value>> {
    serde_json::from_str(s)
        .map_err(|_| {
            warn!("{}", error::INVALID_ATTRIBUTES_STRUCTURE.message);
            VcxError::from_msg(VcxErrorKind::InvalidAttributesStructure, error::INVALID_ATTRIBUTES_STRUCTURE.message)
        })
}

pub fn get_credential_attributes(handle: u32) -> VcxResult<String> {
    ISSUER_CREDENTIAL_MAP.get(handle, |_| {
        Err(VcxError::from(VcxErrorKind::NotReady)) // TODO: implement
    })
}

pub fn get_rev_reg_id(handle: u32) -> VcxResult<String> {
    ISSUER_CREDENTIAL_MAP.get(handle, |credential| {
        credential.get_rev_reg_id() 
    })
}

pub fn get_source_id(handle: u32) -> VcxResult<String> {
    ISSUER_CREDENTIAL_MAP.get(handle, |credential| {
        credential.get_source_id()
    })
}

#[cfg(test)]
pub mod tests {
    use ::{issuer_credential, settings};
    use api::VcxStateType;
    use connection::tests::build_test_connection_inviter_requested;
    use credential_def::tests::create_cred_def_fake;
    use libindy::utils::anoncreds::libindy_create_and_store_credential_def;
    use libindy::utils::LibindyMock;
    use utils::constants::{SCHEMAS_JSON, V3_OBJECT_SERIALIZE_VERSION, REV_REG_ID};
    #[allow(unused_imports)]
    use utils::devsetup::*;
    use utils::httpclient::HttpClientMockResponse;
    use utils::mockdata::mockdata_connection::ARIES_CONNECTION_ACK;
    use utils::mockdata::mockdata_credex::ARIES_CREDENTIAL_REQUEST;

    use super::*;

    static DEFAULT_CREDENTIAL_NAME: &str = "Credential";
    static DEFAULT_CREDENTIAL_ID: &str = "defaultCredentialId";

    static CREDENTIAL_DATA: &str =
        r#"{"address2":["101 Wilson Lane"],
        "zip":["87121"],
        "state":["UT"],
        "city":["SLC"],
        "address1":["101 Tela Lane"]
        }"#;

    pub fn util_put_credential_def_in_issuer_wallet(_schema_seq_num: u32, _wallet_handle: i32) {
        let issuer_did = settings::get_config_value(settings::CONFIG_INSTITUTION_DID).unwrap();
        let tag = "test_tag";
        let config = "{support_revocation: false}";

        libindy_create_and_store_credential_def(&issuer_did, SCHEMAS_JSON, tag, None, config).unwrap();
    }

    fn _issuer_credential_create() -> u32 {
        issuer_credential_create(create_cred_def_fake(),
                                 "1".to_string(),
                                 "8XFh8yBzrpJQmNyZzgoTqB".to_owned(),
                                 "credential_name".to_string(),
                                 "{\"attr\":\"value\"}".to_owned(),
                                 1).unwrap()
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_issuer_credential_create_succeeds() {
        let _setup = SetupMocks::init();

        let handle = _issuer_credential_create();
        assert!(handle > 0);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_to_string_succeeds() {
        let _setup = SetupMocks::init();

        let handle = _issuer_credential_create();
        let string = to_string(handle).unwrap();
        assert!(!string.is_empty());
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_send_credential_offer() {
        let _setup = SetupMocks::init();

        let handle_conn = build_test_connection_inviter_requested();

        let handle_cred = _issuer_credential_create();

        assert_eq!(send_credential_offer(handle_cred, handle_conn, None).unwrap(), error::SUCCESS.code_num);
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateOfferSent as u32);
    }

    #[cfg(feature = "pool_tests")]
    #[cfg(feature = "to_restore")]
    #[test]
    fn test_generate_cred_offer() {
        let _setup = SetupLibraryWalletPoolZeroFees::init();

        let _issuer = create_full_issuer_credential().0
            .generate_credential_offer().unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_retry_send_credential_offer() {
        let _setup = SetupMocks::init();

        let connection_handle = build_test_connection_inviter_requested();

        let handle = _issuer_credential_create();
        assert_eq!(get_state(handle).unwrap(), VcxStateType::VcxStateInitialized as u32);

        LibindyMock::set_next_result(error::TIMEOUT_LIBINDY_ERROR.code_num);

        let res = send_credential_offer(handle, connection_handle, None).unwrap_err();
        assert_eq!(res.kind(), VcxErrorKind::InvalidState);
        assert_eq!(get_state(handle).unwrap(), VcxStateType::VcxStateInitialized as u32);

        // Can retry after initial failure
        assert_eq!(send_credential_offer(handle, connection_handle, None).unwrap(), error::SUCCESS.code_num);
        assert_eq!(get_state(handle).unwrap(), VcxStateType::VcxStateOfferSent as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_credential_can_be_resent_after_failure() {
        let _setup = SetupMocks::init();

        let handle_conn = build_test_connection_inviter_requested();

        let handle_cred = _issuer_credential_create();
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateInitialized as u32);
        assert_eq!(get_rev_reg_id(handle_cred).unwrap(), REV_REG_ID);

        assert_eq!(send_credential_offer(handle_cred, handle_conn, None).unwrap(), error::SUCCESS.code_num);
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateOfferSent as u32);
        assert_eq!(get_rev_reg_id(handle_cred).unwrap(), REV_REG_ID);

        issuer_credential::update_state(handle_cred, Some(ARIES_CREDENTIAL_REQUEST), Some(handle_conn)).unwrap();
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateRequestReceived as u32);
        assert_eq!(get_rev_reg_id(handle_cred).unwrap(), REV_REG_ID);

        // First attempt to send credential fails
        HttpClientMockResponse::set_next_response(VcxResult::Err(VcxError::from_msg(VcxErrorKind::IOError, "Sending message timeout.")));
        let send_result = issuer_credential::send_credential(handle_cred, handle_conn);
        assert_eq!(send_result.is_err(), true);
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateRequestReceived as u32);
        assert_eq!(get_rev_reg_id(handle_cred).unwrap(), REV_REG_ID);

        // Can retry after initial failure
        issuer_credential::send_credential(handle_cred, handle_conn).unwrap();
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateAccepted as u32);
        assert_eq!(get_rev_reg_id(handle_cred).unwrap(), REV_REG_ID);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_from_string_succeeds() {
        let _setup = SetupMocks::init();

        let handle = _issuer_credential_create();

        let string = to_string(handle).unwrap();

        let value: serde_json::Value = serde_json::from_str(&string).unwrap();
        assert_eq!(value["version"], V3_OBJECT_SERIALIZE_VERSION);

        release(handle).unwrap();

        let new_handle = from_string(&string).unwrap();

        let new_string = to_string(new_handle).unwrap();
        assert_eq!(new_string, string);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_update_state_with_message() {
        let _setup = SetupMocks::init();

        let handle_conn = build_test_connection_inviter_requested();
        let handle_cred = _issuer_credential_create();

        assert_eq!(send_credential_offer(handle_cred, handle_conn, None).unwrap(), error::SUCCESS.code_num);
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateOfferSent as u32);

        issuer_credential::update_state(handle_cred, Some(ARIES_CREDENTIAL_REQUEST), Some(handle_conn)).unwrap();
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateRequestReceived as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_update_state_with_bad_message() {
        let _setup = SetupMocks::init();

        let handle_conn = build_test_connection_inviter_requested();
        let handle_cred = _issuer_credential_create();

        assert_eq!(send_credential_offer(handle_cred, handle_conn, None).unwrap(), error::SUCCESS.code_num);
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateOfferSent as u32);

        // try to update state with nonsense message
        let result = issuer_credential::update_state(handle_cred, Some(ARIES_CONNECTION_ACK), Some(handle_conn));
        assert!(result.is_ok()); // todo: maybe we should rather return error if update_state doesn't progress state
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateOfferSent as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_release_all() {
        let _setup = SetupMocks::init();

        let h1 = _issuer_credential_create();
        let h2 = _issuer_credential_create();
        let h3 = _issuer_credential_create();
        let h4 = _issuer_credential_create();
        let h5 = _issuer_credential_create();
        release_all();
        assert_eq!(release(h1).unwrap_err().kind(), VcxErrorKind::InvalidIssuerCredentialHandle);
        assert_eq!(release(h2).unwrap_err().kind(), VcxErrorKind::InvalidIssuerCredentialHandle);
        assert_eq!(release(h3).unwrap_err().kind(), VcxErrorKind::InvalidIssuerCredentialHandle);
        assert_eq!(release(h4).unwrap_err().kind(), VcxErrorKind::InvalidIssuerCredentialHandle);
        assert_eq!(release(h5).unwrap_err().kind(), VcxErrorKind::InvalidIssuerCredentialHandle);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_errors() {
        let _setup = SetupLibraryWallet::init();

        assert_eq!(to_string(0).unwrap_err().kind(), VcxErrorKind::InvalidHandle);
        assert_eq!(release(0).unwrap_err().kind(), VcxErrorKind::InvalidIssuerCredentialHandle);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_cant_revoke_without_revocation_details() {
        let _setup = SetupMocks::init();

        let handle_conn = build_test_connection_inviter_requested();

        let handle_cred = _issuer_credential_create();
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateInitialized as u32);

        assert_eq!(send_credential_offer(handle_cred, handle_conn, None).unwrap(), error::SUCCESS.code_num);
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateOfferSent as u32);

        issuer_credential::update_state(handle_cred, Some(ARIES_CREDENTIAL_REQUEST), Some(handle_conn)).unwrap();
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateRequestReceived as u32);

        issuer_credential::send_credential(handle_cred, handle_conn).unwrap();
        assert_eq!(get_state(handle_cred).unwrap(), VcxStateType::VcxStateAccepted as u32);

        let revoc_result = issuer_credential::revoke_credential(handle_cred);
        assert_eq!(revoc_result.unwrap_err().kind(), VcxErrorKind::InvalidRevocationDetails)
    }

    // todo: Write test which will use use credetial definition supporting revocation, then actually revoke credential
}
