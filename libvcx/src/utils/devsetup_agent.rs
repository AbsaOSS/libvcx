
pub const SERIALIZE_VERSION: &'static str = "2.0";

#[cfg(test)]
pub mod test {
    use agency_client::payload::PayloadKinds;

    use crate::{aries, settings};
    use crate::api_lib::api_handle::{connection, credential, credential_def, disclosed_proof, issuer_credential, proof, schema};
    use crate::aries::handlers::connection::connection::{Connection, ConnectionState};
    use crate::aries::handlers::connection::invitee::state_machine::InviteeState;
    use crate::aries::handlers::connection::inviter::state_machine::InviterState;
    use crate::aries::messages::a2a::A2AMessage;
    use crate::error::{VcxError, VcxErrorKind, VcxResult};
    use crate::init::{create_agency_client_for_main_wallet, init_issuer_config, open_as_main_wallet};
    use crate::libindy::utils::wallet::*;
    use crate::utils::constants;
    use crate::utils::devsetup::*;
    use crate::utils::provision::{AgencyClientConfig, AgentProvisionConfig, provision_cloud_agent};

    #[derive(Debug)]
    pub struct VcxAgencyMessage {
        pub uid: String,
        pub decrypted_msg: String,
    }

    fn determine_message_type(a2a_message: A2AMessage) -> PayloadKinds {
        debug!("determine_message_type >>> a2a_message: {:?}", a2a_message);
        match a2a_message.clone() {
            A2AMessage::PresentationRequest(_) => PayloadKinds::ProofRequest,
            A2AMessage::CredentialOffer(_) => PayloadKinds::CredOffer,
            A2AMessage::Credential(_) => PayloadKinds::Cred,
            A2AMessage::Presentation(_) => PayloadKinds::Proof,
            _msg => PayloadKinds::Other(String::from("aries"))
        }
    }

    fn str_message_to_a2a_message(message: &str) -> VcxResult<A2AMessage> {
        Ok(serde_json::from_str(message)
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize A2A message: {}", err)))?
        )
    }

    fn str_message_to_payload_type(message: &str) -> VcxResult<PayloadKinds> {
        let a2a_message = str_message_to_a2a_message(message)?;
        Ok(determine_message_type(a2a_message))
    }

    fn download_message(did: String, filter_msg_type: PayloadKinds) -> Option<VcxAgencyMessage> {
        let mut messages = agency_client::get_message::download_messages_noauth(Some(vec![did]), Some(vec![String::from("MS-103")]), None).unwrap();
        assert_eq!(1, messages.len());
        let messages = messages.pop().unwrap();

        for message in messages.msgs.into_iter() {
            let decrypted_msg = &message.decrypted_msg.unwrap();
            let msg_type = str_message_to_payload_type(decrypted_msg).unwrap();
            if filter_msg_type == msg_type {
                return Some(VcxAgencyMessage {
                    uid: message.uid,
                    decrypted_msg: decrypted_msg.clone(),
                });
            }
        }
        None
    }

    pub trait TestAgent {
        fn activate(&mut self) -> VcxResult<()>;
    }

    pub struct Faber {
        pub is_active: bool,
        pub config_wallet: WalletConfig,
        pub config_agency: AgencyClientConfig,
        pub config_issuer: IssuerConfig,
        pub connection: Connection,
        pub schema_handle: u32,
        pub cred_def_handle: u32,
        pub credential_handle: u32,
        pub presentation_handle: u32,
    }

    impl TestAgent for Faber {
        fn activate(&mut self) -> VcxResult<()> {
            close_main_wallet()
                .unwrap_or_else(|e| warn!("Failed to close main wallet (perhaps none was open?)"));
            settings::clear_config();

            info!("activate >>> Faber opening main wallet");
            open_as_main_wallet(&self.config_wallet)?;
            info!("activate >>> Faber initiating issuer config");
            init_issuer_config(&self.config_issuer)?;
            info!("activate >>> Faber initiating agency client");
            create_agency_client_for_main_wallet(&self.config_agency)?;
            info!("activate >>> Faber done");
            Ok(())
        }
    }

    impl TestAgent for Alice {
        fn activate(&mut self) -> VcxResult<()> {
            close_main_wallet()
                .unwrap_or_else(|e| warn!("Failed to close main wallet (perhaps none was open?)"));
            settings::clear_config();

            info!("activate >>> Alice opening main wallet");
            open_as_main_wallet(&self.config_wallet)?;
            info!("activate >>> Alice initiating agency client");
            create_agency_client_for_main_wallet(&self.config_agency)?;
            info!("activate >>> Alice done");
            Ok(())
        }
    }

    impl Faber {
        pub fn setup() -> Faber {
            settings::clear_config();
            let enterprise_seed = "000000000000000000000000Trustee1";
            let config_wallet = WalletConfig {
                wallet_name: format!("faber_wallet_{}", uuid::Uuid::new_v4().to_string()),
                wallet_key: settings::DEFAULT_WALLET_KEY.into(),
                wallet_key_derivation: settings::WALLET_KDF_RAW.into(),
                wallet_type: None,
                storage_config: None,
                storage_credentials: None,
                rekey: None,
                rekey_derivation_method: None
            };
            let config_provision_agent = AgentProvisionConfig {
                agency_did: AGENCY_DID.to_string(),
                agency_verkey: AGENCY_VERKEY.to_string(),
                agency_endpoint: AGENCY_ENDPOINT.to_string(),
                agent_seed: None
            };
            create_wallet(&config_wallet).unwrap();
            open_as_main_wallet(&config_wallet).unwrap();
            let config_issuer = configure_issuer_wallet(enterprise_seed).unwrap();
            init_issuer_config(&config_issuer).unwrap();
            let config_agency = provision_cloud_agent(&config_provision_agent).unwrap();
            let faber = Faber {
                is_active: false,
                config_wallet,
                config_agency,
                config_issuer,
                schema_handle: 0,
                cred_def_handle: 0,
                connection: Connection::create("alice", true).unwrap(),
                credential_handle: 0,
                presentation_handle: 0,
            };
            close_main_wallet().unwrap();
            faber
        }


        pub fn create_schema(&mut self) {
            self.activate().unwrap();
            let did = String::from("V4SGRU86Z58d6TV7PBUe6f");
            let data = r#"["name","date","degree", "empty_param"]"#.to_string();
            let name: String = crate::utils::random::generate_random_schema_name();
            let version: String = String::from("1.0");

            self.schema_handle = schema::create_and_publish_schema("test_schema", did.clone(), name, version, data).unwrap();
        }

        pub fn create_credential_definition(&mut self) {
            self.activate().unwrap();

            let schema_id = schema::get_schema_id(self.schema_handle).unwrap();
            let did = String::from("V4SGRU86Z58d6TV7PBUe6f");
            let name = String::from("degree");
            let tag = String::from("tag");

            self.cred_def_handle = credential_def::create_and_publish_credentialdef(String::from("test_cred_def"), name, did.clone(), schema_id, tag, String::from("{}")).unwrap();
        }

        pub fn create_presentation_request(&self) -> u32 {
            let requested_attrs = json!([
                {"name": "name"},
                {"name": "date"},
                {"name": "degree"},
                {"name": "empty_param", "restrictions": {"attr::empty_param::value": ""}}
            ]).to_string();

            proof::create_proof(String::from("alice_degree"),
                                requested_attrs,
                                json!([]).to_string(),
                                json!({}).to_string(),
                                String::from("proof_from_alice")).unwrap()
        }

        pub fn create_invite(&mut self) -> String {
            self.activate().unwrap();
            self.connection.connect().unwrap();
            self.connection.update_state().unwrap();
            assert_eq!(ConnectionState::Inviter(InviterState::Invited), self.connection.get_state());

            json!(self.connection.get_invite_details().unwrap()).to_string()
        }

        pub fn update_state(&mut self, expected_state: u32) {
            self.activate().unwrap();
            self.connection.update_state().unwrap();
            assert_eq!(expected_state, u32::from(self.connection.get_state()));
        }

        pub fn ping(&mut self) {
            self.activate().unwrap();
            self.connection.send_ping(None).unwrap();
        }

        pub fn discovery_features(&mut self) {
            self.activate().unwrap();
            self.connection.send_discovery_features(None, None).unwrap();
        }

        pub fn connection_info(&mut self) -> serde_json::Value {
            self.activate().unwrap();
            let details = self.connection.get_connection_info().unwrap();
            serde_json::from_str(&details).unwrap()
        }

        pub fn offer_credential(&mut self) {
            self.activate().unwrap();

            let did = String::from("V4SGRU86Z58d6TV7PBUe6f");
            let credential_data = json!({
                "name": "alice",
                "date": "05-2018",
                "degree": "maths",
                "empty_param": ""
            }).to_string();

            self.credential_handle = issuer_credential::issuer_credential_create(self.cred_def_handle,
                                                                                 String::from("alice_degree"),
                                                                                 did,
                                                                                 String::from("cred"),
                                                                                 credential_data,
                                                                                 0).unwrap();
            let connection_by_handle = connection::store_connection(self.connection.clone()).unwrap();
            issuer_credential::send_credential_offer(self.credential_handle, connection_by_handle, None).unwrap();
            issuer_credential::update_state(self.credential_handle, None, connection_by_handle).unwrap();
            assert_eq!(1, issuer_credential::get_state(self.credential_handle).unwrap());
        }

        pub fn send_credential(&mut self) {
            self.activate().unwrap();
            let connection_by_handle = connection::store_connection(self.connection.clone()).unwrap();
            issuer_credential::update_state(self.credential_handle, None, connection_by_handle).unwrap();
            assert_eq!(2, issuer_credential::get_state(self.credential_handle).unwrap());

            issuer_credential::send_credential(self.credential_handle, connection_by_handle).unwrap();
            issuer_credential::update_state(self.credential_handle, None, connection_by_handle).unwrap();
            assert_eq!(4, issuer_credential::get_state(self.credential_handle).unwrap());
            assert_eq!(aries::messages::status::Status::Success.code(), issuer_credential::get_credential_status(self.credential_handle).unwrap());
        }

        pub fn request_presentation(&mut self) {
            self.activate().unwrap();
            self.presentation_handle = self.create_presentation_request();
            assert_eq!(0, proof::get_state(self.presentation_handle).unwrap());

            let connection_by_handle = connection::store_connection(self.connection.clone()).unwrap();
            proof::send_proof_request(self.presentation_handle, connection_by_handle, None).unwrap();
            proof::update_state(self.presentation_handle, None, connection_by_handle).unwrap();

            assert_eq!(1, proof::get_state(self.presentation_handle).unwrap());
        }

        pub fn verify_presentation(&mut self) {
            self.activate().unwrap();
            self.update_proof_state(2, aries::messages::status::Status::Success.code())
        }

        pub fn update_proof_state(&mut self, expected_state: u32, expected_status: u32) {
            self.activate().unwrap();

            let connection_by_handle = connection::store_connection(self.connection.clone()).unwrap();
            proof::update_state(self.presentation_handle, None, connection_by_handle).unwrap();
            assert_eq!(expected_state, proof::get_state(self.presentation_handle).unwrap());
            assert_eq!(expected_status, proof::get_proof_state(self.presentation_handle).unwrap());
        }

        pub fn teardown(&mut self) {
            self.activate().unwrap();
            close_main_wallet().unwrap();
            delete_wallet(&self.config_wallet).unwrap();
        }
    }

    pub struct Alice {
        pub is_active: bool,
        pub config_wallet: WalletConfig,
        pub config_agency: AgencyClientConfig,
        pub connection: Connection,
        pub credential_handle: u32,
        pub presentation_handle: u32,
    }

    impl Alice {
        pub fn setup() -> Alice {
            settings::clear_config();

            let config_wallet = WalletConfig {
                wallet_name: format!("alice_wallet_{}", uuid::Uuid::new_v4().to_string()),
                wallet_key: settings::DEFAULT_WALLET_KEY.into(),
                wallet_key_derivation: settings::WALLET_KDF_RAW.into(),
                wallet_type: None,
                storage_config: None,
                storage_credentials: None,
                rekey: None,
                rekey_derivation_method: None
            };

            let config_provision_agent = AgentProvisionConfig {
                agency_did: C_AGENCY_DID.to_string(),
                agency_verkey: C_AGENCY_VERKEY.to_string(),
                agency_endpoint: C_AGENCY_ENDPOINT.to_string(),
                agent_seed: None
            };

            create_wallet(&config_wallet).unwrap();
            open_as_main_wallet(&config_wallet).unwrap();
            let config_agency = provision_cloud_agent(&config_provision_agent).unwrap();
            let alice = Alice {
                is_active: false,
                config_wallet,
                config_agency,
                connection: Connection::create("tmp_empoty", true).unwrap(),
                credential_handle: 0,
                presentation_handle: 0,
            };
            close_main_wallet().unwrap();
            alice
        }

        pub fn accept_invite(&mut self, invite: &str) {
            self.activate().unwrap();
            self.connection = Connection::create_with_invite("faber", serde_json::from_str(invite).unwrap(), true).unwrap();
            self.connection.connect().unwrap();
            self.connection.update_state().unwrap();
            assert_eq!(ConnectionState::Invitee(InviteeState::Requested), self.connection.get_state());
        }

        pub fn update_state(&mut self, expected_state: u32) {
            self.activate().unwrap();
            self.connection.update_state().unwrap();
            assert_eq!(expected_state, u32::from(self.connection.get_state()));
        }

        pub fn download_message(&mut self, message_type: PayloadKinds) -> VcxResult<VcxAgencyMessage> {
            self.activate()?;
            let did = self.connection.pairwise_info().pw_did.to_string();
            download_message(did, message_type)
                .ok_or(VcxError::from_msg(VcxErrorKind::UnknownError, format!("Failed to download a message")))
        }

        pub fn accept_offer(&mut self) {
            self.activate().unwrap();
            let connection_by_handle = connection::store_connection(self.connection.clone()).unwrap();
            let offers = credential::get_credential_offer_messages(connection_by_handle).unwrap();
            let offer = serde_json::from_str::<Vec<::serde_json::Value>>(&offers).unwrap()[0].clone();
            let offer_json = serde_json::to_string(&offer).unwrap();

            self.credential_handle = credential::credential_create_with_offer("degree", &offer_json).unwrap();
            assert_eq!(0, credential::get_state(self.credential_handle).unwrap());

            credential::send_credential_request(self.credential_handle, connection_by_handle).unwrap();
            assert_eq!(1, credential::get_state(self.credential_handle).unwrap());
        }

        pub fn accept_credential(&mut self) {
            self.activate().unwrap();
            let connection_by_handle = connection::store_connection(self.connection.clone()).unwrap();
            credential::update_state(self.credential_handle, None, connection_by_handle).unwrap();
            assert_eq!(2, credential::get_state(self.credential_handle).unwrap());
            assert_eq!(aries::messages::status::Status::Success.code(), credential::get_credential_status(self.credential_handle).unwrap());
        }

        pub fn get_proof_request_messages(&mut self) -> String {
            self.activate().unwrap();
            let connection_by_handle = connection::store_connection(self.connection.clone()).unwrap();
            let presentation_requests = disclosed_proof::get_proof_request_messages(connection_by_handle).unwrap();
            let presentation_request = serde_json::from_str::<Vec<::serde_json::Value>>(&presentation_requests).unwrap()[0].clone();
            let presentation_request_json = serde_json::to_string(&presentation_request).unwrap();
            presentation_request_json
        }

        pub fn get_credentials_for_presentation(&mut self) -> serde_json::Value {
            let credentials = disclosed_proof::retrieve_credentials(self.presentation_handle).unwrap();
            let credentials: std::collections::HashMap<String, serde_json::Value> = serde_json::from_str(&credentials).unwrap();

            let mut use_credentials = json!({});

            for (referent, credentials) in credentials["attrs"].as_object().unwrap().iter() {
                use_credentials["attrs"][referent] = json!({
                    "credential": credentials[0]
                })
            }

            use_credentials
        }

        pub fn send_presentation(&mut self) {
            self.activate().unwrap();
            let presentation_request_json = self.get_proof_request_messages();

            self.presentation_handle = disclosed_proof::create_proof("degree", &presentation_request_json).unwrap();

            let credentials = self.get_credentials_for_presentation();

            disclosed_proof::generate_proof(self.presentation_handle, credentials.to_string(), String::from("{}")).unwrap();
            assert_eq!(1, disclosed_proof::get_state(self.presentation_handle).unwrap());

            let connection_by_handle = connection::store_connection(self.connection.clone()).unwrap();
            disclosed_proof::send_proof(self.presentation_handle, connection_by_handle).unwrap();
            assert_eq!(3, disclosed_proof::get_state(self.presentation_handle).unwrap());
        }

        pub fn decline_presentation_request(&mut self) {
            self.activate().unwrap();
            let presentation_request_json = self.get_proof_request_messages();

            let connection_by_handle = connection::store_connection(self.connection.clone()).unwrap();
            self.presentation_handle = disclosed_proof::create_proof("degree", &presentation_request_json).unwrap();
            disclosed_proof::decline_presentation_request(self.presentation_handle, connection_by_handle, Some(String::from("reason")), None).unwrap();
        }

        pub fn propose_presentation(&mut self) {
            self.activate().unwrap();
            let presentation_request_json = self.get_proof_request_messages();

            self.presentation_handle = disclosed_proof::create_proof("degree", &presentation_request_json).unwrap();
            let proposal_data = json!({
                "attributes": [
                    {
                        "name": "first name"
                    }
                ],
                "predicates": [
                    {
                        "name": "age",
                        "predicate": ">",
                        "threshold": 18
                    }
                ]
            });
            let connection_by_handle = connection::store_connection(self.connection.clone()).unwrap();
            disclosed_proof::decline_presentation_request(self.presentation_handle, connection_by_handle, None, Some(proposal_data.to_string())).unwrap();
        }

        pub fn ensure_presentation_verified(&mut self) {
            self.activate().unwrap();
            let connection_by_handle = connection::store_connection(self.connection.clone()).unwrap();
            disclosed_proof::update_state(self.presentation_handle, None, connection_by_handle).unwrap();
            assert_eq!(aries::messages::status::Status::Success.code(), disclosed_proof::get_presentation_status(self.presentation_handle).unwrap());
        }
    }

    impl Drop for Faber {
        fn drop(&mut self) {
            self.activate().unwrap_or_else(|e| error!("Failed to close main wallet while dropping Faber"));
            close_main_wallet().unwrap_or_else(|e| error!("Failed to close main wallet while dropping Faber"));
            delete_wallet(&self.config_wallet).unwrap_or_else(|e| error!("Failed to delete Faber's wallet while dropping"));
        }
    }

    impl Drop for Alice {
        fn drop(&mut self) {
            self.activate().unwrap_or_else(|e| error!("Failed to close main wallet while dropping Alice"));
            close_main_wallet().unwrap_or_else(|e| error!("Failed to close main wallet while dropping Alice"));
            delete_wallet(&self.config_wallet).unwrap_or_else(|e| error!("Failed to delete Alice's wallet while dropping"));
        }
    }
}
