pub mod connection;
pub mod credential;
pub mod credential_def;
pub mod disclosed_proof;
pub mod issuer_credential;
pub mod proof;
pub mod schema;
pub mod object_cache;
pub mod devsetup_agent;

#[cfg(test)]
pub mod test {
    use agency_client::payload::PayloadKinds;

    use crate::{aries, libindy, settings};
    use crate::api_lib::api_handle::{connection, credential, disclosed_proof};
    use crate::libindy::utils::wallet::*;
    use crate::utils::plugins::init_plugin;

    use std::thread;
    use std::time::Duration;

    use serde_json::Value;

    use agency_client::get_message::download_messages_noauth;
    use agency_client::MessageStatusCode;
    use agency_client::mocking::AgencyMockDecrypted;
    use agency_client::update_message::{UIDsByConn, update_agency_messages};

    use crate::aries::messages::ack::tests::_ack;
    use crate::aries::messages::a2a::A2AMessage;
    use crate::aries::handlers::connection::connection::{Connection, ConnectionState};
    use crate::aries::handlers::connection::invitee::state_machine::InviteeState;
    use crate::aries::handlers::connection::inviter::state_machine::InviterState;
    use crate::utils::constants;
    use crate::utils::devsetup::*;
    use crate::api_lib::api_handle::devsetup_agent::test::{Alice, Faber, TestAgent};
    use crate::utils::mockdata::mockdata_connection::{ARIES_CONNECTION_ACK, ARIES_CONNECTION_INVITATION, ARIES_CONNECTION_REQUEST, CONNECTION_SM_INVITEE_COMPLETED, CONNECTION_SM_INVITEE_INVITED, CONNECTION_SM_INVITEE_REQUESTED, CONNECTION_SM_INVITER_COMPLETED};

    use super::*;

    pub struct PaymentPlugin {}

    impl PaymentPlugin {
        pub fn load() {
            init_plugin(settings::DEFAULT_PAYMENT_PLUGIN, settings::DEFAULT_PAYMENT_INIT_FUNCTION);
        }
    }

    pub struct Pool {}

    impl Pool {
        pub fn open() -> Pool {
            libindy::utils::pool::tests::open_test_pool();
            Pool {}
        }
    }

    impl Drop for Pool {
        fn drop(&mut self) {
            libindy::utils::pool::close().unwrap();
            libindy::utils::pool::tests::delete_test_pool();
        }
    }

    #[cfg(feature = "agency_pool_tests")]
    #[test]
    fn aries_demo() {
        PaymentPlugin::load();
        let _pool = Pool::open();

        let mut faber = Faber::setup();
        let mut alice = Alice::setup();

        // Publish Schema and Credential Definition
        faber.create_schema();

        std::thread::sleep(std::time::Duration::from_secs(2));

        faber.create_credential_definition();

        // Connection
        let invite = faber.create_invite();
        alice.accept_invite(&invite);

        faber.update_state(3);
        alice.update_state(4);
        faber.update_state(4);

        // Credential issuance
        faber.offer_credential();
        alice.accept_offer();
        faber.send_credential();
        alice.accept_credential();

        // Credential Presentation
        faber.request_presentation();
        alice.send_presentation();
        faber.verify_presentation();
        alice.ensure_presentation_verified();
    }

    #[cfg(feature = "agency_pool_tests")]
    #[test]
    fn aries_demo_handle_connection_related_messages() {
        PaymentPlugin::load();
        let _pool = Pool::open();

        let mut faber = Faber::setup();
        let mut alice = Alice::setup();

        // Publish Schema and Credential Definition
        faber.create_schema();

        std::thread::sleep(std::time::Duration::from_secs(2));

        faber.create_credential_definition();

        // Connection
        let invite = faber.create_invite();
        alice.accept_invite(&invite);

        faber.update_state(3);
        alice.update_state(4);
        faber.update_state(4);

        // Ping
        faber.ping();

        alice.update_state(4);

        faber.update_state(4);

        let faber_connection_info = faber.connection_info();
        assert!(faber_connection_info["their"]["protocols"].as_array().is_none());

        // Discovery Features
        faber.discovery_features();

        alice.update_state(4);

        faber.update_state(4);

        let faber_connection_info = faber.connection_info();
        assert!(faber_connection_info["their"]["protocols"].as_array().unwrap().len() > 0);
    }

    #[cfg(feature = "agency_pool_tests")]
    #[test]
    fn aries_demo_create_with_message_id_flow() {
        let _setup = SetupEmpty::init();
        PaymentPlugin::load();
        let _pool = Pool::open();

        let mut faber = Faber::setup();
        let mut alice = Alice::setup();

        // Publish Schema and Credential Definition
        faber.create_schema();

        std::thread::sleep(std::time::Duration::from_secs(2));

        faber.create_credential_definition();

        // Connection
        let invite = faber.create_invite();
        alice.accept_invite(&invite);

        faber.update_state(3);
        alice.update_state(4);
        faber.update_state(4);

        /*
         Create with message id flow
        */

        // Credential issuance
        faber.offer_credential();

        // Alice creates Credential object with message id
        {
            let message = alice.download_message(PayloadKinds::CredOffer).unwrap();
            let alice_connection_by_handle = connection::store_connection(alice.connection.clone()).unwrap();
            let (credential_handle, _credential_offer) = credential::credential_create_with_msgid("test", alice_connection_by_handle, &message.uid).unwrap();
            alice.credential_handle = credential_handle;

            credential::send_credential_request(alice.credential_handle, alice_connection_by_handle).unwrap();
            assert_eq!(1, credential::get_state(alice.credential_handle).unwrap());
        }

        faber.send_credential();
        alice.accept_credential();

        // Credential Presentation
        faber.request_presentation();

        // Alice creates Presentation object with message id
        {
            let message = alice.download_message(PayloadKinds::ProofRequest).unwrap();
            let alice_connection_by_handle = connection::store_connection(alice.connection.clone()).unwrap();
            let (presentation_handle, _presentation_request) = disclosed_proof::create_proof_with_msgid("test", alice_connection_by_handle, &message.uid).unwrap();
            alice.presentation_handle = presentation_handle;

            let credentials = alice.get_credentials_for_presentation();

            disclosed_proof::generate_proof(alice.presentation_handle, credentials.to_string(), String::from("{}")).unwrap();
            assert_eq!(1, disclosed_proof::get_state(alice.presentation_handle).unwrap());

            let alice_connection_by_handle = connection::store_connection(alice.connection.clone()).unwrap();
            disclosed_proof::send_proof(alice.presentation_handle, alice_connection_by_handle).unwrap();
            assert_eq!(3, disclosed_proof::get_state(alice.presentation_handle).unwrap());
        }

        faber.verify_presentation();
    }

    #[cfg(feature = "agency_pool_tests")]
    #[test]
    fn aries_demo_download_message_flow() {
        SetupEmpty::init();
        PaymentPlugin::load();
        let _pool = Pool::open();

        let mut faber = Faber::setup();
        let mut alice = Alice::setup();

        // Publish Schema and Credential Definition
        faber.create_schema();

        std::thread::sleep(std::time::Duration::from_secs(2));

        faber.create_credential_definition();

        // Connection
        let invite = faber.create_invite();
        alice.accept_invite(&invite);

        faber.update_state(3);
        alice.update_state(4);
        faber.update_state(4);

        /*
         Create with message flow
        */

        // Credential issuance
        faber.offer_credential();

        // Alice creates Credential object with Offer
        {
            let message = alice.download_message(PayloadKinds::CredOffer).unwrap();

            alice.credential_handle = credential::credential_create_with_offer("test", &message.decrypted_msg).unwrap();

            alice.connection.update_message_status(message.uid).unwrap();

            let alice_connection_by_handle = connection::store_connection(alice.connection.clone()).unwrap();
            credential::send_credential_request(alice.credential_handle, alice_connection_by_handle).unwrap();
            assert_eq!(1, credential::get_state(alice.credential_handle).unwrap());
        }

        faber.send_credential();
        alice.accept_credential();

        // Credential Presentation
        faber.request_presentation();

        // Alice creates Presentation object with Proof Request
        {
            let agency_msg = alice.download_message(PayloadKinds::ProofRequest).unwrap();

            alice.presentation_handle = disclosed_proof::create_proof("test", &agency_msg.decrypted_msg).unwrap();

            alice.connection.update_message_status(agency_msg.uid).unwrap();

            let credentials = alice.get_credentials_for_presentation();

            disclosed_proof::generate_proof(alice.presentation_handle, credentials.to_string(), String::from("{}")).unwrap();
            assert_eq!(1, disclosed_proof::get_state(alice.presentation_handle).unwrap());

            let alice_connection_by_handle = connection::store_connection(alice.connection.clone()).unwrap();
            disclosed_proof::send_proof(alice.presentation_handle, alice_connection_by_handle).unwrap();
            assert_eq!(3, disclosed_proof::get_state(alice.presentation_handle).unwrap());
        }

        faber.verify_presentation();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_deserialize_connection_inviter_completed() {
        let _setup = SetupMocks::init();

        let connection = Connection::from_string(CONNECTION_SM_INVITER_COMPLETED).unwrap();
        let _second_string = connection.to_string();

        assert_eq!(connection.pairwise_info().pw_did, "2ZHFFhzA2XtTD6hJqzL7ux");
        assert_eq!(connection.pairwise_info().pw_vk, "rCw3x5h1jS6gPo7rRrt3EYbXXe5nNjnGbdf1jAwUxuj");
        assert_eq!(connection.cloud_agent_info().agent_did, "EZrZyu4bfydm4ByNm56kPP");
        assert_eq!(connection.cloud_agent_info().agent_vk, "8Ps2WosJ9AV1eXPoJKsEJdM3NchPhSyS8qFt6LQUTKv2");
        assert_eq!(connection.get_state(), ConnectionState::Inviter(InviterState::Completed));
    }

    fn test_deserialize_and_serialize(sm_serialized: &str) {
        let original_object: Value = serde_json::from_str(sm_serialized).unwrap();
        let connection = Connection::from_string(sm_serialized).unwrap();
        let reserialized = connection.to_string().unwrap();
        let reserialized_object: Value = serde_json::from_str(&reserialized).unwrap();

        assert_eq!(original_object, reserialized_object);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_deserialize_and_serialize_should_produce_the_same_object() {
        let _setup = SetupMocks::init();

        test_deserialize_and_serialize(CONNECTION_SM_INVITEE_INVITED);
        test_deserialize_and_serialize(CONNECTION_SM_INVITEE_REQUESTED);
        test_deserialize_and_serialize(CONNECTION_SM_INVITEE_COMPLETED);
        test_deserialize_and_serialize(CONNECTION_SM_INVITER_COMPLETED);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_serialize_deserialize() {
        let _setup = SetupMocks::init();

        let connection = Connection::create("test_serialize_deserialize", true).unwrap();
        let first_string = connection.to_string().unwrap();

        let connection2 = Connection::from_string(&first_string).unwrap();
        let second_string = connection2.to_string().unwrap();

        assert_eq!(first_string, second_string);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_serialize_deserialize_serde() {
        let _setup = SetupMocks::init();

        let connection = Connection::create("test_serialize_deserialize", true).unwrap();
        let first_string = serde_json::to_string(&connection).unwrap();

        let connection: Connection = serde_json::from_str(&first_string).unwrap();
        let second_string = serde_json::to_string(&connection).unwrap();
        assert_eq!(first_string, second_string);
    }


    pub fn create_connected_connections(consumer: &mut Alice, institution: &mut Faber) -> (Connection, Connection) {
        debug!("Institution is going to create connection.");
        institution.activate().unwrap();
        let mut institution_to_consumer = Connection::create("consumer", true).unwrap();
        let _my_public_did = settings::get_config_value(settings::CONFIG_INSTITUTION_DID).unwrap();
        institution_to_consumer.connect().unwrap();
        let details = institution_to_consumer.get_invite_details().unwrap();

        consumer.activate().unwrap();
        debug!("Consumer is going to accept connection invitation.");
        let mut consumer_to_institution = Connection::create_with_invite("institution", details.clone(), true).unwrap();

        consumer_to_institution.connect().unwrap();
        consumer_to_institution.update_state().unwrap();

        debug!("Institution is going to process connection request.");
        institution.activate().unwrap();
        thread::sleep(Duration::from_millis(500));
        institution_to_consumer.update_state().unwrap();
        assert_eq!(ConnectionState::Inviter(InviterState::Responded), institution_to_consumer.get_state());

        debug!("Consumer is going to complete the connection protocol.");
        consumer.activate().unwrap();
        consumer_to_institution.update_state().unwrap();
        assert_eq!(ConnectionState::Invitee(InviteeState::Completed), consumer_to_institution.get_state());

        debug!("Institution is going to complete the connection protocol.");
        institution.activate().unwrap();
        thread::sleep(Duration::from_millis(500));
        institution_to_consumer.update_state().unwrap();
        assert_eq!(ConnectionState::Inviter(InviterState::Completed), institution_to_consumer.get_state());

        (consumer_to_institution, institution_to_consumer)
    }

    #[cfg(feature = "agency_pool_tests")]
    #[test]
    fn test_send_and_download_messages() {
        let _setup = SetupLibraryAgencyV2::init();
        let mut institution = Faber::setup();
        let mut consumer = Alice::setup();

        let (alice_to_faber, faber_to_alice) = create_connected_connections(&mut consumer, &mut institution);

        institution.activate().unwrap();
        faber_to_alice.send_generic_message("Hello Alice").unwrap();
        faber_to_alice.send_generic_message("How are you Alice?").unwrap();

        consumer.activate().unwrap();
        alice_to_faber.send_generic_message("Hello Faber").unwrap();

        thread::sleep(Duration::from_millis(1000));

        let all_messages = download_messages_noauth(None, None, None).unwrap();
        assert_eq!(all_messages.len(), 2);
        assert_eq!(all_messages[1].msgs.len(), 3);
        assert!(all_messages[1].msgs[0].decrypted_msg.is_some());
        assert!(all_messages[1].msgs[1].decrypted_msg.is_some());

        let received = download_messages_noauth(None, Some(vec![MessageStatusCode::Received.to_string()]), None).unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(received[1].msgs.len(), 2);
        assert!(received[1].msgs[0].decrypted_msg.is_some());
        assert_eq!(received[1].msgs[0].status_code, MessageStatusCode::Received);
        assert!(received[1].msgs[1].decrypted_msg.is_some());

        // there should be messages in "Reviewed" status connections/1.0/response from Aries-Faber connection protocol
        let reviewed = download_messages_noauth(None, Some(vec![MessageStatusCode::Reviewed.to_string()]), None).unwrap();
        assert_eq!(reviewed.len(), 2);
        assert_eq!(reviewed[1].msgs.len(), 1);
        assert!(reviewed[1].msgs[0].decrypted_msg.is_some());
        assert_eq!(reviewed[1].msgs[0].status_code, MessageStatusCode::Reviewed);

        let rejected = download_messages_noauth(None, Some(vec![MessageStatusCode::Rejected.to_string()]), None).unwrap();
        assert_eq!(rejected.len(), 2);
        assert_eq!(rejected[1].msgs.len(), 0);

        let specific = download_messages_noauth(None, None, Some(vec![received[1].msgs[0].uid.clone()])).unwrap();
        assert_eq!(specific.len(), 2);
        assert_eq!(specific[1].msgs.len(), 1);
        let msg = specific[1].msgs[0].decrypted_msg.clone().unwrap();
        let msg_aries_value: Value = serde_json::from_str(&msg).unwrap();
        assert!(msg_aries_value.is_object());
        assert!(msg_aries_value["@id"].is_string());
        assert!(msg_aries_value["@type"].is_string());
        assert!(msg_aries_value["content"].is_string());

        let unknown_did = "CmrXdgpTXsZqLQtGpX5Yee".to_string();
        let empty = download_messages_noauth(Some(vec![unknown_did]), None, None).unwrap();
        assert_eq!(empty.len(), 0);
    }

    #[test]
    #[cfg(feature = "agency_v2")]
    fn test_connection_send_works() {
        let _setup = SetupEmpty::init();
        let mut faber = Faber::setup();
        let mut alice = Alice::setup();

        let invite = faber.create_invite();
        alice.accept_invite(&invite);

        faber.update_state(3);
        alice.update_state(4);
        faber.update_state(4);

        let uid: String;
        let message = _ack();

        info!("test_connection_send_works:: Test if Send Message works");
        {
            faber.activate().unwrap();
            faber.connection.send_message_closure().unwrap()(&message.to_a2a_message()).unwrap();
        }

        {
            info!("test_connection_send_works:: Test if Get Messages works");
            alice.activate().unwrap();

            let messages = alice.connection.get_messages().unwrap();
            assert_eq!(1, messages.len());

            uid = messages.keys().next().unwrap().clone();
            let received_message = messages.values().next().unwrap().clone();

            match received_message {
                A2AMessage::Ack(received_message) => assert_eq!(message, received_message.clone()),
                _ => assert!(false)
            }
        }

        info!("test_connection_send_works:: Test if Get Message by id works");
        {
            alice.activate().unwrap();

            let message = alice.connection.get_message_by_id(&uid.clone()).unwrap();

            match message {
                A2AMessage::Ack(ack) => assert_eq!(_ack(), ack),
                _ => assert!(false)
            }
        }

        info!("test_connection_send_works:: Test if Update Message Status works");
        {
            alice.activate().unwrap();

            alice.connection.update_message_status(uid).unwrap();
            let messages = alice.connection.get_messages().unwrap();
            assert_eq!(0, messages.len());
        }

        info!("test_connection_send_works:: Test if Send Basic Message works");
        {
            faber.activate().unwrap();

            let basic_message = r#"Hi there"#;
            faber.connection.send_generic_message(basic_message).unwrap();

            alice.activate().unwrap();

            let messages = alice.connection.get_messages().unwrap();
            assert_eq!(1, messages.len());

            let uid = messages.keys().next().unwrap().clone();
            let message = messages.values().next().unwrap().clone();

            match message {
                A2AMessage::BasicMessage(message) => assert_eq!(basic_message, message.content),
                _ => assert!(false)
            }
            alice.connection.update_message_status(uid).unwrap();
        }

        info!("test_connection_send_works:: Test if Download Messages");
        {
            use agency_client::get_message::{MessageByConnection, Message};

            let credential_offer = aries::messages::issuance::credential_offer::tests::_credential_offer();

            faber.activate().unwrap();
            faber.connection.send_message_closure().unwrap()(&credential_offer.to_a2a_message()).unwrap();

            alice.activate().unwrap();

            let msgs = alice.connection.download_messages(Some(vec![MessageStatusCode::Received]), None).unwrap();
            let message: Message = msgs[0].clone();
            let decrypted_msg = message.decrypted_msg.unwrap();
            let _payload: aries::messages::issuance::credential_offer::CredentialOffer = serde_json::from_str(&decrypted_msg).unwrap();

            alice.connection.update_message_status(message.uid.clone()).unwrap()
        }
    }

    #[cfg(feature = "agency_v2")]
    #[test]
    fn test_download_messages() {
        let _setup = SetupEmpty::init();
        let mut institution = Faber::setup();
        let mut consumer1 = Alice::setup();
        let mut consumer2 = Alice::setup();
        let (consumer1_to_institution, institution_to_consumer1) = create_connected_connections(&mut consumer1, &mut institution);
        let (consumer2_to_institution, institution_to_consumer2) = create_connected_connections(&mut consumer2, &mut institution);

        let consumer1_pwdid = consumer1_to_institution.remote_did().unwrap();
        let consumer2_pwdid = consumer2_to_institution.remote_did().unwrap();

        consumer1.activate().unwrap();
        consumer1_to_institution.send_generic_message("Hello Institution from consumer1").unwrap();
        consumer2.activate().unwrap();
        consumer2_to_institution.send_generic_message("Hello Institution from consumer2").unwrap();

        institution.activate().unwrap();

        let consumer1_msgs = institution_to_consumer1.download_messages(None, None).unwrap();
        assert_eq!(consumer1_msgs.len(), 2);

        let consumer2_msgs = institution_to_consumer2.download_messages(None, None).unwrap();
        assert_eq!(consumer2_msgs.len(), 2);

        let consumer1_received_msgs = institution_to_consumer1.download_messages(Some(vec![MessageStatusCode::Received]), None).unwrap();
        assert_eq!(consumer1_received_msgs.len(), 1);

        let consumer1_reviewed_msgs = institution_to_consumer1.download_messages(Some(vec![MessageStatusCode::Reviewed]), None).unwrap();
        assert_eq!(consumer1_reviewed_msgs.len(), 1);
    }

    #[cfg(feature = "agency_v2")]
    #[test]
    fn test_update_agency_messages() {
        let _setup = SetupEmpty::init();
        let mut institution = Faber::setup();
        let mut consumer1 = Alice::setup();
        let (alice_to_faber, faber_to_alice) = create_connected_connections(&mut consumer1, &mut institution);

        faber_to_alice.send_generic_message("Hello 1").unwrap();
        faber_to_alice.send_generic_message("Hello 2").unwrap();
        faber_to_alice.send_generic_message("Hello 3").unwrap();

        thread::sleep(Duration::from_millis(1000));
        consumer1.activate().unwrap();

        let received = alice_to_faber.download_messages(Some(vec![MessageStatusCode::Received]), None).unwrap();
        assert_eq!(received.len(), 3);
        let uid = received[0].uid.clone();

        let reviewed = alice_to_faber.download_messages(Some(vec![MessageStatusCode::Reviewed]), None).unwrap();
        let reviewed_count_before = reviewed.len();

        let pairwise_did = alice_to_faber.pairwise_info().pw_did.clone();
        let message = serde_json::to_string(&vec![UIDsByConn { pairwise_did: pairwise_did.clone(), uids: vec![uid.clone()] }]).unwrap();
        update_agency_messages("MS-106", &message).unwrap();

        let received = alice_to_faber.download_messages(Some(vec![MessageStatusCode::Received]), None).unwrap();
        assert_eq!(received.len(), 2);

        let reviewed = alice_to_faber.download_messages(Some(vec![MessageStatusCode::Reviewed]), None).unwrap();
        let reviewed_count_after = reviewed.len();
        assert_eq!(reviewed_count_after, reviewed_count_before + 1);

        let specific_review = alice_to_faber.download_messages(Some(vec![MessageStatusCode::Reviewed]), Some(vec![uid.clone()])).unwrap();
        assert_eq!(specific_review[0].uid, uid);
    }
}
