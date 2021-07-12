#[macro_use]
pub mod handlers;
pub mod messages;
pub mod utils;

#[cfg(test)]
pub mod test {
    use agency_client::payload::PayloadKinds;

    use crate::{libindy, settings};
    use crate::api_lib::api_handle::{connection, credential, disclosed_proof};
    use crate::libindy::utils::wallet::*;
    use crate::utils::devsetup::*;
    use crate::utils::devsetup_agent::test::{Alice, Faber};
    use crate::utils::plugins::init_plugin;

    pub fn source_id() -> String {
        String::from("test source id")
    }

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
}

