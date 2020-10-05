use std::collections::HashMap;

use api::VcxStateType;
use error::prelude::*;
use aries::handlers::connection::agent_info::AgentInfo;
use aries::handlers::connection::invitee::states::complete::CompleteState;
use aries::handlers::connection::invitee::states::invited::InvitedState;
use aries::handlers::connection::invitee::states::null::NullState;
use aries::handlers::connection::invitee::states::requested::RequestedState;
use aries::handlers::connection::messages::DidExchangeMessages;
use aries::messages::a2a::A2AMessage;
use aries::messages::a2a::protocol_registry::ProtocolRegistry;
use aries::messages::connection::did_doc::DidDoc;
use aries::messages::connection::invite::Invitation;
use aries::messages::connection::problem_report::{ProblemCode, ProblemReport};
use aries::messages::connection::request::Request;
use aries::messages::discovery::disclose::ProtocolDescriptor;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmConnectionInvitee {
    source_id: String,
    agent_info: AgentInfo,
    state: InviteeState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InviteeState {
    Null(NullState),
    Invited(InvitedState),
    Requested(RequestedState),
    Completed(CompleteState),
}

impl InviteeState {
    pub fn code(&self) -> u32 {
        match self {
            InviteeState::Null(_) => VcxStateType::VcxStateInitialized as u32,
            InviteeState::Invited(_) => VcxStateType::VcxStateOfferSent as u32,
            InviteeState::Requested(_) => VcxStateType::VcxStateRequestReceived as u32,
            InviteeState::Completed(_) => VcxStateType::VcxStateAccepted as u32,
        }
    }
}

impl SmConnectionInvitee {
    pub fn _build_invitee(source_id: &str) -> Self {
        SmConnectionInvitee {
            source_id: source_id.to_string(),
            state: InviteeState::Null(NullState {}),
            agent_info: AgentInfo::default(),
        }
    }

    pub fn new(source_id: &str) -> Self {
        SmConnectionInvitee::_build_invitee(source_id)
    }

    pub fn is_in_null_state(&self) -> bool {
        match self.state {
            InviteeState::Null(_) => true,
            _ => false
        }
    }

    pub fn from(source_id: String, agent_info: AgentInfo, state: InviteeState) -> Self {
        SmConnectionInvitee {
            source_id,
            agent_info,
            state,
        }
    }

    pub fn agent_info(&self) -> &AgentInfo {
        &self.agent_info
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn state(&self) -> u32 {
        self.state.code()
    }

    pub fn state_object(&self) -> &InviteeState {
        &self.state
    }

    pub fn step(self, message: DidExchangeMessages) -> VcxResult<SmConnectionInvitee> {
        trace!("SmConnectionInvitee::step >>> message: {:?}", message);
        let SmConnectionInvitee { source_id, agent_info, state } = self;

        let (new_state, agent_info) =
            SmConnectionInvitee::invitee_step(state, message, &source_id, agent_info)?;

        Ok(SmConnectionInvitee { source_id, agent_info, state: new_state })
    }

    pub fn their_did_doc(&self) -> Option<DidDoc> {
        match self.state {
            InviteeState::Null(_) => None,
            InviteeState::Invited(ref state) => Some(DidDoc::from(state.invitation.clone())),
            InviteeState::Requested(ref state) => Some(state.did_doc.clone()),
            InviteeState::Completed(ref state) => Some(state.did_doc.clone()),
        }
    }

    pub fn get_invitation(&self) -> Option<&Invitation> {
        match self.state {
            InviteeState::Invited(ref state) => Some(&state.invitation),
            _ => None
        }
    }

    pub fn find_message_to_handle(&self, messages: HashMap<String, A2AMessage>) -> Option<(String, A2AMessage)> {
        for (uid, message) in messages {
            if self.can_handle_message(&message) {
                return Some((uid, message));
            }
        }
        None
    }

    pub fn get_protocols(&self) -> Vec<ProtocolDescriptor> {
        ProtocolRegistry::init().protocols()
    }

    pub fn get_remote_protocols(&self) -> Option<Vec<ProtocolDescriptor>> {
        match self.state {
            InviteeState::Completed(ref state) => state.protocols.clone(),
            _ => None
        }
    }

    pub fn remote_did(&self) -> VcxResult<String> {
        self.their_did_doc()
            .map(|did_doc: DidDoc| did_doc.id.clone())
            .ok_or(VcxError::from_msg(VcxErrorKind::NotReady, "Remote Connection DID is not set"))
    }

    pub fn remote_vk(&self) -> VcxResult<String> {
        self.their_did_doc()
            .and_then(|did_doc| did_doc.recipient_keys().get(0).cloned())
            .ok_or(VcxError::from_msg(VcxErrorKind::NotReady, "Remote Connection Verkey is not set"))
    }

    pub fn can_handle_message(&self, message: &A2AMessage) -> bool {
        match self.state {
            InviteeState::Requested(_) => {
                match message {
                    A2AMessage::ConnectionResponse(_) => {
                        debug!("Invitee received ConnectionResponse message");
                        true
                    }
                    A2AMessage::ConnectionProblemReport(_) => {
                        debug!("Invitee received ProblemReport message");
                        true
                    }
                    _ => {
                        debug!("Invitee received unexpected message: {:?}", message);
                        false
                    }
                }
            }
            InviteeState::Completed(_) => {
                match message {
                    A2AMessage::Ping(_) => {
                        debug!("Ping message received");
                        true
                    }
                    A2AMessage::PingResponse(_) => {
                        debug!("PingResponse message received");
                        true
                    }
                    A2AMessage::Query(_) => {
                        debug!("Query message received");
                        true
                    }
                    A2AMessage::Disclose(_) => {
                        debug!("Disclose message received");
                        true
                    }
                    _ => {
                        debug!("Unexpected message received in Completed state: {:?}", message);
                        false
                    }
                }
            }
            _ => {
                debug!("Unexpected message received: message: {:?}", message);
                false
            }
        }
    }

    pub fn invitee_step(invitee_state: InviteeState, message: DidExchangeMessages, source_id: &str, mut agent_info: AgentInfo) -> VcxResult<(InviteeState, AgentInfo)> {
        let new_state = match invitee_state {
            InviteeState::Null(state) => {
                match message {
                    DidExchangeMessages::InvitationReceived(invitation) => {
                        InviteeState::Invited((state, invitation).into())
                    }
                    _ => {
                        InviteeState::Null(state)
                    }
                }
            }
            InviteeState::Invited(state) => {
                match message {
                    DidExchangeMessages::Connect() => {
                        agent_info = agent_info.create_agent()?;
                        let request = Request::create()
                            .set_label(source_id.to_string())
                            .set_did(agent_info.pw_did.to_string())
                            .set_service_endpoint(agent_info.agency_endpoint()?)
                            .set_keys(agent_info.recipient_keys(), agent_info.routing_keys()?);

                        agent_info.send_message(&request.to_a2a_message(), &DidDoc::from(state.invitation.clone()))?;
                        InviteeState::Requested((state, request).into())
                    }
                    DidExchangeMessages::ProblemReportReceived(problem_report) => {
                        InviteeState::Null((state, problem_report).into())
                    }
                    _ => {
                        InviteeState::Invited(state)
                    }
                }
            }
            InviteeState::Requested(state) => {
                match message {
                    DidExchangeMessages::ExchangeResponseReceived(response) => {
                        match state.handle_connection_response(response, &agent_info) {
                            Ok(response) => {
                                InviteeState::Completed((state, response).into())
                            }
                            Err(err) => {
                                let problem_report = ProblemReport::create()
                                    .set_problem_code(ProblemCode::ResponseProcessingError)
                                    .set_explain(err.to_string())
                                    .set_thread_id(&state.request.id.0);
                                agent_info.send_message(&problem_report.to_a2a_message(), &state.did_doc).ok();
                                InviteeState::Null((state, problem_report).into())
                            }
                        }
                    }
                    DidExchangeMessages::ProblemReportReceived(problem_report) => {
                        InviteeState::Null((state, problem_report).into())
                    }
                    _ => {
                        InviteeState::Requested(state)
                    }
                }
            }
            InviteeState::Completed(state) => {
                state.handle_message(message, &agent_info)?
            }
        };
        Ok((new_state, agent_info))
    }
}


#[cfg(test)]
pub mod test {
    use utils::devsetup::SetupAriesMocks;
    use aries::messages::ack::tests::_ack;
    use aries::messages::connection::invite::tests::_invitation;
    use aries::messages::connection::problem_report::tests::_problem_report;
    use aries::messages::connection::request::tests::_request;
    use aries::messages::connection::response::tests::_signed_response;
    use aries::messages::discovery::disclose::tests::_disclose;
    use aries::messages::discovery::query::tests::_query;
    use aries::messages::trust_ping::ping::tests::_ping;
    use aries::messages::trust_ping::ping_response::tests::_ping_response;
    use aries::test::setup::AgencyModeSetup;
    use aries::test::source_id;

    use super::*;

    pub mod invitee {
        use aries::messages::connection::did_doc::tests::_service_endpoint;
        use aries::messages::connection::response::{Response, SignedResponse};

        use super::*;

        pub fn invitee_sm() -> SmConnectionInvitee {
            SmConnectionInvitee::new(&source_id())
        }

        impl SmConnectionInvitee {
            pub fn to_invitee_invited_state(mut self) -> SmConnectionInvitee {
                self = self.step(DidExchangeMessages::InvitationReceived(_invitation())).unwrap();
                self
            }

            pub fn to_invitee_requested_state(mut self) -> SmConnectionInvitee {
                self = self.step(DidExchangeMessages::InvitationReceived(_invitation())).unwrap();
                self = self.step(DidExchangeMessages::Connect()).unwrap();
                self
            }

            pub fn to_invitee_completed_state(mut self) -> SmConnectionInvitee {
                let key = "GJ1SzoWzavQYfNL9XkaJdrQejfztN4XqdsiV4ct3LXKL".to_string();
                let invitation = Invitation::default().set_recipient_keys(vec![key.clone()]);

                self = self.step(DidExchangeMessages::InvitationReceived(invitation)).unwrap();
                self = self.step(DidExchangeMessages::Connect()).unwrap();
                self = self.step(DidExchangeMessages::ExchangeResponseReceived(_response(&key))).unwrap();
                self = self.step(DidExchangeMessages::AckReceived(_ack())).unwrap();
                self
            }
        }

        fn _response(key: &str) -> SignedResponse {
            Response::default()
                .set_service_endpoint(_service_endpoint())
                .set_keys(vec![key.to_string()], vec![])
                .set_thread_id(&_request().id.0)
                .encode(&key).unwrap()
        }

        mod new {
            use super::*;

            #[test]
            #[cfg(feature = "general_test")]
            fn test_invitee_new() {
                let _setup = SetupAriesMocks::init();

                let invitee_sm = invitee_sm();

                assert_match!(InviteeState::Null(_), invitee_sm.state);
                assert_eq!(source_id(), invitee_sm.source_id());
            }
        }

        mod step {
            use super::*;

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_init() {
                let _setup = AgencyModeSetup::init();

                let did_exchange_sm = invitee_sm();

                assert_match!(InviteeState::Null(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_invite_message_from_null_state() {
                let _setup = AgencyModeSetup::init();

                let mut did_exchange_sm = invitee_sm();

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::InvitationReceived(_invitation())).unwrap();

                assert_match!(InviteeState::Invited(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_other_message_from_null_state() {
                let _setup = AgencyModeSetup::init();

                let mut did_exchange_sm = invitee_sm();

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::Connect()).unwrap();
                assert_match!(InviteeState::Null(_), did_exchange_sm.state);

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::AckReceived(_ack())).unwrap();
                assert_match!(InviteeState::Null(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_connect_message_from_invited_state() {
                let _setup = AgencyModeSetup::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_invited_state();

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::Connect()).unwrap();

                assert_match!(InviteeState::Requested(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_problem_report_message_from_invited_state() {
                let _setup = AgencyModeSetup::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_invited_state();

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::ProblemReportReceived(_problem_report())).unwrap();

                assert_match!(InviteeState::Null(_), did_exchange_sm.state);
            }

            // Todo: seems like I have mixed up inviter and invitee tests????
            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_other_messages_from_invited_state() {
                let _setup = AgencyModeSetup::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_invited_state();

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::AckReceived(_ack())).unwrap();
                assert_match!(InviteeState::Invited(_), did_exchange_sm.state);

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::ExchangeRequestReceived(_request())).unwrap();
                assert_match!(InviteeState::Invited(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_response_message_from_requested_state() {
                let _setup = AgencyModeSetup::init();

                let key = "GJ1SzoWzavQYfNL9XkaJdrQejfztN4XqdsiV4ct3LXKL";

                let mut did_exchange_sm = invitee_sm().to_invitee_requested_state();

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::ExchangeResponseReceived(_response(key))).unwrap();

                assert_match!(InviteeState::Completed(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_invalid_response_message_from_requested_state() {
                let _setup = AgencyModeSetup::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_requested_state();

                let mut signed_response = _signed_response();
                signed_response.connection_sig.signature = String::from("other");

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::ExchangeResponseReceived(signed_response)).unwrap();

                assert_match!(InviteeState::Null(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_problem_report_message_from_requested_state() {
                let _setup = AgencyModeSetup::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_requested_state();

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::ProblemReportReceived(_problem_report())).unwrap();

                assert_match!(InviteeState::Null(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_other_messages_from_requested_state() {
                let _setup = AgencyModeSetup::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_requested_state();

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::AckReceived(_ack())).unwrap();
                assert_match!(InviteeState::Requested(_), did_exchange_sm.state);

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::PingReceived(_ping())).unwrap();
                assert_match!(InviteeState::Requested(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_messages_from_completed_state() {
                let _setup = AgencyModeSetup::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_completed_state();

                // Send Ping
                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::SendPing(None)).unwrap();
                assert_match!(InviteeState::Completed(_), did_exchange_sm.state);

                // Ping
                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::PingReceived(_ping())).unwrap();
                assert_match!(InviteeState::Completed(_), did_exchange_sm.state);

                // Ping Response
                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::PingResponseReceived(_ping_response())).unwrap();
                assert_match!(InviteeState::Completed(_), did_exchange_sm.state);

                // Discovery Features
                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::DiscoverFeatures((None, None))).unwrap();
                assert_match!(InviteeState::Completed(_), did_exchange_sm.state);

                // Query
                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::QueryReceived(_query())).unwrap();
                assert_match!(InviteeState::Completed(_), did_exchange_sm.state);

                // Disclose
                assert!(did_exchange_sm.get_remote_protocols().is_none());

                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::DiscloseReceived(_disclose())).unwrap();
                assert_match!(InviteeState::Completed(_), did_exchange_sm.state);

                assert!(did_exchange_sm.get_remote_protocols().is_some());

                // ignore
                // Ack
                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::AckReceived(_ack())).unwrap();
                assert_match!(InviteeState::Completed(_), did_exchange_sm.state);

                // Problem Report
                did_exchange_sm = did_exchange_sm.step(DidExchangeMessages::ProblemReportReceived(_problem_report())).unwrap();
                assert_match!(InviteeState::Completed(_), did_exchange_sm.state);
            }
        }

        mod find_message_to_handle {
            use super::*;

            #[test]
            #[cfg(feature = "general_test")]
            fn test_find_message_to_handle_from_invited_state() {
                let _setup = AgencyModeSetup::init();

                let connection = invitee_sm().to_invitee_invited_state();

                // No messages
                {
                    let messages = map!(
                        "key_1".to_string() => A2AMessage::ConnectionRequest(_request()),
                        "key_2".to_string() => A2AMessage::ConnectionResponse(_signed_response()),
                        "key_3".to_string() => A2AMessage::ConnectionProblemReport(_problem_report()),
                        "key_4".to_string() => A2AMessage::Ping(_ping()),
                        "key_5".to_string() => A2AMessage::Ack(_ack())
                    );

                    assert!(connection.find_message_to_handle(messages).is_none());
                }
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_find_message_to_handle_from_requested_state() {
                let _setup = AgencyModeSetup::init();

                let connection = invitee_sm().to_invitee_requested_state();

                // Connection Response
                {
                    let messages = map!(
                        "key_1".to_string() => A2AMessage::Ping(_ping()),
                        "key_2".to_string() => A2AMessage::ConnectionRequest(_request()),
                        "key_3".to_string() => A2AMessage::ConnectionResponse(_signed_response())
                    );

                    let (uid, message) = connection.find_message_to_handle(messages).unwrap();
                    assert_eq!("key_3", uid);
                    assert_match!(A2AMessage::ConnectionResponse(_), message);
                }

                // Connection Problem Report
                {
                    let messages = map!(
                        "key_1".to_string() => A2AMessage::Ping(_ping()),
                        "key_2".to_string() => A2AMessage::Ack(_ack()),
                        "key_3".to_string() => A2AMessage::ConnectionProblemReport(_problem_report())
                    );

                    let (uid, message) = connection.find_message_to_handle(messages).unwrap();
                    assert_eq!("key_3", uid);
                    assert_match!(A2AMessage::ConnectionProblemReport(_), message);
                }

                // No messages
                {
                    let messages = map!(
                        "key_1".to_string() => A2AMessage::Ping(_ping()),
                        "key_2".to_string() => A2AMessage::Ack(_ack())
                    );

                    assert!(connection.find_message_to_handle(messages).is_none());
                }
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_find_message_to_handle_from_completed_state() {
                let _setup = AgencyModeSetup::init();

                let connection = invitee_sm().to_invitee_completed_state();

                // Ping
                {
                    let messages = map!(
                        "key_1".to_string() => A2AMessage::ConnectionRequest(_request()),
                        "key_2".to_string() => A2AMessage::ConnectionResponse(_signed_response()),
                        "key_3".to_string() => A2AMessage::ConnectionProblemReport(_problem_report()),
                        "key_4".to_string() => A2AMessage::Ping(_ping()),
                        "key_5".to_string() => A2AMessage::Ack(_ack())
                    );

                    let (uid, message) = connection.find_message_to_handle(messages).unwrap();
                    assert_eq!("key_4", uid);
                    assert_match!(A2AMessage::Ping(_), message);
                }

                // Ping Response
                {
                    let messages = map!(
                        "key_1".to_string() => A2AMessage::ConnectionRequest(_request()),
                        "key_2".to_string() => A2AMessage::ConnectionResponse(_signed_response()),
                        "key_3".to_string() => A2AMessage::ConnectionProblemReport(_problem_report()),
                        "key_4".to_string() => A2AMessage::PingResponse(_ping_response()),
                        "key_5".to_string() => A2AMessage::Ack(_ack())
                    );

                    let (uid, message) = connection.find_message_to_handle(messages).unwrap();
                    assert_eq!("key_4", uid);
                    assert_match!(A2AMessage::PingResponse(_), message);
                }

                // Query
                {
                    let messages = map!(
                        "key_1".to_string() => A2AMessage::ConnectionRequest(_request()),
                        "key_2".to_string() => A2AMessage::ConnectionResponse(_signed_response()),
                        "key_3".to_string() => A2AMessage::Query(_query())
                    );

                    let (uid, message) = connection.find_message_to_handle(messages).unwrap();
                    assert_eq!("key_3", uid);
                    assert_match!(A2AMessage::Query(_), message);
                }

                // Disclose
                {
                    let messages = map!(
                        "key_1".to_string() => A2AMessage::ConnectionRequest(_request()),
                        "key_2".to_string() => A2AMessage::ConnectionResponse(_signed_response()),
                        "key_3".to_string() => A2AMessage::Disclose(_disclose())
                    );

                    let (uid, message) = connection.find_message_to_handle(messages).unwrap();
                    assert_eq!("key_3", uid);
                    assert_match!(A2AMessage::Disclose(_), message);
                }
            }
        }

        mod get_state {
            use super::*;

            #[test]
            #[cfg(feature = "general_test")]
            fn test_get_state() {
                let _setup = SetupAriesMocks::init();

                assert_eq!(VcxStateType::VcxStateInitialized as u32, invitee_sm().state());
                assert_eq!(VcxStateType::VcxStateOfferSent as u32, invitee_sm().to_invitee_invited_state().state());
                assert_eq!(VcxStateType::VcxStateRequestReceived as u32, invitee_sm().to_invitee_requested_state().state());
            }
        }
    }
}
