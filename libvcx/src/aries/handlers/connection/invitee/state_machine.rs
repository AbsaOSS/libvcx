use std::collections::HashMap;

use crate::aries::handlers::connection::invitee::states::complete::CompleteState;
use crate::aries::handlers::connection::invitee::states::invited::InvitedState;
use crate::aries::handlers::connection::invitee::states::null::NullState;
use crate::aries::handlers::connection::invitee::states::requested::RequestedState;
use crate::aries::handlers::connection::invitee::states::responded::RespondedState;
use crate::aries::handlers::connection::inviter::state_machine::InviterState;
use crate::aries::handlers::connection::pairwise_info::PairwiseInfo;
use crate::aries::messages::a2a::A2AMessage;
use crate::aries::messages::a2a::protocol_registry::ProtocolRegistry;
use crate::aries::messages::ack::Ack;
use crate::aries::messages::connection::did_doc::DidDoc;
use crate::aries::messages::connection::invite::Invitation;
use crate::aries::messages::connection::problem_report::{ProblemCode, ProblemReport};
use crate::aries::messages::connection::request::Request;
use crate::aries::messages::connection::response::{Response, SignedResponse};
use crate::aries::messages::discovery::disclose::{Disclose, ProtocolDescriptor};
use crate::aries::messages::discovery::query::Query;
use crate::aries::messages::trust_ping::ping::Ping;
use crate::aries::messages::trust_ping::ping_response::PingResponse;
use crate::error::prelude::*;

#[derive(Clone)]
pub struct SmConnectionInvitee {
    source_id: String,
    pairwise_info: PairwiseInfo,
    state: InviteeFullState,
    send_message: fn(&str, &DidDoc, &A2AMessage) -> VcxResult<()>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InviteeFullState {
    Null(NullState),
    Invited(InvitedState),
    Requested(RequestedState),
    Responded(RespondedState),
    Completed(CompleteState),
}

#[derive(Debug, PartialEq)]
pub enum InviteeState {
    Null,
    Invited,
    Requested,
    Responded,
    Completed,
}

impl From<InviteeFullState> for InviteeState {
    fn from(state: InviteeFullState) -> InviteeState {
        match state {
            InviteeFullState::Null(_) => InviteeState::Null,
            InviteeFullState::Invited(_) => InviteeState::Invited,
            InviteeFullState::Requested(_) => InviteeState::Requested,
            InviteeFullState::Responded(_) => InviteeState::Responded,
            InviteeFullState::Completed(_) => InviteeState::Completed
        }
    }
}

impl SmConnectionInvitee {
    pub fn new(source_id: &str, pairwise_info: PairwiseInfo, send_message: fn(&str, &DidDoc, &A2AMessage) -> VcxResult<()>) -> Self {
        SmConnectionInvitee {
            source_id: source_id.to_string(),
            state: InviteeFullState::Null(NullState {}),
            pairwise_info,
            send_message,
        }
    }

    pub fn is_in_null_state(&self) -> bool {
        return InviteeState::from(self.state.clone()) == InviteeState::Null;
    }

    pub fn from(source_id: String, pairwise_info: PairwiseInfo, state: InviteeFullState, send_message: fn(&str, &DidDoc, &A2AMessage) -> VcxResult<()>) -> Self {
        SmConnectionInvitee {
            source_id,
            pairwise_info,
            state,
            send_message,
        }
    }

    pub fn pairwise_info(&self) -> &PairwiseInfo {
        &self.pairwise_info
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn get_state(&self) -> InviteeState {
        InviteeState::from(self.state.clone())
    }

    pub fn state_object(&self) -> &InviteeFullState {
        &self.state
    }

    pub fn needs_message(&self) -> bool {
        match self.state {
            InviteeFullState::Responded(_) => false,
            _ => true
        }
    }

    pub fn their_did_doc(&self) -> Option<DidDoc> {
        match self.state {
            InviteeFullState::Null(_) => None,
            InviteeFullState::Invited(ref state) => Some(DidDoc::from(state.invitation.clone())),
            InviteeFullState::Requested(ref state) => Some(state.did_doc.clone()),
            InviteeFullState::Responded(ref state) => Some(state.did_doc.clone()),
            InviteeFullState::Completed(ref state) => Some(state.did_doc.clone()),
        }
    }

    pub fn get_invitation(&self) -> Option<&Invitation> {
        match self.state {
            InviteeFullState::Invited(ref state) => Some(&state.invitation),
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
            InviteeFullState::Completed(ref state) => state.protocols.clone(),
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
            InviteeFullState::Requested(_) => {
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
            InviteeFullState::Completed(_) => {
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

    fn _send_ack(did_doc: &DidDoc,
                 request: &Request,
                 response: &SignedResponse,
                 pairwise_info: &PairwiseInfo,
                 send_message: fn(&str, &DidDoc, &A2AMessage) -> VcxResult<()>) -> VcxResult<Response> {
        let remote_vk: String = did_doc.recipient_keys().get(0).cloned()
            .ok_or(VcxError::from_msg(VcxErrorKind::InvalidState, "Cannot handle Response: Remote Verkey not found"))?;

        let response = response.clone().decode(&remote_vk)?;

        if !response.from_thread(&request.id.0) {
            return Err(VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot handle Response: thread id does not match: {:?}", response.thread)));
        }

        let message = Ack::create()
            .set_thread_id(&response.thread.thid.clone().unwrap_or_default())
            .to_a2a_message();

        send_message(&pairwise_info.pw_vk, &response.connection.did_doc, &message)?;
        Ok(response)
    }

    pub fn handle_invitation(self, invitation: Invitation) -> VcxResult<Self> {
        let Self { source_id, pairwise_info, state, send_message } = self;
        let state = match state {
            InviteeFullState::Null(state) => {
                InviteeFullState::Invited((state, invitation).into())
            }
            _ => {
                state.clone()
            }
        };
        Ok(Self { source_id, pairwise_info, state, send_message })
    }

    pub fn handle_connect(self, routing_keys: Vec<String>, service_endpoint: String) -> VcxResult<Self> {
        let Self { source_id, pairwise_info, state, send_message } = self;
        let state = match state {
            InviteeFullState::Invited(state) => {
                let recipient_keys = vec!(pairwise_info.pw_vk.clone());
                let request = Request::create()
                    .set_label(source_id.to_string())
                    .set_did(pairwise_info.pw_did.to_string())
                    .set_service_endpoint(service_endpoint)
                    .set_keys(recipient_keys, routing_keys);

                let ddo = DidDoc::from(state.invitation.clone());
                send_message(&pairwise_info.pw_vk, &ddo, &request.to_a2a_message())?;
                let new_state = InviteeFullState::Requested((state, request).into());
                new_state
            }
            _ => {
                state.clone()
            }
        };
        Ok(Self { source_id, pairwise_info, state, send_message })
    }

    pub fn handle_connection_response(self, response: SignedResponse) -> VcxResult<Self> {
        let Self { source_id, pairwise_info, state, send_message } = self;
        let state = match state {
            InviteeFullState::Requested(state) => {
                InviteeFullState::Responded((state, response).into())
            }
            _ => {
                state.clone()
            }
        };
        Ok(Self { source_id, pairwise_info, state, send_message })
    }

    pub fn handle_ping(self, ping: Ping) -> VcxResult<Self> {
        let Self { source_id, pairwise_info, state, send_message } = self;
        let state = match state {
            InviteeFullState::Completed(state) => {
                state.handle_ping(&ping, &pairwise_info.pw_vk, send_message)?;
                InviteeFullState::Completed(state)
            }
            _ => {
                state.clone()
            }
        };
        Ok(Self { source_id, pairwise_info, state, send_message })
    }

    pub fn handle_send_ping(self, comment: Option<String>) -> VcxResult<Self> {
        let Self { source_id, pairwise_info, state, send_message } = self;
        let state = match state {
            InviteeFullState::Completed(state) => {
                state.handle_send_ping(comment, &pairwise_info.pw_vk, send_message)?;
                InviteeFullState::Completed(state)
            }
            _ => {
                state.clone()
            }
        };
        Ok(Self { source_id, pairwise_info, state, send_message })
    }

    pub fn handle_ping_response(self, _ping_response: PingResponse) -> VcxResult<Self> {
        Ok(self)
    }

    pub fn handle_discover_features(self, query_: Option<String>, comment: Option<String>) -> VcxResult<Self> {
        let Self { source_id, pairwise_info, state, send_message } = self;
        let state = match state {
            InviteeFullState::Completed(state) => {
                state.handle_discover_features(query_, comment, &pairwise_info.pw_vk, send_message)?;
                InviteeFullState::Completed(state)
            }
            _ => {
                state.clone()
            }
        };
        Ok(Self { source_id, pairwise_info, state, send_message })
    }

    pub fn handle_discovery_query(self, query: Query) -> VcxResult<Self> {
        let Self { source_id, pairwise_info, state, send_message } = self;
        let state = match state {
            InviteeFullState::Completed(state) => {
                state.handle_discovery_query(query, &pairwise_info.pw_vk, send_message)?;
                InviteeFullState::Completed(state)
            }
            _ => {
                state.clone()
            }
        };
        Ok(Self { source_id, pairwise_info, state, send_message })
    }

    pub fn handle_disclose(self, disclose: Disclose) -> VcxResult<Self> {
        let Self { source_id, pairwise_info, state, send_message } = self;
        let state = match state {
            InviteeFullState::Completed(state) => {
                InviteeFullState::Completed((state.clone(), disclose.protocols).into())
            }
            _ => {
                state.clone()
            }
        };
        Ok(Self { source_id, pairwise_info, state, send_message })
    }


    pub fn handle_send_ack(self) -> VcxResult<Self> {
        let Self { source_id, pairwise_info, state, send_message } = self;
        let state = match state {
            InviteeFullState::Responded(state) => {
                match Self::_send_ack(&state.did_doc, &state.request, &state.response, &pairwise_info, send_message) {
                    Ok(response) => InviteeFullState::Completed((state, response).into()),
                    Err(err) => {
                        let problem_report = ProblemReport::create()
                            .set_problem_code(ProblemCode::ResponseProcessingError)
                            .set_explain(err.to_string())
                            .set_thread_id(&state.request.id.0);
                        send_message(&pairwise_info.pw_vk, &state.did_doc, &problem_report.to_a2a_message()).ok();
                        InviteeFullState::Null((state, problem_report).into())
                    }
                }
            }
            _ => state.clone()
        };
        Ok(Self { source_id, pairwise_info, state, send_message })
    }

    pub fn handle_problem_report(self, problem_report: ProblemReport) -> VcxResult<Self> {
        let Self { source_id, pairwise_info, state, send_message } = self;
        let state = match state {
            InviteeFullState::Requested(state) => {
                InviteeFullState::Null((state, problem_report).into())
            }
            InviteeFullState::Invited(state) => {
                InviteeFullState::Null((state, problem_report).into())
            }
            _ => {
                state.clone()
            }
        };
        Ok(Self { source_id, pairwise_info, state, send_message })
    }

    pub fn handle_ack(self, _ack: Ack) -> VcxResult<Self> {
        Ok(self)
    }
}

#[cfg(test)]
pub mod test {
    use crate::aries::messages::ack::tests::_ack;
    use crate::aries::messages::connection::invite::tests::_invitation;
    use crate::aries::messages::connection::problem_report::tests::_problem_report;
    use crate::aries::messages::connection::request::tests::_request;
    use crate::aries::messages::connection::response::tests::_signed_response;
    use crate::aries::messages::discovery::disclose::tests::_disclose;
    use crate::aries::messages::discovery::query::tests::_query;
    use crate::aries::messages::trust_ping::ping::tests::_ping;
    use crate::aries::messages::trust_ping::ping_response::tests::_ping_response;
    use crate::aries::test::source_id;
    use crate::utils::devsetup::SetupMocks;

    use super::*;

    pub mod invitee {
        use crate::aries::messages::connection::did_doc::tests::_service_endpoint;
        use crate::aries::messages::connection::response::{Response, SignedResponse};

        use super::*;

        fn _send_message(pv_wk: &str, did_doc: &DidDoc, a2a_message: &A2AMessage) -> VcxResult<()> {
            VcxResult::Ok(())
        }

        pub fn invitee_sm() -> SmConnectionInvitee {
            let pairwise_info = PairwiseInfo::create().unwrap();
            SmConnectionInvitee::new(&source_id(), pairwise_info, _send_message)
        }

        impl SmConnectionInvitee {
            pub fn to_invitee_invited_state(mut self) -> SmConnectionInvitee {
                self = self.handle_invitation(_invitation()).unwrap();
                self
            }

            pub fn to_invitee_requested_state(mut self) -> SmConnectionInvitee {
                self = self.handle_invitation(_invitation()).unwrap();
                let routing_keys: Vec<String> = vec!("verkey123".into());
                let service_endpoint = String::from("https://example.org/agent");
                self = self.handle_connect(routing_keys, service_endpoint).unwrap();
                self
            }

            pub fn to_invitee_completed_state(mut self) -> SmConnectionInvitee {
                let key = "GJ1SzoWzavQYfNL9XkaJdrQejfztN4XqdsiV4ct3LXKL".to_string();
                let invitation = Invitation::default().set_recipient_keys(vec![key.clone()]);

                self = self.handle_invitation(invitation).unwrap();

                let routing_keys: Vec<String> = vec!("verkey123".into());
                let service_endpoint = String::from("https://example.org/agent");
                self = self.handle_connect(routing_keys, service_endpoint).unwrap();
                self = self.handle_connection_response(_response(&key)).unwrap();
                self = self.handle_send_ack().unwrap();
                self = self.handle_ack(_ack()).unwrap();
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
                let _setup = SetupMocks::init();

                let invitee_sm = invitee_sm();

                assert_match!(InviteeFullState::Null(_), invitee_sm.state);
                assert_eq!(source_id(), invitee_sm.source_id());
            }
        }

        mod step {
            use crate::utils::devsetup::SetupIndyMocks;

            use super::*;

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_init() {
                let _setup = SetupIndyMocks::init();

                let did_exchange_sm = invitee_sm();

                assert_match!(InviteeFullState::Null(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_invite_message_from_null_state() {
                let _setup = SetupIndyMocks::init();

                let mut did_exchange_sm = invitee_sm();

                did_exchange_sm = did_exchange_sm.handle_invitation(_invitation()).unwrap();

                assert_match!(InviteeFullState::Invited(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_other_message_from_null_state() {
                let _setup = SetupIndyMocks::init();

                let mut did_exchange_sm = invitee_sm();

                let routing_keys: Vec<String> = vec!("verkey123".into());
                let service_endpoint = String::from("https://example.org/agent");
                did_exchange_sm = did_exchange_sm.handle_connect(routing_keys, service_endpoint).unwrap();
                assert_match!(InviteeFullState::Null(_), did_exchange_sm.state);

                did_exchange_sm = did_exchange_sm.handle_ack(_ack()).unwrap();
                assert_match!(InviteeFullState::Null(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_connect_message_from_invited_state() {
                let _setup = SetupIndyMocks::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_invited_state();

                let routing_keys: Vec<String> = vec!("verkey123".into());
                let service_endpoint = String::from("https://example.org/agent");
                did_exchange_sm = did_exchange_sm.handle_connect(routing_keys, service_endpoint).unwrap();

                assert_match!(InviteeFullState::Requested(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_problem_report_message_from_invited_state() {
                let _setup = SetupIndyMocks::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_invited_state();

                did_exchange_sm = did_exchange_sm.handle_problem_report(_problem_report()).unwrap();

                assert_match!(InviteeFullState::Null(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_response_message_from_requested_state() {
                let _setup = SetupIndyMocks::init();

                let key = "GJ1SzoWzavQYfNL9XkaJdrQejfztN4XqdsiV4ct3LXKL";

                let mut did_exchange_sm = invitee_sm().to_invitee_requested_state();

                did_exchange_sm = did_exchange_sm.handle_connection_response(_response(&key)).unwrap();
                did_exchange_sm = did_exchange_sm.handle_send_ack().unwrap();

                assert_match!(InviteeFullState::Completed(_), did_exchange_sm.state);
            }


            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_other_messages_from_invited_state() {
                let _setup = SetupIndyMocks::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_invited_state();

                did_exchange_sm = did_exchange_sm.handle_ack(_ack()).unwrap();
                assert_match!(InviteeFullState::Invited(_), did_exchange_sm.state);

                did_exchange_sm = did_exchange_sm.handle_discovery_query(_query()).unwrap();
                assert_match!(InviteeFullState::Invited(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_invalid_response_message_from_requested_state() {
                let _setup = SetupIndyMocks::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_requested_state();

                let mut signed_response = _signed_response();
                signed_response.connection_sig.signature = String::from("other");

                did_exchange_sm = did_exchange_sm.handle_connection_response(signed_response).unwrap();
                did_exchange_sm = did_exchange_sm.handle_send_ack().unwrap();

                assert_match!(InviteeFullState::Null(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_problem_report_message_from_requested_state() {
                let _setup = SetupIndyMocks::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_requested_state();

                did_exchange_sm = did_exchange_sm.handle_problem_report(_problem_report()).unwrap();

                assert_match!(InviteeFullState::Null(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_other_messages_from_requested_state() {
                let _setup = SetupIndyMocks::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_requested_state();

                did_exchange_sm = did_exchange_sm.handle_ack(_ack()).unwrap();
                assert_match!(InviteeFullState::Requested(_), did_exchange_sm.state);

                did_exchange_sm = did_exchange_sm.handle_ping(_ping()).unwrap();
                assert_match!(InviteeFullState::Requested(_), did_exchange_sm.state);
            }

            #[test]
            #[cfg(feature = "general_test")]
            fn test_did_exchange_handle_messages_from_completed_state() {
                let _setup = SetupIndyMocks::init();

                let mut did_exchange_sm = invitee_sm().to_invitee_completed_state();

                // Send Ping
                did_exchange_sm = did_exchange_sm.handle_send_ping(None).unwrap();
                assert_match!(InviteeFullState::Completed(_), did_exchange_sm.state);

                // Ping
                did_exchange_sm = did_exchange_sm.handle_ping(_ping()).unwrap();
                assert_match!(InviteeFullState::Completed(_), did_exchange_sm.state);

                // Ping Response
                did_exchange_sm = did_exchange_sm.handle_ping_response(_ping_response()).unwrap();
                assert_match!(InviteeFullState::Completed(_), did_exchange_sm.state);

                // Discovery Features
                did_exchange_sm = did_exchange_sm.handle_discover_features(None, None).unwrap();
                assert_match!(InviteeFullState::Completed(_), did_exchange_sm.state);

                // Query
                did_exchange_sm = did_exchange_sm.handle_discovery_query(_query()).unwrap();
                assert_match!(InviteeFullState::Completed(_), did_exchange_sm.state);

                // Disclose
                assert!(did_exchange_sm.get_remote_protocols().is_none());

                did_exchange_sm = did_exchange_sm.handle_disclose(_disclose()).unwrap();
                assert_match!(InviteeFullState::Completed(_), did_exchange_sm.state);

                assert!(did_exchange_sm.get_remote_protocols().is_some());

                // ignore
                // Ack
                did_exchange_sm = did_exchange_sm.handle_ack(_ack()).unwrap();
                assert_match!(InviteeFullState::Completed(_), did_exchange_sm.state);

                // Problem Report
                did_exchange_sm = did_exchange_sm.handle_problem_report(_problem_report()).unwrap();
                assert_match!(InviteeFullState::Completed(_), did_exchange_sm.state);
            }
        }

        mod find_message_to_handle {
            use crate::utils::devsetup::SetupIndyMocks;

            use super::*;

            #[test]
            #[cfg(feature = "general_test")]
            fn test_find_message_to_handle_from_invited_state() {
                let _setup = SetupIndyMocks::init();

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
                let _setup = SetupIndyMocks::init();

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
                let _setup = SetupIndyMocks::init();

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
                let _setup = SetupMocks::init();

                assert_eq!(InviteeState::Null, invitee_sm().get_state());
                assert_eq!(InviteeState::Invited, invitee_sm().to_invitee_invited_state().get_state());
                assert_eq!(InviteeState::Requested, invitee_sm().to_invitee_requested_state().get_state());
            }
        }
    }
}
