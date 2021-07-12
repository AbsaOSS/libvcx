use std::collections::HashMap;

use crate::aries::handlers::proof_presentation::prover::prover::ProverState;
use crate::aries::handlers::proof_presentation::prover::messages::ProverMessages;
use crate::aries::handlers::proof_presentation::prover::states::finished::FinishedState;
use crate::aries::handlers::proof_presentation::prover::states::initial::InitialState;
use crate::aries::handlers::proof_presentation::prover::states::presentation_prepared::PresentationPreparedState;
use crate::aries::handlers::proof_presentation::prover::states::presentation_prepared_failed::PresentationPreparationFailedState;
use crate::aries::handlers::proof_presentation::prover::states::presentation_sent::PresentationSentState;
use crate::aries::messages::a2a::A2AMessage;
use crate::aries::messages::error::ProblemReport;
use crate::aries::messages::proof_presentation::presentation::Presentation;
use crate::aries::messages::proof_presentation::presentation_proposal::{PresentationPreview, PresentationProposal};
use crate::aries::messages::proof_presentation::presentation_request::PresentationRequest;
use crate::aries::messages::status::Status;
use crate::error::prelude::*;

/// A state machine that tracks the evolution of states for a Prover during
/// the Present Proof protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProverSM {
    source_id: String,
    thread_id: String,
    state: ProverFullState,
}

impl ProverSM {
    pub fn new(presentation_request: PresentationRequest, source_id: String) -> ProverSM {
        ProverSM { source_id, thread_id: presentation_request.id.0.clone(), state: ProverFullState::Initiated(InitialState { presentation_request }) }
    }
}

// Possible Transitions:
//
// Initial -> PresentationPrepared, PresentationPreparationFailedState, Finished
// PresentationPrepared -> PresentationSent, Finished
// PresentationPreparationFailedState -> Finished
// PresentationSent -> Finished
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProverFullState {
    Initiated(InitialState),
    PresentationPrepared(PresentationPreparedState),
    PresentationPreparationFailed(PresentationPreparationFailedState),
    PresentationSent(PresentationSentState),
    Finished(FinishedState),
}

impl ProverSM {
    pub fn find_message_to_handle(&self, messages: HashMap<String, A2AMessage>) -> Option<(String, A2AMessage)> {
        trace!("Prover::find_message_to_handle >>> messages: {:?}", messages);

        for (uid, message) in messages {
            match self.state {
                ProverFullState::Initiated(_) => {
                    match message {
                        A2AMessage::PresentationRequest(_) => {
                            // ignore it here??
                        }
                        _ => {}
                    }
                }
                ProverFullState::PresentationPrepared(_) => {
                    // do not process messages
                }
                ProverFullState::PresentationPreparationFailed(_) => {
                    // do not process messages
                }
                ProverFullState::PresentationSent(_) => {
                    match message {
                        A2AMessage::Ack(ack) | A2AMessage::PresentationAck(ack) => {
                            if ack.from_thread(&self.thread_id) {
                                return Some((uid, A2AMessage::PresentationAck(ack)));
                            }
                        }
                        A2AMessage::CommonProblemReport(problem_report) => {
                            if problem_report.from_thread(&self.thread_id) {
                                return Some((uid, A2AMessage::CommonProblemReport(problem_report)));
                            }
                        }
                        _ => {}
                    }
                }
                ProverFullState::Finished(_) => {
                    // do not process messages
                }
            };
        }

        None
    }

    pub fn step(self,
                message: ProverMessages,
                send_message: Option<&impl Fn(&A2AMessage) -> VcxResult<()>>,
    ) -> VcxResult<ProverSM> {
        trace!("ProverSM::step >>> message: {:?}", message);

        let ProverSM { source_id, state, thread_id } = self;

        let state = match state {
            ProverFullState::Initiated(state) => {
                match message {
                    ProverMessages::SetPresentation(presentation) => {
                        let presentation = presentation.set_thread_id(&thread_id);
                        ProverFullState::PresentationPrepared((state, presentation).into())
                    }
                    ProverMessages::PreparePresentation((credentials, self_attested_attrs)) => {
                        match state.build_presentation(&credentials, &self_attested_attrs) {
                            Ok(presentation) => {
                                let presentation = Presentation::create()
                                    .ask_for_ack()
                                    .set_thread_id(&thread_id)
                                    .set_presentations_attach(presentation)?;

                                ProverFullState::PresentationPrepared((state, presentation).into())
                            }
                            Err(err) => {
                                let problem_report =
                                    ProblemReport::create()
                                        .set_comment(err.to_string())
                                        .set_thread_id(&thread_id);

                                ProverFullState::PresentationPreparationFailed((state, problem_report).into())
                            }
                        }
                    }
                    ProverMessages::RejectPresentationRequest(reason) => {
                        if let Some(send_message) = send_message {
                            Self::_handle_reject_presentation_request(send_message, &reason, &thread_id)?;
                            ProverFullState::Finished(state.into())
                        } else {
                            return Err(VcxError::from_msg(VcxErrorKind::ActionNotSupported, "Send message closure is required."));
                        }
                    }
                    ProverMessages::ProposePresentation(preview) => {
                        if let Some(send_message) = send_message {
                            Self::_handle_presentation_proposal(send_message, preview, &thread_id)?;
                            ProverFullState::Finished(state.into())
                        } else {
                            return Err(VcxError::from_msg(VcxErrorKind::ActionNotSupported, "Send message closure is required."));
                        }
                    }
                    _ => {
                        ProverFullState::Initiated(state)
                    }
                }
            }
            ProverFullState::PresentationPrepared(state) => {
                match message {
                    ProverMessages::SendPresentation => {
                        if let Some(send_message) = send_message {
                            send_message(&state.presentation.to_a2a_message())?;
                            ProverFullState::PresentationSent((state).into())
                        } else {
                            return Err(VcxError::from_msg(VcxErrorKind::ActionNotSupported, "Send message closure is required."));
                        }
                    }
                    ProverMessages::RejectPresentationRequest(reason) => {
                        if let Some(send_message) = send_message {
                            Self::_handle_reject_presentation_request(send_message, &reason, &thread_id)?;
                            ProverFullState::Finished(state.into())
                        } else {
                            return Err(VcxError::from_msg(VcxErrorKind::ActionNotSupported, "Send message closure is required."));
                        }
                    }
                    ProverMessages::ProposePresentation(preview) => {
                        if let Some(send_message) = send_message {
                            Self::_handle_presentation_proposal(send_message, preview, &thread_id)?;
                            ProverFullState::Finished(state.into())
                        } else {
                            return Err(VcxError::from_msg(VcxErrorKind::ActionNotSupported, "Send message closure is required."));
                        }
                    }
                    _ => {
                        ProverFullState::PresentationPrepared(state)
                    }
                }
            }
            ProverFullState::PresentationPreparationFailed(state) => {
                match message {
                    ProverMessages::SendPresentation => {
                        if let Some(send_message) = send_message {
                            send_message(&state.problem_report.to_a2a_message())?;
                            ProverFullState::Finished((state).into())
                        } else {
                            return Err(VcxError::from_msg(VcxErrorKind::ActionNotSupported, "Send message closure is required."));
                        }
                    }
                    _ => {
                        ProverFullState::PresentationPreparationFailed(state)
                    }
                }
            }
            ProverFullState::PresentationSent(state) => {
                match message {
                    ProverMessages::PresentationAckReceived(ack) => {
                        ProverFullState::Finished((state, ack).into())
                    }
                    ProverMessages::PresentationRejectReceived(problem_report) => {
                        ProverFullState::Finished((state, problem_report).into())
                    }
                    ProverMessages::RejectPresentationRequest(_) => {
                        return Err(VcxError::from_msg(VcxErrorKind::ActionNotSupported, "Presentation is already sent"));
                    }
                    _ => {
                        ProverFullState::PresentationSent(state)
                    }
                }
            }
            ProverFullState::Finished(state) => ProverFullState::Finished(state)
        };

        Ok(ProverSM { source_id, state, thread_id })
    }

    fn _handle_reject_presentation_request(
        send_message: &impl Fn(&A2AMessage) -> VcxResult<()>,
        reason: &str,
        thread_id: &str,
    ) -> VcxResult<()> {
        let problem_report = ProblemReport::create()
            .set_comment(reason.to_string())
            .set_thread_id(thread_id);

        send_message(&problem_report.to_a2a_message())
    }

    fn _handle_presentation_proposal(
        send_message: &impl Fn(&A2AMessage) -> VcxResult<()>,
        preview: PresentationPreview,
        thread_id: &str,
    ) -> VcxResult<()> {
        let proposal = PresentationProposal::create()
            .set_presentation_preview(preview)
            .set_thread_id(thread_id);

        send_message(&proposal.to_a2a_message())
    }

    pub fn source_id(&self) -> String { self.source_id.clone() }

    pub fn get_state(&self) -> ProverState {
        match self.state {
            ProverFullState::Initiated(_) => ProverState::Initial,
            ProverFullState::PresentationPrepared(_) => ProverState::PresentationPrepared,
            ProverFullState::PresentationPreparationFailed(_) => ProverState::PresentationPreparationFailed,
            ProverFullState::PresentationSent(_) => ProverState::PresentationSent,
            ProverFullState::Finished(ref status) => {
                match status.status {
                    Status::Success => ProverState::Finished,
                    _ => ProverState::Failed
                }
            }
        }
    }

    pub fn has_transitions(&self) -> bool {
        trace!("Prover::states::has_transitions >> state: {:?}", self.state);
        match self.state {
            ProverFullState::Initiated(_) => false,
            ProverFullState::PresentationPrepared(_) => true,
            ProverFullState::PresentationPreparationFailed(_) => true,
            ProverFullState::PresentationSent(_) => true,
            ProverFullState::Finished(_) => false,
        }
    }

    pub fn presentation_status(&self) -> u32 {
        match self.state {
            ProverFullState::Finished(ref state) => state.status.code(),
            _ => Status::Undefined.code()
        }
    }

    pub fn presentation_request(&self) -> &PresentationRequest {
        match self.state {
            ProverFullState::Initiated(ref state) => &state.presentation_request,
            ProverFullState::PresentationPrepared(ref state) => &state.presentation_request,
            ProverFullState::PresentationPreparationFailed(ref state) => &state.presentation_request,
            ProverFullState::PresentationSent(ref state) => &state.presentation_request,
            ProverFullState::Finished(ref state) => &state.presentation_request,
        }
    }

    pub fn presentation(&self) -> VcxResult<&Presentation> {
        match self.state {
            ProverFullState::Initiated(_) => Err(VcxError::from_msg(VcxErrorKind::NotReady, "Presentation is not created yet")),
            ProverFullState::PresentationPrepared(ref state) => Ok(&state.presentation),
            ProverFullState::PresentationPreparationFailed(_) => Err(VcxError::from_msg(VcxErrorKind::NotReady, "Presentation is not created yet")),
            ProverFullState::PresentationSent(ref state) => Ok(&state.presentation),
            ProverFullState::Finished(ref state) => Ok(&state.presentation),
        }
    }
}

#[cfg(test)]
pub mod test {
    use crate::aries::messages::proof_presentation::presentation::tests::_presentation;
    use crate::aries::messages::proof_presentation::presentation_proposal::tests::{_presentation_preview, _presentation_proposal};
    use crate::aries::messages::proof_presentation::presentation_request::tests::_presentation_request;
    use crate::aries::messages::proof_presentation::test::{_ack, _problem_report};
    use crate::aries::test::source_id;
    use crate::utils::devsetup::SetupMocks;

    use super::*;

    pub fn _prover_sm() -> ProverSM {
        ProverSM::new(_presentation_request(), source_id())
    }

    impl ProverSM {
        fn to_presentation_prepared_state(mut self) -> ProverSM {
            self = self.step(ProverMessages::PreparePresentation((_credentials(), _self_attested())), None::<&fn(&A2AMessage) -> _>).unwrap();
            self
        }

        fn to_presentation_sent_state(mut self) -> ProverSM {
            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            self = self.step(ProverMessages::PreparePresentation((_credentials(), _self_attested())), send_message).unwrap();
            self = self.step(ProverMessages::SendPresentation, send_message).unwrap();
            self
        }

        fn to_finished_state(mut self) -> ProverSM {
            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            self = self.step(ProverMessages::PreparePresentation((_credentials(), _self_attested())), None::<&fn(&A2AMessage) -> _>).unwrap();
            self = self.step(ProverMessages::SendPresentation, send_message).unwrap();
            self = self.step(ProverMessages::PresentationAckReceived(_ack()), send_message).unwrap();
            self
        }
    }

    fn _credentials() -> String {
        json!({
            "attrs":{
            "attribute_0":{
                "credential":{
                    "cred_info":{
                        "attrs":{"name": "alice"},
                        "cred_def_id": "V4SGRU86Z58d6TV7PBUe6f:3:CL:419:tag",
                        "referent": "a1991de8-8317-43fd-98b3-63bac40b9e8b",
                        "schema_id": "V4SGRU86Z58d6TV7PBUe6f:2:QcimrRShWQniqlHUtIDddYP0n:1.0"
                        }
                    }
                }
            }
        }).to_string()
    }

    fn _self_attested() -> String {
        json!({}).to_string()
    }

    mod new {
        use super::*;

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_new() {
            let _setup = SetupMocks::init();

            let prover_sm = _prover_sm();

            assert_match!(ProverFullState::Initiated(_), prover_sm.state);
            assert_eq!(source_id(), prover_sm.source_id());
        }
    }

    mod step {
        use crate::utils::constants::CREDS_FROM_PROOF_REQ;
        use crate::utils::mockdata::mock_settings::MockBuilder;

        use super::*;

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_init() {
            let _setup = SetupMocks::init();

            let prover_sm = _prover_sm();
            assert_match!(ProverFullState::Initiated(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_prepare_presentation_message_from_initiated_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();
            prover_sm = prover_sm.step(ProverMessages::PreparePresentation((_credentials(), _self_attested())), send_message).unwrap();

            assert_match!(ProverFullState::PresentationPrepared(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_prepare_presentation_message_from_initiated_state_for_invalid_credentials() {
            let _setup = SetupMocks::init();
            let _mock_builder = MockBuilder::init().
                set_mock_creds_retrieved_for_proof_request(CREDS_FROM_PROOF_REQ);

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();
            prover_sm = prover_sm.step(ProverMessages::PreparePresentation(("invalid".to_string(), _self_attested())), send_message).unwrap();

            assert_match!(ProverFullState::PresentationPreparationFailed(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_reject_presentation_request_message_from_initiated_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();
            prover_sm = prover_sm.step(ProverMessages::RejectPresentationRequest(String::from("reject request")), send_message).unwrap();

            assert_match!(ProverFullState::Finished(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_propose_presentation_message_from_initiated_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();
            prover_sm = prover_sm.step(ProverMessages::ProposePresentation((_presentation_preview())), send_message).unwrap();

            assert_match!(ProverFullState::Finished(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_other_messages_from_initiated_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();

            prover_sm = prover_sm.step(ProverMessages::SendPresentation, send_message).unwrap();
            assert_match!(ProverFullState::Initiated(_), prover_sm.state);

            prover_sm = prover_sm.step(ProverMessages::PresentationAckReceived(_ack()), send_message).unwrap();
            assert_match!(ProverFullState::Initiated(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_send_presentation_message_from_presentation_prepared_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();

            prover_sm = prover_sm.step(ProverMessages::PreparePresentation((_credentials(), _self_attested())), send_message).unwrap();
            prover_sm = prover_sm.step(ProverMessages::SendPresentation, send_message).unwrap();

            assert_match!(ProverFullState::PresentationSent(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_other_messages_from_presentation_prepared_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm().to_presentation_prepared_state();

            prover_sm = prover_sm.step(ProverMessages::PresentationRejectReceived(_problem_report()), send_message).unwrap();
            assert_match!(ProverFullState::PresentationPrepared(_), prover_sm.state);

            prover_sm = prover_sm.step(ProverMessages::PresentationAckReceived(_ack()), send_message).unwrap();
            assert_match!(ProverFullState::PresentationPrepared(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_reject_presentation_request_message_from_presentation_prepared_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm().to_presentation_prepared_state();

            prover_sm = prover_sm.step(ProverMessages::RejectPresentationRequest(String::from("reject request")), send_message).unwrap();

            assert_match!(ProverFullState::Finished(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_propose_presentation_message_from_presentation_prepared_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm().to_presentation_prepared_state();
            prover_sm = prover_sm.step(ProverMessages::ProposePresentation(_presentation_preview()), send_message).unwrap();

            assert_match!(ProverFullState::Finished(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_send_presentation_message_from_presentation_preparation_failed_state() {
            let _setup = SetupMocks::init();
            let _mock_builder = MockBuilder::init().
                set_mock_creds_retrieved_for_proof_request(CREDS_FROM_PROOF_REQ);

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();
            prover_sm = prover_sm.step(ProverMessages::PreparePresentation(("invalid".to_string(), _self_attested())), send_message).unwrap();
            assert_match!(ProverFullState::PresentationPreparationFailed(_), prover_sm.state);

            prover_sm = prover_sm.step(ProverMessages::SendPresentation, send_message).unwrap();
            assert_match!(ProverFullState::Finished(_), prover_sm.state);
            assert_eq!(Status::Failed(ProblemReport::default()).code(), prover_sm.presentation_status());
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_other_messages_from_presentation_preparation_failed_state() {
            let _setup = SetupMocks::init();
            let _mock_builder = MockBuilder::init().
                set_mock_creds_retrieved_for_proof_request(CREDS_FROM_PROOF_REQ);

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();
            prover_sm = prover_sm.step(ProverMessages::PreparePresentation(("invalid".to_string(), _self_attested())), send_message).unwrap();

            prover_sm = prover_sm.step(ProverMessages::PresentationRejectReceived(_problem_report()), send_message).unwrap();
            assert_match!(ProverFullState::PresentationPreparationFailed(_), prover_sm.state);

            prover_sm = prover_sm.step(ProverMessages::PresentationAckReceived(_ack()), send_message).unwrap();
            assert_match!(ProverFullState::PresentationPreparationFailed(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_ack_message_from_presentation_sent_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();
            prover_sm = prover_sm.step(ProverMessages::PreparePresentation((_credentials(), _self_attested())), send_message).unwrap();
            prover_sm = prover_sm.step(ProverMessages::SendPresentation, send_message).unwrap();
            prover_sm = prover_sm.step(ProverMessages::PresentationAckReceived(_ack()), send_message).unwrap();

            assert_match!(ProverFullState::Finished(_), prover_sm.state);
            assert_eq!(Status::Success.code(), prover_sm.presentation_status());
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_reject_presentation_request_message_from_presentation_sent_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let prover_sm = _prover_sm().to_presentation_sent_state();
            let err = prover_sm.step(ProverMessages::RejectPresentationRequest(String::from("reject")), send_message).unwrap_err();
            assert_eq!(VcxErrorKind::ActionNotSupported, err.kind());
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_presentation_reject_message_from_presentation_sent_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();
            prover_sm = prover_sm.step(ProverMessages::PreparePresentation((_credentials(), _self_attested())), send_message).unwrap();
            prover_sm = prover_sm.step(ProverMessages::SendPresentation, send_message).unwrap();
            prover_sm = prover_sm.step(ProverMessages::PresentationRejectReceived(_problem_report()), send_message).unwrap();

            assert_match!(ProverFullState::Finished(_), prover_sm.state);
            assert_eq!(Status::Failed(ProblemReport::create()).code(), prover_sm.presentation_status());
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_other_messages_from_presentation_sent_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();
            prover_sm = prover_sm.step(ProverMessages::PreparePresentation((_credentials(), _self_attested())), send_message).unwrap();
            prover_sm = prover_sm.step(ProverMessages::SendPresentation, send_message).unwrap();

            prover_sm = prover_sm.step(ProverMessages::PreparePresentation((_credentials(), _self_attested())), send_message).unwrap();
            assert_match!(ProverFullState::PresentationSent(_), prover_sm.state);

            prover_sm = prover_sm.step(ProverMessages::SendPresentation, send_message).unwrap();
            assert_match!(ProverFullState::PresentationSent(_), prover_sm.state);
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_handle_messages_from_finished_state() {
            let _setup = SetupMocks::init();

            let send_message = Some(&|_: &A2AMessage| VcxResult::Ok(()));
            let mut prover_sm = _prover_sm();
            prover_sm = prover_sm.step(ProverMessages::PreparePresentation((_credentials(), _self_attested())), send_message).unwrap();
            prover_sm = prover_sm.step(ProverMessages::SendPresentation, send_message).unwrap();
            prover_sm = prover_sm.step(ProverMessages::PresentationAckReceived(_ack()), send_message).unwrap();

            prover_sm = prover_sm.step(ProverMessages::PresentationAckReceived(_ack()), send_message).unwrap();
            assert_match!(ProverFullState::Finished(_), prover_sm.state);

            prover_sm = prover_sm.step(ProverMessages::PresentationRejectReceived(_problem_report()), send_message).unwrap();
            assert_match!(ProverFullState::Finished(_), prover_sm.state);
        }
    }

    mod find_message_to_handle {
        use super::*;

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_find_message_to_handle_from_initiated_state() {
            let _setup = SetupMocks::init();

            let prover = _prover_sm();

            // No messages
            {
                let messages = map!(
                    "key_1".to_string() => A2AMessage::PresentationProposal(_presentation_proposal()),
                    "key_2".to_string() => A2AMessage::Presentation(_presentation()),
                    "key_3".to_string() => A2AMessage::PresentationRequest(_presentation_request()),
                    "key_4".to_string() => A2AMessage::PresentationAck(_ack()),
                    "key_5".to_string() => A2AMessage::CommonProblemReport(_problem_report())
                );

                assert!(prover.find_message_to_handle(messages).is_none());
            }
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_find_message_to_handle_from_presentation_prepared_state() {
            let _setup = SetupMocks::init();

            let prover = _prover_sm().to_presentation_prepared_state();

            // No messages
            {
                let messages = map!(
                    "key_1".to_string() => A2AMessage::PresentationProposal(_presentation_proposal()),
                    "key_2".to_string() => A2AMessage::Presentation(_presentation()),
                    "key_3".to_string() => A2AMessage::PresentationRequest(_presentation_request()),
                    "key_4".to_string() => A2AMessage::PresentationAck(_ack()),
                    "key_5".to_string() => A2AMessage::CommonProblemReport(_problem_report())
                );

                assert!(prover.find_message_to_handle(messages).is_none());
            }
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_find_message_to_handle_from_presentation_sent_state() {
            let _setup = SetupMocks::init();

            let prover = _prover_sm().to_presentation_sent_state();

            // Ack
            {
                let messages = map!(
                    "key_1".to_string() => A2AMessage::PresentationProposal(_presentation_proposal()),
                    "key_2".to_string() => A2AMessage::Presentation(_presentation()),
                    "key_3".to_string() => A2AMessage::PresentationAck(_ack())
                );

                let (uid, message) = prover.find_message_to_handle(messages).unwrap();
                assert_eq!("key_3", uid);
                assert_match!(A2AMessage::PresentationAck(_), message);
            }

            // Problem Report
            {
                let messages = map!(
                    "key_1".to_string() => A2AMessage::PresentationProposal(_presentation_proposal()),
                    "key_2".to_string() => A2AMessage::PresentationRequest(_presentation_request()),
                    "key_3".to_string() => A2AMessage::CommonProblemReport(_problem_report())
                );

                let (uid, message) = prover.find_message_to_handle(messages).unwrap();
                assert_eq!("key_3", uid);
                assert_match!(A2AMessage::CommonProblemReport(_), message);
            }

            // No messages for different Thread ID
            {
                let messages = map!(
                    "key_1".to_string() => A2AMessage::PresentationProposal(_presentation_proposal().set_thread_id("")),
                    "key_2".to_string() => A2AMessage::Presentation(_presentation().set_thread_id("")),
                    "key_3".to_string() => A2AMessage::PresentationAck(_ack().set_thread_id("")),
                    "key_4".to_string() => A2AMessage::CommonProblemReport(_problem_report().set_thread_id(""))
                );

                assert!(prover.find_message_to_handle(messages).is_none());
            }

            // No messages
            {
                let messages = map!(
                    "key_1".to_string() => A2AMessage::PresentationProposal(_presentation_proposal()),
                    "key_2".to_string() => A2AMessage::PresentationRequest(_presentation_request())
                );

                assert!(prover.find_message_to_handle(messages).is_none());
            }
        }

        #[test]
        #[cfg(feature = "general_test")]
        fn test_prover_find_message_to_handle_from_finished_state() {
            let _setup = SetupMocks::init();

            let prover = _prover_sm().to_finished_state();

            // No messages
            {
                let messages = map!(
                    "key_1".to_string() => A2AMessage::PresentationProposal(_presentation_proposal()),
                    "key_2".to_string() => A2AMessage::Presentation(_presentation()),
                    "key_3".to_string() => A2AMessage::PresentationRequest(_presentation_request()),
                    "key_4".to_string() => A2AMessage::PresentationAck(_ack()),
                    "key_5".to_string() => A2AMessage::CommonProblemReport(_problem_report())
                );

                assert!(prover.find_message_to_handle(messages).is_none());
            }
        }
    }

    mod get_state {
        use super::*;

        #[test]
        #[cfg(feature = "general_test")]
        fn test_get_state() {
            let _setup = SetupMocks::init();

            assert_eq!(ProverState::Initial, _prover_sm().get_state());
            assert_eq!(ProverState::PresentationPrepared, _prover_sm().to_presentation_prepared_state().get_state());
            assert_eq!(ProverState::PresentationSent, _prover_sm().to_presentation_sent_state().get_state());
            assert_eq!(ProverState::Finished, _prover_sm().to_finished_state().get_state());
        }
    }
}
