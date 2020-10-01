use connection;
use error::{VcxError, VcxErrorKind, VcxResult};
use v3::handlers::proof_presentation::verifier::states::finished::FinishedState;
use v3::handlers::proof_presentation::verifier::state_machine::RevocationStatus;
use v3::messages::a2a::A2AMessage;
use v3::messages::error::ProblemReport;
use v3::messages::proof_presentation::presentation::Presentation;
use v3::messages::proof_presentation::presentation_ack::PresentationAck;
use v3::messages::proof_presentation::presentation_request::PresentationRequest;
use v3::messages::status::Status;
use proof_utils::validate_indy_proof;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresentationRequestSentState {
    pub connection_handle: u32,
    pub presentation_request: PresentationRequest,
}


impl PresentationRequestSentState {
    pub fn verify_presentation(&self, presentation: &Presentation) -> VcxResult<()> {
        let valid = validate_indy_proof(&presentation.presentations_attach.content()?,
                                               &self.presentation_request.request_presentations_attach.content()?)?;

        if !valid {
            return Err(VcxError::from_msg(VcxErrorKind::InvalidProof, "Presentation verification failed"));
        }

        if presentation.please_ack.is_some() {
            let ack = PresentationAck::create().set_thread_id(&self.presentation_request.id.0);
            connection::send_message(self.connection_handle, A2AMessage::PresentationAck(ack))?;
        }

        Ok(())
    }
}


impl From<(PresentationRequestSentState, Presentation, RevocationStatus)> for FinishedState {
    fn from((state, presentation, was_revoked): (PresentationRequestSentState, Presentation, RevocationStatus)) -> Self {
        trace!("transit state from PresentationRequestSentState to FinishedState");
        FinishedState {
            connection_handle: state.connection_handle,
            presentation_request: state.presentation_request,
            presentation: Some(presentation),
            status: Status::Success,
            revocation_status: Some(was_revoked),
        }
    }
}

impl From<(PresentationRequestSentState, ProblemReport)> for FinishedState {
    fn from((state, problem_report): (PresentationRequestSentState, ProblemReport)) -> Self {
        trace!("transit state from PresentationRequestSentState to FinishedState");
        FinishedState {
            connection_handle: state.connection_handle,
            presentation_request: state.presentation_request,
            presentation: None,
            status: Status::Failed(problem_report),
            revocation_status: None,
        }
    }
}
