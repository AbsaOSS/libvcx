use v3::handlers::issuance::issuer::state_machine::RevocationInfoV1;
use v3::handlers::issuance::issuer::states::credential_sent::CredentialSentState;
use v3::handlers::issuance::issuer::states::finished::FinishedState;
use v3::messages::a2a::MessageId;
use v3::messages::error::ProblemReport;
use v3::messages::issuance::credential_request::CredentialRequest;
use v3::messages::status::Status;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestReceivedState {
    pub offer: String,
    pub cred_data: String,
    pub rev_reg_id: Option<String>,
    pub tails_file: Option<String>,
    pub connection_handle: u32,
    pub request: CredentialRequest,
    pub thread_id: String,
}

impl From<(RequestReceivedState, MessageId)> for CredentialSentState {
    fn from((state, _sent_id): (RequestReceivedState, MessageId)) -> Self {
        trace!("SM is now in CredentialSent state");
        CredentialSentState {
            connection_handle: state.connection_handle,
            revocation_info_v1: Some(RevocationInfoV1 {
                cred_rev_id: None,
                rev_reg_id: state.rev_reg_id,
                tails_file: state.tails_file,
            }),
            thread_id: state.thread_id,
        }
    }
}

impl From<(RequestReceivedState, Option<String>)> for FinishedState {
    fn from((state, cred_rev_id): (RequestReceivedState, Option<String>)) -> Self {
        trace!("SM is now in Finished state");
        FinishedState {
            cred_id: None,
            thread_id: state.thread_id,
            revocation_info_v1: Some(RevocationInfoV1 {
                cred_rev_id,
                rev_reg_id: state.rev_reg_id,
                tails_file: state.tails_file,
            }),
            status: Status::Success,
        }
    }
}

impl From<(RequestReceivedState, ProblemReport)> for FinishedState {
    fn from((state, err): (RequestReceivedState, ProblemReport)) -> Self {
        trace!("SM is now in Finished state");
        FinishedState {
            cred_id: None,
            thread_id: state.thread_id,
            revocation_info_v1: Some(RevocationInfoV1 {
                cred_rev_id: None,
                rev_reg_id: state.rev_reg_id,
                tails_file: state.tails_file,
            }),
            status: Status::Failed(err),
        }
    }
}