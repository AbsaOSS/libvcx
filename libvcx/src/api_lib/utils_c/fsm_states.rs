use crate::aries::handlers::connection::connection::ConnectionState;
use crate::aries::handlers::connection::invitee::state_machine::InviteeState;
use crate::aries::handlers::connection::inviter::state_machine::InviterState;
use crate::aries::handlers::issuance::holder::holder::HolderState;
use crate::aries::handlers::issuance::issuer::issuer::IssuerState;
use crate::aries::handlers::proof_presentation::prover::prover::ProverState;
use crate::aries::handlers::proof_presentation::verifier::verifier::VerifierState;

impl From<ConnectionState> for u32 {
    fn from(state: ConnectionState) -> u32 {
        match state {
            ConnectionState::Inviter(inviter_state) => {
                match inviter_state {
                    InviterState::Null => 0,
                    InviterState::Invited => 1,
                    InviterState::Requested => 2,
                    InviterState::Responded => 3,
                    InviterState::Completed => 4,
                }
            }
            ConnectionState::Invitee(invitee_state) => {
                match invitee_state {
                    InviteeState::Null => 0,
                    InviteeState::Invited => 1,
                    InviteeState::Requested => 2,
                    InviteeState::Responded => 3,
                    InviteeState::Completed => 4,
                }
            }
        }
    }
}

impl From<HolderState> for u32 {
    fn from(state: HolderState) -> u32 {
        match state {
            HolderState::OfferReceived => 0,
            HolderState::RequestSent => 1,
            HolderState::Finished => 2,
            HolderState::Failed => 3
        }
    }
}

impl From<IssuerState> for u32 {
    fn from(state: IssuerState) -> u32 {
        match state {
            IssuerState::Initial => 0,
            IssuerState::OfferSent => 1,
            IssuerState::RequestReceived => 2,
            IssuerState::CredentialSent => 3,
            IssuerState::Finished => 4,
            IssuerState::Failed => 5
        }
    }
}

impl From<ProverState> for u32 {
    fn from(state: ProverState) -> u32 {
        match state {
            ProverState::Initial => 0,
            ProverState::PresentationPrepared => 1,
            ProverState::PresentationPreparationFailed => 2,
            ProverState::PresentationSent => 3,
            ProverState::Finished => 4,
            ProverState::Failed => 5
        }
    }
}

impl From<VerifierState> for u32 {
    fn from(state: VerifierState) -> u32 {
        match state {
            VerifierState::Initial => 0,
            VerifierState::PresentationRequestSent => 1,
            VerifierState::Finished => 2,
            VerifierState::Failed => 3
        }
    }
}
