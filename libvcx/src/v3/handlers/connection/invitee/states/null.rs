use v3::handlers::connection::invitee::states::invited::InvitedState;
use v3::messages::connection::invite::Invitation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullState {}

impl From<(NullState, Invitation)> for InvitedState {
    fn from((_state, invitation): (NullState, Invitation)) -> InvitedState {
        trace!("ConnectionInvitee: transit state from NullState to InvitedState");
        InvitedState { invitation }
    }
}
