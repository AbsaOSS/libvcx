use crate::error::prelude::*;
use crate::aries::handlers::proof_presentation::verifier::messages::VerifierMessages;
use crate::aries::handlers::proof_presentation::verifier::state_machine::VerifierSM;
use crate::aries::handlers::connection::connection::Connection;
use crate::aries::messages::a2a::A2AMessage;
use crate::aries::messages::proof_presentation::presentation_request::*;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Verifier {
    verifier_sm: VerifierSM
}

#[derive(Debug, PartialEq)]
pub enum VerifierState {
    Initial,
    PresentationRequestSent,
    Finished,
    Failed
}

impl Verifier {
    pub fn create(source_id: String,
                  requested_attrs: String,
                  requested_predicates: String,
                  revocation_details: String,
                  name: String) -> VcxResult<Verifier> {
        trace!("Verifier::create >>> source_id: {:?}, requested_attrs: {:?}, requested_predicates: {:?}, revocation_details: {:?}, name: {:?}",
               source_id, requested_attrs, requested_predicates, revocation_details, name);

        let presentation_request =
            PresentationRequestData::create()
                .set_name(name)
                .set_requested_attributes(requested_attrs)?
                .set_requested_predicates(requested_predicates)?
                .set_not_revoked_interval(revocation_details)?
                .set_nonce()?;

        Ok(Verifier {
            verifier_sm: VerifierSM::new(presentation_request, source_id),
        })
    }

    pub fn get_source_id(&self) -> String { self.verifier_sm.source_id() }

    pub fn get_state(&self) -> VerifierState {
        trace!("Verifier::get_state >>>");
        self.verifier_sm.get_state()
    }

    pub fn presentation_status(&self) -> u32 {
        trace!("Verifier::presentation_state >>>");
        self.verifier_sm.presentation_status()
    }

    pub fn handle_message(&mut self, message: VerifierMessages, send_message: Option<&impl Fn(&A2AMessage) -> VcxResult<()>>) -> VcxResult<()> {
        trace!("Verifier::handle_message >>> message: {:?}", message);
        self.step(message, send_message)
    }

    pub fn send_presentation_request(&mut self, send_message: impl Fn(&A2AMessage) -> VcxResult<()>, comment: Option<String>) -> VcxResult<()> {
        trace!("Verifier::send_presentation_request >>>");
        self.step(VerifierMessages::SendPresentationRequest(comment), Some(&send_message))
    }

    pub fn generate_presentation_request_msg(&self) -> VcxResult<String> {
        trace!("Verifier::generate_presentation_request_msg >>>");

        let proof_request = self.verifier_sm.presentation_request()?;

        Ok(json!(proof_request).to_string())
    }

    pub fn get_presentation(&self) -> VcxResult<String> {
        trace!("Verifier::get_presentation >>>");

        let proof = self.verifier_sm.presentation()?.to_a2a_message();
        Ok(json!(proof).to_string())
    }

    pub fn step(&mut self, message: VerifierMessages, send_message: Option<&impl Fn(&A2AMessage) -> VcxResult<()>>)
        -> VcxResult<()> 
    {
        self.verifier_sm = self.verifier_sm.clone().step(message, send_message)?;
        Ok(())
    }

    pub fn has_transitions(&self) -> bool {
        self.verifier_sm.has_transitions()
    }

    pub fn find_message_to_handle(&self, messages: HashMap<String, A2AMessage>) -> Option<(String, A2AMessage)> {
        self.verifier_sm.find_message_to_handle(messages)
    }

    pub fn update_state(&mut self, connection: &Connection) -> VcxResult<VerifierState> {
        trace!("Verifier::update_state >>> ");
        if !self.has_transitions() { return Ok(self.get_state()); }
        let send_message = connection.send_message_closure()?;

        let messages = connection.get_messages()?;
        if let Some((uid, msg)) = self.find_message_to_handle(messages) {
            self.step(msg.into(), Some(&send_message))?;
            connection.update_message_status(uid)?;
        }
        Ok(self.get_state())
    }
}
