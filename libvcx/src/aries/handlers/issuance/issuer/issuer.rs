use std::collections::HashMap;

use crate::aries::handlers::issuance::issuer::state_machine::IssuerSM;
use crate::aries::handlers::issuance::messages::CredentialIssuanceMessage;
use crate::aries::messages::a2a::A2AMessage;
use crate::aries::handlers::connection::connection::Connection;
use crate::error::prelude::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Issuer {
    issuer_sm: IssuerSM
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct IssuerConfig {
    pub cred_def_id: String,
    pub rev_reg_id: Option<String>,
    pub tails_file: Option<String>
}

#[derive(Debug, PartialEq)]
pub enum IssuerState {
    Initial,
    OfferSent,
    RequestReceived,
    CredentialSent,
    Finished,
    Failed
}

impl Issuer {
    pub fn create(issuer_config: &IssuerConfig, credential_data: &str, source_id: &str) -> VcxResult<Issuer> {
        trace!("Issuer::issuer_create_credential >>> issuer_config: {:?}, credential_data: {:?}, source_id: {:?}", issuer_config, credential_data, source_id);

        let issuer_sm = IssuerSM::new(&issuer_config.cred_def_id.to_string(), credential_data, issuer_config.rev_reg_id.clone(), issuer_config.tails_file.clone(), source_id);
        Ok(Issuer { issuer_sm })
    }

    pub fn send_credential_offer(&mut self, send_message: impl Fn(&A2AMessage) -> VcxResult<()>, comment: Option<String>) -> VcxResult<()> {
        self.step(CredentialIssuanceMessage::CredentialInit(comment), Some(&send_message))
    }

    pub fn send_credential(&mut self, send_message: impl Fn(&A2AMessage) -> VcxResult<()>) -> VcxResult<()> {
        self.step(CredentialIssuanceMessage::CredentialSend(), Some(&send_message))
    }

    pub fn get_state(&self) -> IssuerState {
        self.issuer_sm.get_state()
    }

    pub fn get_source_id(&self) -> VcxResult<String> {
        Ok(self.issuer_sm.get_source_id())
    }

    pub fn is_terminal_state(&self) -> bool {
        self.issuer_sm.is_terminal_state()
    }

    pub fn find_message_to_handle(&self, messages: HashMap<String, A2AMessage>) -> Option<(String, A2AMessage)> {
        self.issuer_sm.find_message_to_handle(messages)
    }

    pub fn revoke_credential(&self, publish: bool) -> VcxResult<()> {
        self.issuer_sm.revoke(publish)
    }

    pub fn get_rev_reg_id(&self) -> VcxResult<String> {
        self.issuer_sm.get_rev_reg_id()
    }

    pub fn is_revokable(&self) -> VcxResult<bool> {
        self.issuer_sm.is_revokable()
    }

    pub fn get_credential_status(&self) -> VcxResult<u32> {
        Ok(self.issuer_sm.credential_status())
    }

    pub fn step(&mut self, message: CredentialIssuanceMessage, send_message: Option<&impl Fn(&A2AMessage) -> VcxResult<()>>) -> VcxResult<()> {
        self.issuer_sm = self.issuer_sm.clone().handle_message(message, send_message)?;
        Ok(())
    }

    pub fn update_state(&mut self, connection: &Connection) -> VcxResult<IssuerState> {
        trace!("Issuer::update_state >>>");
        if self.is_terminal_state() { return Ok(self.get_state()); }
        let send_message = connection.send_message_closure()?;

        let messages = connection.get_messages()?;
        if let Some((uid, msg)) = self.find_message_to_handle(messages) {
            self.step(msg.into(), Some(&send_message))?;
            connection.update_message_status(uid)?;
        }
        Ok(self.get_state())
    }
}
