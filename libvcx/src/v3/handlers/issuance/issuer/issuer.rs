use error::prelude::*;
use v3::handlers::issuance::issuer::state_machine::IssuerSM;
use v3::handlers::issuance::messages::CredentialIssuanceMessage;
use v3::messages::a2a::A2AMessage;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Issuer {
    issuer_sm: IssuerSM
}

impl Issuer {
    pub fn create(cred_def_handle: u32, credential_data: &str, source_id: &str) -> VcxResult<Issuer> {
        trace!("Issuer::issuer_create_credential >>> cred_def_handle: {:?}, credential_data: {:?}, source_id: {:?}", cred_def_handle, credential_data, source_id);

        let cred_def_id = ::credential_def::get_cred_def_id(cred_def_handle)?;
        let rev_reg_id = ::credential_def::get_rev_reg_id(cred_def_handle)?;
        let tails_file = ::credential_def::get_tails_file(cred_def_handle)?;
        let issuer_sm = IssuerSM::new(&cred_def_id, credential_data, rev_reg_id, tails_file, source_id);
        Ok(Issuer { issuer_sm })
    }

    pub fn send_credential_offer(&mut self, connection_handle: u32) -> VcxResult<()> {
        self.step(CredentialIssuanceMessage::CredentialInit(connection_handle))
    }

    pub fn send_credential(&mut self, connection_handle: u32) -> VcxResult<()> {
        self.step(CredentialIssuanceMessage::CredentialSend(connection_handle))
    }

    pub fn get_state(&self) -> VcxResult<u32> {
        Ok(self.issuer_sm.state())
    }

    pub fn get_source_id(&self) -> VcxResult<String> {
        Ok(self.issuer_sm.get_source_id())
    }

    pub fn revoke_credential(&self, publish: bool) -> VcxResult<()> {
        self.issuer_sm.revoke(publish)
    }

    pub fn update_status(&mut self, msg: Option<String>, connection_handle: Option<u32>) -> VcxResult<()> {
        match msg {
            Some(msg) => {
                let message: A2AMessage = ::serde_json::from_str(&msg)
                    .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidOption, format!("Cannot deserialize Message: {:?}", err)))?;

                self.step(message.into())
            }
            None => {
                self.issuer_sm = self.issuer_sm.clone().update_state(connection_handle)?;
                Ok(())
            }
        }
    }

    pub fn get_credential_status(&self) -> VcxResult<u32> {
        Ok(self.issuer_sm.credential_status())
    }

    pub fn step(&mut self, message: CredentialIssuanceMessage) -> VcxResult<()> {
        self.issuer_sm = self.issuer_sm.clone().handle_message(message)?;
        Ok(())
    }
}
