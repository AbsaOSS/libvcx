// Holder

use connection;
use error::prelude::*;
use v3::handlers::issuance::holder::state_machine::HolderSM;
use v3::handlers::issuance::messages::CredentialIssuanceMessage;
use v3::messages::a2a::A2AMessage;
use v3::messages::issuance::credential::Credential;
use v3::messages::issuance::credential_offer::CredentialOffer;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Holder {
    holder_sm: HolderSM
}

impl Holder {
    pub fn create(credential_offer: CredentialOffer, source_id: &str) -> VcxResult<Holder> {
        trace!("Holder::holder_create_credential >>> credential_offer: {:?}, source_id: {:?}", credential_offer, source_id);

        let holder_sm = HolderSM::new(credential_offer, source_id.to_string());

        Ok(Holder { holder_sm })
    }

    pub fn send_request(&mut self, connection_handle: u32) -> VcxResult<()> {
        self.step(CredentialIssuanceMessage::CredentialRequestSend(connection_handle))
    }

    pub fn update_state(&mut self, msg: Option<String>, connection_handle: Option<u32>) -> VcxResult<()> {
        match msg {
            Some(msg) => {
                let message: A2AMessage = ::serde_json::from_str(&msg)
                    .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidOption, format!("Cannot update state: Message deserialization failed: {:?}", err)))?;

                self.step(message.into())
            }
            None => {
                self.holder_sm = self.holder_sm.clone().update_state(connection_handle)?;
                Ok(())
            }
        }
    }

    pub fn get_status(&self) -> u32 {
        self.holder_sm.state()
    }

    pub fn get_source_id(&self) -> String {
        self.holder_sm.get_source_id()
    }

    pub fn get_credential(&self) -> VcxResult<(String, Credential)> {
        self.holder_sm.get_credential()
    }

    pub fn delete_credential(&self) -> VcxResult<()> {
        self.holder_sm.delete_credential()
    }

    pub fn get_credential_status(&self) -> VcxResult<u32> {
        Ok(self.holder_sm.credential_status())
    }

    pub fn step(&mut self, message: CredentialIssuanceMessage) -> VcxResult<()> {
        self.holder_sm = self.holder_sm.clone().handle_message(message)?;
        Ok(())
    }

    pub fn get_credential_offer_message(connection_handle: u32, msg_id: &str) -> VcxResult<CredentialOffer> {
        let message = connection::get_message_by_id(connection_handle, msg_id.to_string())?;

        let credential_offer: CredentialOffer = match message {
            A2AMessage::CredentialOffer(credential_offer) => credential_offer,
            msg => {
                return Err(VcxError::from_msg(VcxErrorKind::InvalidMessages,
                                              format!("Message of different type was received: {:?}", msg)));
            }
        };

        Ok(credential_offer)
    }

    pub fn get_credential_offer_messages(conn_handle: u32) -> VcxResult<Vec<CredentialOffer>> {
        let messages = connection::get_messages(conn_handle)?;
        let msgs: Vec<CredentialOffer> = messages
            .into_iter()
            .filter_map(|(_, a2a_message)| {
                match a2a_message {
                    A2AMessage::CredentialOffer(credential_offer) => {
                        Some(credential_offer)
                    }
                    _ => None
                }
            })
            .collect();

        Ok(msgs)
    }
}
