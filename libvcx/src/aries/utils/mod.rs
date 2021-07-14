use crate::aries::messages::connection::did_doc::DidDoc;
use crate::aries::messages::a2a::A2AMessage;
use crate::aries::utils::encryption_envelope::EncryptionEnvelope;
use crate::error::VcxResult;

pub mod encryption_envelope;

pub fn send_message(sender_verkey: &str, did_doc: &DidDoc, message: &A2AMessage) -> VcxResult<()> {
    trace!("send_message >>> message: {:?}, did_doc: {:?}", message, &did_doc);
    let envelope = EncryptionEnvelope::create(&message, Some(sender_verkey), &did_doc)?;
    futures::executor::block_on(agency_client::httpclient::post_message(&envelope.0, &did_doc.get_endpoint()))?;
    Ok(())
}

pub fn send_message_anonymously(did_doc: &DidDoc, message: &A2AMessage) -> VcxResult<()> {
    trace!("send_message_anonymously >>> message: {:?}, did_doc: {:?}", message, &did_doc);
    let envelope = EncryptionEnvelope::create(&message, None, &did_doc)?;
    futures::executor::block_on(agency_client::httpclient::post_message(&envelope.0, &did_doc.get_endpoint()))?;
    Ok(())
}
