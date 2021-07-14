use indy::crypto;
use crate::indy::future::Future;
use crate::mocking::agency_mocks_enabled;
use crate::error::AgencyClientResult;

pub fn pack_message(sender_vk: Option<&str>, receiver_keys: &str, msg: &[u8]) -> AgencyClientResult<Vec<u8>> {
    trace!("pack_message >>> sender_vk: {:?}, receiver_keys: {}, msg: ...", sender_vk, receiver_keys);
    if agency_mocks_enabled() {
        trace!("pack_message >>> mocks enabled, returning message");
        return Ok(msg.to_vec());
    } 

    crypto::pack_message(crate::utils::wallet::get_wallet_handle(), msg, receiver_keys, sender_vk)
        .wait()
        .map_err(|err| err.into())
}

pub fn unpack_message(msg: &[u8]) -> AgencyClientResult<Vec<u8>> {
    if agency_mocks_enabled() {
        trace!("unpack_message >>> mocks enabled, returning message");
        return Ok(msg.to_vec());
    } 

    crypto::unpack_message(crate::utils::wallet::get_wallet_handle(), msg)
        .wait()
        .map_err(|err| err.into())
}
