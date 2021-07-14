use indy::did;

use crate::error::prelude::*;
use crate::utils::wallet::get_wallet_handle;
use crate::utils::constants;
use crate::mocking;
use crate::indy::future::Future;

pub fn create_and_store_my_did(seed: Option<&str>, method_name: Option<&str>) -> AgencyClientResult<(String, String)> {
    trace!("create_and_store_my_did >>> seed: {:?}, method_name: {:?}", seed, method_name);
    if mocking::agency_mocks_enabled() {
        return Ok((constants::DID.to_string(), constants::VERKEY.to_string()));
    }

    let my_did_json = json!({"seed": seed, "method_name": method_name});

    did::create_and_store_my_did(get_wallet_handle(), &my_did_json.to_string())
        .wait()
        .map_err(AgencyClientError::from)
}
