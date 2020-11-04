use futures::Future;
use indy::did;

use error::prelude::*;
use settings;
use libindy::utils::wallet::get_wallet_handle;

pub fn create_and_store_my_did(seed: Option<&str>, method_name: Option<&str>) -> VcxResult<(String, String)> {
    if settings::indy_mocks_enabled() {
        return Ok((::utils::constants::DID.to_string(), ::utils::constants::VERKEY.to_string()));
    }

    let my_did_json = json!({"seed": seed, "method_name": method_name});

    did::create_and_store_my_did(get_wallet_handle(), &my_did_json.to_string())
        .wait()
        .map_err(VcxError::from)
}

pub fn get_local_verkey(did: &str) -> VcxResult<String> {
    if settings::indy_mocks_enabled() {
        return Ok(::utils::constants::VERKEY.to_string());
    }

    did::key_for_local_did(get_wallet_handle(), did)
        .wait()
        .map_err(VcxError::from)
}
