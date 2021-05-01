use serde::Deserialize;

use indy::WalletHandle;
use agency_client::agent_utils;

use crate::error::prelude::*;
use crate::libindy::utils::{anoncreds, signus, wallet};
use crate::settings;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    agency_url: String,
    pub agency_did: String,
    agency_verkey: String,
    wallet_name: Option<String>,
    wallet_key: String,
    wallet_type: Option<String>,
    agent_seed: Option<String>,
    enterprise_seed: Option<String>,
    wallet_key_derivation: Option<String>,
    name: Option<String>,
    path: Option<String>,
    storage_config: Option<String>,
    storage_credentials: Option<String>,
    pool_config: Option<String>,
    did_method: Option<String>,
    webhook_url: Option<String>,
    use_latest_protocols: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AgencyConfig {
    agency_did: String,
    agency_verkey: String,
    agency_endpoint: String,
    agent_seed: Option<String>
}

pub fn parse_config(config: &str) -> VcxResult<Config> {
    let my_config: Config = ::serde_json::from_str(&config)
        .map_err(|err|
            VcxError::from_msg(
                VcxErrorKind::InvalidConfiguration,
                format!("Cannot parse config: {}", err),
            )
        )?;
    Ok(my_config)
}

pub fn get_or_default(config: &Option<String>, default: &str) -> String {
    config.to_owned().unwrap_or(default.to_string())
}

pub fn set_config_values(my_config: &Config) {
    let wallet_name = get_or_default(&my_config.wallet_name, settings::DEFAULT_WALLET_NAME);

    settings::set_config_value(settings::CONFIG_WALLET_NAME, &wallet_name);
    settings::set_config_value(settings::CONFIG_WALLET_KEY, &my_config.wallet_key);
    settings::get_agency_client_mut().unwrap().set_agency_url(&my_config.agency_url);
    settings::get_agency_client_mut().unwrap().set_agency_did(&my_config.agency_did);
    settings::get_agency_client_mut().unwrap().set_agency_vk(&my_config.agency_verkey);
    settings::get_agency_client_mut().unwrap().set_agent_vk(&my_config.agency_verkey);

    settings::set_opt_config_value(settings::CONFIG_WALLET_KEY_DERIVATION, &my_config.wallet_key_derivation);
    settings::set_opt_config_value(settings::CONFIG_WALLET_TYPE, &my_config.wallet_type);
    settings::set_opt_config_value(settings::CONFIG_WALLET_STORAGE_CONFIG, &my_config.storage_config);
    settings::set_opt_config_value(settings::CONFIG_WALLET_STORAGE_CREDS, &my_config.storage_credentials);
    settings::set_opt_config_value(settings::CONFIG_POOL_CONFIG, &my_config.pool_config);
    settings::set_opt_config_value(settings::CONFIG_DID_METHOD, &my_config.did_method);
    settings::set_opt_config_value(settings::CONFIG_WEBHOOK_URL, &my_config.webhook_url);
}

pub fn configure_wallet(my_config: &Config) -> VcxResult<(String, String, String, WalletHandle)> {
    let wallet_name = get_or_default(&my_config.wallet_name, settings::DEFAULT_WALLET_NAME);

    let wh = wallet::create_and_open_as_main_wallet(
        &wallet_name,
        &my_config.wallet_key,
        &my_config.wallet_key_derivation.as_deref().unwrap_or(settings::WALLET_KDF_DEFAULT.into()),
        my_config.wallet_type.as_ref().map(String::as_str),
        my_config.storage_config.as_ref().map(String::as_str),
        my_config.storage_credentials.as_ref().map(String::as_str),
    )?;
    wallet::set_wallet_handle(wh);
    trace!("initialized wallet");

    // If MS is already in wallet then just continue
    anoncreds::libindy_prover_create_master_secret(settings::DEFAULT_LINK_SECRET_ALIAS).ok();

    let (my_did, my_vk) = signus::create_and_store_my_did(
        my_config.agent_seed.as_ref().map(String::as_str),
        my_config.did_method.as_ref().map(String::as_str),
    )?;

    settings::set_config_value(settings::CONFIG_INSTITUTION_DID, &my_did);
    settings::get_agency_client_mut()?.set_my_vk(&my_vk);

    Ok((my_did, my_vk, wallet_name, wh))
}

fn _create_issuer_keys(my_did: &str, my_vk: &str, my_config: &Config) -> VcxResult<(String, String)> {
    if my_config.enterprise_seed == my_config.agent_seed {
        Ok((my_did.to_string(), my_vk.to_string()))
    } else {
        signus::create_and_store_my_did(
            my_config.enterprise_seed.as_ref().map(String::as_str),
            my_config.did_method.as_ref().map(String::as_str),
        )
    }
}

pub fn get_final_config(my_did: &str,
                        my_vk: &str,
                        agent_did: &str,
                        agent_vk: &str,
                        wallet_name: &str,
                        my_config: &Config) -> VcxResult<String> {
    let (issuer_did, issuer_vk) = _create_issuer_keys(my_did, my_vk, my_config)?;

    let mut final_config = json!({
        "wallet_key": &my_config.wallet_key,
        "wallet_name": wallet_name,
        "agency_endpoint": &my_config.agency_url,
        "agency_did": &my_config.agency_did,
        "agency_verkey": &my_config.agency_verkey,
        "sdk_to_remote_did": my_did,
        "sdk_to_remote_verkey": my_vk,
        "institution_did": issuer_did,
        "institution_verkey": issuer_vk,
        "remote_to_sdk_did": agent_did,
        "remote_to_sdk_verkey": agent_vk,
        "institution_name": get_or_default(&my_config.name, "<CHANGE_ME>"),
        "genesis_path": get_or_default(&my_config.path, "<CHANGE_ME>")
    });

    if let Some(key_derivation) = &my_config.wallet_key_derivation {
        final_config["wallet_key_derivation"] = json!(key_derivation);
    }
    if let Some(wallet_type) = &my_config.wallet_type {
        final_config["wallet_type"] = json!(wallet_type);
    }
    if let Some(_storage_config) = &my_config.storage_config {
        final_config["storage_config"] = json!(_storage_config);
    }
    if let Some(_storage_credentials) = &my_config.storage_credentials {
        final_config["storage_credentials"] = json!(_storage_credentials);
    }
    if let Some(_pool_config) = &my_config.pool_config {
        final_config["pool_config"] = json!(_pool_config);
    }
    if let Some(_webhook_url) = &my_config.webhook_url {
        final_config["webhook_url"] = json!(_webhook_url);
    }
    if let Some(_use_latest_protocols) = &my_config.use_latest_protocols {
        final_config["use_latest_protocols"] = json!(_use_latest_protocols);
    }

    Ok(final_config.to_string())
}

pub fn connect_register_provision(config: &str) -> VcxResult<String> {
    debug!("connect_register_provision >>> config: {:?}", config);
    let my_config = parse_config(config)?;

    trace!("***Configuring Library");
    set_config_values(&my_config);

    trace!("***Configuring Wallet");
    let (my_did, my_vk, wallet_name, _) = configure_wallet(&my_config)?;

    debug!("connect_register_provision:: Final settings: {:?}", settings::settings_as_string());

    trace!("Connecting to Agency");
    let (agent_did, agent_vk) = agent_utils::onboarding(&my_did, &my_vk, &my_config.agency_did)?;

    let config = get_final_config(&my_did, &my_vk, &agent_did, &agent_vk, &wallet_name, &my_config)?;

    wallet::close_main_wallet()?;

    Ok(config)
}

pub fn provision_cloud_agent(agency_config: &str) -> VcxResult<String> {
    let agency_config: AgencyConfig = serde_json::from_str(agency_config)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson,
                                          format!("Failed to serialize agency config: {:?}, err: {:?}", agency_config,  err)))?;

    let (my_did, my_vk) = signus::create_and_store_my_did(agency_config.agent_seed.as_ref().map(String::as_str), None)?;

    settings::get_agency_client_mut().unwrap().set_agency_did(&agency_config.agency_did);
    settings::get_agency_client_mut().unwrap().set_agency_vk(&agency_config.agency_verkey);
    settings::get_agency_client_mut().unwrap().set_agency_url(&agency_config.agency_endpoint);
    settings::get_agency_client_mut().unwrap().set_my_vk(&my_vk);
    settings::get_agency_client_mut().unwrap().set_my_pwdid(&my_did);
    settings::get_agency_client_mut().unwrap().set_agent_vk(&agency_config.agency_verkey); // This is reset when connection is established and agent did needs not be set before onboarding

    let (agent_did, agent_vk) = agent_utils::onboarding(&my_did, &my_vk, &agency_config.agency_did)?;

    let agency_config = json!({
        "agency_did": agency_config.agency_did,
        "agency_endpoint": agency_config.agency_endpoint,
        "agency_verkey": agency_config.agency_verkey,
        "remote_to_sdk_did": agent_did,
        "remote_to_sdk_verkey": agent_vk,
        "sdk_to_remote_did": my_did,
        "sdk_to_remote_verkey": my_vk,
    });

    Ok(agency_config.to_string())
}

#[cfg(test)]
mod tests {
    use std::env;

    use crate::api::vcx::vcx_shutdown;
    use crate::utils::devsetup::*;
    use crate::libindy::utils::wallet::{create_wallet_from_config, open_wallet_directly};

    use super::*;

    #[test]
    #[cfg(feature = "agency_v2")]
    fn test_connect_register_provision_config_path() {
        let _setup = SetupEmpty::init();
        let agency_did = "VsKV7grR1BUE29mG2Fm2kX";
        let agency_vk = "Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR";
        let host = "http://localhost:8080";
        let wallet_key = "test_key";

        let path = if cfg!(target_os = "android") {
            env::var("EXTERNAL_STORAGE").unwrap() + "/tmp/custom1/"
        } else {
            "/tmp/custom1/".to_owned()
        };

        let wallet_config = json!({
            "wallet_name": "test_wallet",
            "wallet_key": wallet_key.to_string(),
            "wallet_key_derivation": settings::WALLET_KDF_ARGON2I_INT,
            "storage_config": json!({
                "path": path
            }).to_string(),
        }).to_string();

        let agency_config = json!({
            "agency_endpoint": host.to_string(),
            "agency_did": agency_did.to_string(),
            "agency_verkey": agency_vk.to_string(),
        }).to_string();

        create_wallet_from_config(&wallet_config).unwrap();
        let wallet_handle = open_wallet_directly(&wallet_config).unwrap();
        let agency_config = provision_cloud_agent(&agency_config).unwrap();

        let config = combine_configs(&wallet_config, &agency_config, None, wallet_handle, None);

        //Creates wallet at custom location
        assert!(std::path::Path::new(&(path + "test_wallet")).exists());
        vcx_shutdown(false);

        settings::process_config_string(&config, false).unwrap();
    }

    // TODO: Setup mocks
    #[test]
    #[ignore]
    #[cfg(feature = "general_test")]
    fn test_connect_register_provision() {
        let _setup = SetupEmpty::init();

        let agency_did = "Ab8TvZa3Q19VNkQVzAWVL7";
        let agency_vk = "5LXaR43B1aQyeh94VBP8LG1Sgvjk7aNfqiksBCSjwqbf";
        // let host = "http://www.whocares.org";
        let host = "http://localhost:8080";
        let wallet_key = "test_key";

        let wallet_config = json!({
            "wallet_name": "test_wallet",
            "wallet_key": wallet_key.to_string(),
            "wallet_key_derivation": settings::WALLET_KDF_ARGON2I_INT,
        }).to_string();

        let agency_config = json!({
            "agency_endpoint": host.to_string(),
            "agency_did": agency_did.to_string(),
            "agency_verkey": agency_vk.to_string(),
        }).to_string();

        create_wallet_from_config(&wallet_config).unwrap();
        let wallet_handle = open_wallet_directly(&wallet_config).unwrap();
        let agency_config = provision_cloud_agent(&agency_config).unwrap();

        let config = combine_configs(&wallet_config, &agency_config, None, wallet_handle, None);

        let expected = json!({
            "agency_did":"Ab8TvZa3Q19VNkQVzAWVL7",
            "agency_endpoint":"http://www.whocares.org",
            "agency_verkey":"5LXaR43B1aQyeh94VBP8LG1Sgvjk7aNfqiksBCSjwqbf",
            "genesis_path":"<CHANGE_ME>",
            "institution_did":"FhrSrYtQcw3p9xwf7NYemf",
            "institution_name":"<CHANGE_ME>",
            "institution_verkey":"91qMFrZjXDoi2Vc8Mm14Ys112tEZdDegBZZoembFEATE",
            "remote_to_sdk_did":"DnEpUQJLupa5rKPkrKUpFd", // taken from mock constants::CONNECTED_RESPONSE_DECRYPTED
            "remote_to_sdk_verkey":"7y118tRW2EMJn18qs9MY5NJWYW2PLwV5QpaLyfoLHtgF", // taken from mock constants::CONNECTED_RESPONSE_DECRYPTED
            "sdk_to_remote_did":"FhrSrYtQcw3p9xwf7NYemf",
            "sdk_to_remote_verkey":"91qMFrZjXDoi2Vc8Mm14Ys112tEZdDegBZZoembFEATE",
            "wallet_key":"test_key",
            "wallet_name":"LIBVCX_SDK_WALLET"
        });

        assert_eq!(expected, ::serde_json::from_str::<serde_json::Value>(&config).unwrap());
    }

    // TODO: Setup mocks
    #[ignore]
    #[test]
    #[cfg(feature = "general_test")]
    fn test_real_connect_register_provision() {
        let _setup = SetupDefaults::init();

        let agency_did = "VsKV7grR1BUE29mG2Fm2kX";
        let agency_vk = "Hezce2UWMZ3wUhVkh2LfKSs8nDzWwzs2Win7EzNN3YaR";
        let host = "http://localhost:8080";
        let wallet_key = "test_key";
        let config = json!({
            "agency_url": host.to_string(),
            "agency_did": agency_did.to_string(),
            "agency_verkey": agency_vk.to_string(),
            "wallet_key": wallet_key.to_string(),
        });

        let result = connect_register_provision(&config.to_string()).unwrap();
        assert!(result.len() > 0);
    }
}
