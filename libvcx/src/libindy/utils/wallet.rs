use indy::{ErrorCode, wallet};
use indy::{INVALID_WALLET_HANDLE, SearchHandle, WalletHandle};
use indy::future::Future;

use crate::error::prelude::*;
use crate::init::open_as_main_wallet;
use crate::libindy::utils::{anoncreds, signus};
use crate::settings;
use crate::settings::Actors::Issuer;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub wallet_name: String,
    pub wallet_key: String,
    pub wallet_key_derivation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_credentials: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekey_derivation_method: Option<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerConfig {
    pub institution_did: String,
    pub institution_verkey: String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletCredentials {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rekey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_credentials: Option<serde_json::Value>,
    key_derivation_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rekey_derivation_method: Option<String>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletRecord {
    id: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    pub value: Option<String>,
    tags: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RestoreWalletConfigs {
    pub wallet_name: String,
    pub wallet_key: String,
    pub exported_wallet_path: String,
    pub backup_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_key_derivation: Option<String>, // todo: i renamed this, consolide stuff, orignal name was key_derivation
}

impl RestoreWalletConfigs {
    pub fn from_str(data: &str) -> VcxResult<RestoreWalletConfigs> {
        serde_json::from_str(data)
            .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize RestoreWalletConfigs: {:?}", err)))
    }
}

pub static mut WALLET_HANDLE: WalletHandle = INVALID_WALLET_HANDLE;

pub fn set_wallet_handle(handle: WalletHandle) -> WalletHandle {
    trace!("set_wallet_handle >>> handle: {:?}", handle);
    unsafe { WALLET_HANDLE = handle; }
    settings::get_agency_client_mut().unwrap().set_wallet_handle(handle.0);
    unsafe { WALLET_HANDLE }
}

pub fn get_wallet_handle() -> WalletHandle { unsafe { WALLET_HANDLE } }

pub fn reset_wallet_handle() -> VcxResult<()> {
    set_wallet_handle(INVALID_WALLET_HANDLE);
    settings::get_agency_client_mut()?.reset_wallet_handle();
    Ok(())
}

pub fn create_wallet(config: &WalletConfig) -> VcxResult<()> {
    let wh = create_and_open_as_main_wallet(&config)?;
    trace!("Created wallet with handle {:?}", wh);

    // If MS is already in wallet then just continue
    anoncreds::libindy_prover_create_master_secret(settings::DEFAULT_LINK_SECRET_ALIAS).ok();
    
    close_main_wallet()?;
    Ok(())
}

pub fn configure_issuer_wallet(enterprise_seed: &str) -> VcxResult<IssuerConfig> {
    let (institution_did, institution_verkey) = signus::create_and_store_my_did(Some(enterprise_seed), None)?;
    Ok(IssuerConfig {
        institution_did,
        institution_verkey
    })
}

pub fn build_wallet_config(wallet_name: &str, wallet_type: Option<&str>, storage_config: Option<&str>) -> String {
    let mut config = json!({
        "id": wallet_name,
        "storage_type": wallet_type
    });
    if let Some(_config) = storage_config { config["storage_config"] = serde_json::from_str(_config).unwrap(); }
    config.to_string()
}


pub fn build_wallet_credentials(key: &str, storage_credentials: Option<&str>, key_derivation_method: &str, rekey: Option<&str>, rekey_derivation_method: Option<&str>) -> VcxResult<String> {
    serde_json::to_string(&WalletCredentials {
        key: key.into(),
        rekey: rekey.map(|s| s.into()),
        storage_credentials: storage_credentials.map(|val| serde_json::from_str(val).unwrap()),
        key_derivation_method: key_derivation_method.into(),
        rekey_derivation_method: rekey_derivation_method.map(|s| s.into())
    }).map_err(|err| VcxError::from_msg(VcxErrorKind::SerializationError, format!("Failed to serialize WalletCredentials, err: {:?}", err)))
}

pub fn create_indy_wallet(wallet_config: &WalletConfig) -> VcxResult<()> {
    trace!("create_wallet >>> {}", &wallet_config.wallet_name);
    let config = build_wallet_config(
        &wallet_config.wallet_name,
        wallet_config.wallet_type.as_deref(),
        wallet_config.storage_config.as_deref());
    let credentials = build_wallet_credentials(
        &wallet_config.wallet_key,
        wallet_config.storage_credentials.as_deref(),
        &wallet_config.wallet_key_derivation,
        None,
        None
    )?;

    trace!("Credentials: {:?}", credentials);

    match wallet::create_wallet(&config, &credentials)
        .wait() {
        Ok(()) => Ok(()),
        Err(err) => {
            match err.error_code.clone() {
                ErrorCode::WalletAlreadyExistsError => {
                    warn!("wallet \"{}\" already exists. skipping creation", wallet_config.wallet_name);
                    Ok(())
                }
                _ => {
                    warn!("could not create wallet {}: {:?}", wallet_config.wallet_name, err.message);
                    Err(VcxError::from_msg(VcxErrorKind::WalletCreate, format!("could not create wallet {}: {:?}", wallet_config.wallet_name, err.message)))
                }
            }
        }
    }
}

pub fn create_and_open_as_main_wallet(wallet_config: &WalletConfig) -> VcxResult<WalletHandle> {
    if settings::indy_mocks_enabled() {
        warn!("open_as_main_wallet ::: Indy mocks enabled, skipping opening main wallet.");
        return Ok(set_wallet_handle(WalletHandle(1)));
    }

    create_indy_wallet(&wallet_config)?;
    open_as_main_wallet(&wallet_config)
}

pub fn close_main_wallet() -> VcxResult<()> {
    trace!("close_main_wallet >>>");
    if settings::indy_mocks_enabled() {
        warn!("close_main_wallet >>> Indy mocks enabled, skipping closing wallet");
        set_wallet_handle(INVALID_WALLET_HANDLE);
        return Ok(());
    }

    wallet::close_wallet(get_wallet_handle())
        .wait()?;

    reset_wallet_handle()?;
    Ok(())
}

pub fn delete_wallet(wallet_config: &WalletConfig) -> VcxResult<()> {
    trace!("delete_wallet >>> wallet_name: {}", &wallet_config.wallet_name);

    let config = build_wallet_config(&wallet_config.wallet_name, wallet_config.wallet_type.as_ref().map(String::as_str), wallet_config.storage_config.as_deref());
    let credentials = build_wallet_credentials(&wallet_config.wallet_key, wallet_config.storage_credentials.as_deref(), &wallet_config.wallet_key_derivation, None, None)?;

    wallet::delete_wallet(&config, &credentials)
        .wait()
        .map_err(|err|
            match err.error_code.clone() {
                ErrorCode::WalletAccessFailed => {
                    err.to_vcx(VcxErrorKind::WalletAccessFailed,
                               format!("Can not open wallet \"{}\". Invalid key has been provided.", &wallet_config.wallet_name))
                }
                ErrorCode::WalletNotFoundError => {
                    err.to_vcx(VcxErrorKind::WalletNotFound,
                               format!("Wallet \"{}\" not found or unavailable", &wallet_config.wallet_name))
                }
                error_code => {
                    err.to_vcx(VcxErrorKind::LibndyError(error_code as u32), "Indy error occurred")
                }
            })?;

    Ok(())
}

pub fn add_record(xtype: &str, id: &str, value: &str, tags: Option<&str>) -> VcxResult<()> {
    trace!("add_record >>> xtype: {}, id: {}, value: {}, tags: {:?}", secret!(&xtype), secret!(&id), secret!(&value), secret!(&tags));

    if settings::indy_mocks_enabled() { return Ok(()); }

    wallet::add_wallet_record(get_wallet_handle(), xtype, id, value, tags)
        .wait()
        .map_err(VcxError::from)
}

pub fn get_record(xtype: &str, id: &str, options: &str) -> VcxResult<String> {
    trace!("get_record >>> xtype: {}, id: {}, options: {}", secret!(&xtype), secret!(&id), options);

    if settings::indy_mocks_enabled() {
        return Ok(r#"{"id":"123","type":"record type","value":"record value","tags":null}"#.to_string());
    }

    wallet::get_wallet_record(get_wallet_handle(), xtype, id, options)
        .wait()
        .map_err(VcxError::from)
}

pub fn delete_record(xtype: &str, id: &str) -> VcxResult<()> {
    trace!("delete_record >>> xtype: {}, id: {}", secret!(&xtype), secret!(&id));

    if settings::indy_mocks_enabled() { return Ok(()); }

    wallet::delete_wallet_record(get_wallet_handle(), xtype, id)
        .wait()
        .map_err(VcxError::from)
}


pub fn update_record_value(xtype: &str, id: &str, value: &str) -> VcxResult<()> {
    trace!("update_record_value >>> xtype: {}, id: {}, value: {}", secret!(&xtype), secret!(&id), secret!(&value));

    if settings::indy_mocks_enabled() { return Ok(()); }

    wallet::update_wallet_record_value(get_wallet_handle(), xtype, id, value)
        .wait()
        .map_err(VcxError::from)
}

pub fn add_record_tags(xtype: &str, id: &str, tags: &str) -> VcxResult<()> {
    trace!("add_record_tags >>> xtype: {}, id: {}, tags: {:?}", secret!(&xtype), secret!(&id), secret!(&tags));

    if settings::indy_mocks_enabled() {
        return Ok(());
    }

    wallet::add_wallet_record_tags(get_wallet_handle(), xtype, id, tags)
        .wait()
        .map_err(VcxError::from)
}

pub fn update_record_tags(xtype: &str, id: &str, tags: &str) -> VcxResult<()> {
    trace!("update_record_tags >>> xtype: {}, id: {}, tags: {}", secret!(&xtype), secret!(&id), secret!(&tags));

    if settings::indy_mocks_enabled() {
        return Ok(());
    }

    wallet::update_wallet_record_tags(get_wallet_handle(), xtype, id, tags)
        .wait()
        .map_err(VcxError::from)
}

pub fn delete_record_tags(xtype: &str, id: &str, tag_names: &str) -> VcxResult<()> {
    trace!("delete_record_tags >>> xtype: {}, id: {}, tag_names: {}", secret!(&xtype), secret!(&id), secret!(&tag_names));

    if settings::indy_mocks_enabled() {
        return Ok(());
    }

    wallet::delete_wallet_record_tags(get_wallet_handle(), xtype, id, tag_names)
        .wait()
        .map_err(VcxError::from)
}

pub fn open_search(xtype: &str, query: &str, options: &str) -> VcxResult<SearchHandle> {
    trace!("open_search >>> xtype: {}, query: {}, options: {}", secret!(&xtype), query, options);

    if settings::indy_mocks_enabled() {
        return Ok(1);
    }

    wallet::open_wallet_search(get_wallet_handle(), xtype, query, options)
        .wait()
        .map_err(VcxError::from)
}

pub fn fetch_next_records(search_handle: SearchHandle, count: usize) -> VcxResult<String> {
    trace!("fetch_next_records >>> search_handle: {}, count: {}", search_handle, count);

    if settings::indy_mocks_enabled() {
        return Ok(String::from("{}"));
    }

    wallet::fetch_wallet_search_next_records(get_wallet_handle(), search_handle, count)
        .wait()
        .map_err(VcxError::from)
}

pub fn close_search(search_handle: SearchHandle) -> VcxResult<()> {
    trace!("close_search >>> search_handle: {}", search_handle);

    if settings::indy_mocks_enabled() {
        return Ok(());
    }

    wallet::close_wallet_search(search_handle)
        .wait()
        .map_err(VcxError::from)
}

pub fn export_main_wallet(path: &str, backup_key: &str) -> VcxResult<()> {
    let wallet_handle = get_wallet_handle();
    trace!("export >>> wallet_handle: {:?}, path: {:?}, backup_key: ****", wallet_handle, path);

    let export_config = json!({ "key": backup_key, "path": &path}).to_string();
    wallet::export_wallet(wallet_handle, &export_config)
        .wait()
        .map_err(VcxError::from)
}

pub fn import(restore_config: &RestoreWalletConfigs) -> VcxResult<()> {
    trace!("import >>> wallet: {} exported_wallet_path: {}", restore_config.wallet_name, restore_config.exported_wallet_path);
    let new_wallet_name = restore_config.wallet_name.clone();
    let new_wallet_key = restore_config.wallet_key.clone();
    let new_wallet_kdf = restore_config.wallet_key_derivation.clone().unwrap_or(settings::WALLET_KDF_DEFAULT.into());

    let new_wallet_config = build_wallet_config(&new_wallet_name, None, None);
    let new_wallet_credentials = build_wallet_credentials(&new_wallet_key, None, &new_wallet_kdf, None, None)?;
    let import_config = json!({
        "key": restore_config.backup_key,
        "path": restore_config.exported_wallet_path
    }).to_string();

    wallet::import_wallet(&new_wallet_config, &new_wallet_credentials, &import_config)
        .wait()
        .map_err(VcxError::from)
}

#[cfg(test)]
pub mod tests {
    use agency_client::agency_settings;

    use crate::libindy::utils::signus::create_and_store_my_did;
    use crate::utils::devsetup::{SetupDefaults, SetupLibraryWallet, TempFile};
    use crate::utils::get_temp_dir_path;

    use super::*;

    fn _record() -> (&'static str, &'static str, &'static str) {
        ("type1", "id1", "value1")
    }

    pub fn create_main_wallet_and_its_backup() -> (TempFile, String, WalletConfig) {
        let wallet_name = &format!("export_test_wallet_{}", uuid::Uuid::new_v4());

        let export_file = TempFile::prepare_path(wallet_name);

        let wallet_config = WalletConfig {
            wallet_name: wallet_name.into(),
            wallet_key: settings::DEFAULT_WALLET_KEY.into(),
            wallet_key_derivation: settings::WALLET_KDF_RAW.into(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None,
            rekey: None,
            rekey_derivation_method: None
        };
        let _handle = create_and_open_as_main_wallet(&wallet_config).unwrap();

        let (my_did, my_vk) = create_and_store_my_did(None, None).unwrap();

        settings::set_config_value(settings::CONFIG_INSTITUTION_DID, &my_did);
        settings::get_agency_client_mut().unwrap().set_my_vk(&my_vk);

        let backup_key = settings::get_config_value(settings::CONFIG_WALLET_BACKUP_KEY).unwrap();

        let (type_, id, value) = _record();
        add_record(type_, id, value, None).unwrap();

        export_main_wallet(&export_file.path, &backup_key).unwrap();

        close_main_wallet().unwrap();

        (export_file, wallet_name.to_string(), wallet_config)
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_wallet() {
        let _setup = SetupLibraryWallet::init();

        assert_ne!(get_wallet_handle(), INVALID_WALLET_HANDLE);
        let wallet_config = WalletConfig {
            wallet_name: "".into(),
            wallet_key: settings::DEFAULT_WALLET_KEY.into(),
            wallet_key_derivation: settings::WALLET_KDF_RAW.into(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None,
            rekey: None,
            rekey_derivation_method: None
        };
        assert_eq!(VcxErrorKind::WalletCreate, create_and_open_as_main_wallet(&wallet_config).unwrap_err().kind());
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_wallet_calls_fail_with_different_key_derivation() {
        let _setup = SetupDefaults::init();

        settings::set_testing_defaults();
        let wallet_name = &format!("test_wrong_kdf_{}", uuid::Uuid::new_v4());
        let wallet_key = settings::DEFAULT_WALLET_NAME;
        let wallet_kdf = settings::WALLET_KDF_ARGON2I_INT;
        let wallet_wrong_kdf = settings::WALLET_KDF_RAW;

        let wallet_config = WalletConfig {
            wallet_name: wallet_name.into(),
            wallet_key: wallet_key.into(),
            wallet_key_derivation: settings::WALLET_KDF_ARGON2I_MOD.into(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None, rekey: None, rekey_derivation_method: None
        };

        create_indy_wallet(&wallet_config).unwrap();

        let mut wallet_config2 = wallet_config.clone();
        wallet_config2.wallet_key_derivation = wallet_wrong_kdf.into();
        // Open fails without Wallet Key Derivation set
        assert_eq!(open_as_main_wallet(&wallet_config2).unwrap_err().kind(), VcxErrorKind::WalletAccessFailed);

        // Open works when set
        assert!(open_as_main_wallet(&wallet_config).is_ok());


        settings::clear_config();
        close_main_wallet().unwrap();

        // Delete fails
        assert_eq!(delete_wallet(&wallet_config2).unwrap_err().kind(), VcxErrorKind::WalletAccessFailed);

        // Delete works
        delete_wallet(&wallet_config).unwrap()
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_wallet_key_rotation() {
        let _setup = SetupDefaults::init();

        let wallet_name = &format!("test_wallet_rotation_{}", uuid::Uuid::new_v4());
        let wallet_key1 = "3CywYxovdJHg5NEiaVq1uLD4hmkBWKs9jnSF2PTfUApe";

        let wallet_config = WalletConfig {
            wallet_name: wallet_name.into(),
            wallet_key: wallet_key1.into(),
            wallet_key_derivation: settings::WALLET_KDF_ARGON2I_MOD.into(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None, rekey: None, rekey_derivation_method: None
        };
        let _handle = create_and_open_as_main_wallet(&wallet_config).unwrap();

        let (my_did, my_vk) = create_and_store_my_did(None, None).unwrap();

        settings::set_config_value(settings::CONFIG_INSTITUTION_DID, &my_did);
        settings::get_agency_client_mut().unwrap().set_my_vk(&my_vk);

        let options = json!({
            "retrieveType": true,
            "retrieveValue": true,
            "retrieveTags": false
        }).to_string();
        let (record_type, id, value) = _record();
        let expected_retrieved_record = format!(r#"{{"type":"{}","id":"{}","value":"{}","tags":null}}"#, record_type, id, value);

        add_record(record_type, id, value, None).unwrap();
        let retrieved_record = get_record(record_type, id, &options).unwrap();
        assert_eq!(retrieved_record, expected_retrieved_record);
        close_main_wallet().unwrap();

        open_as_main_wallet(&wallet_config).unwrap();
        let retrieved_record = get_record(record_type, id, &options).unwrap();
        assert_eq!(retrieved_record, expected_retrieved_record);
        close_main_wallet().unwrap();

        let wallet_key2 = "NGKRM9afPYprbWCv43cTyu62hjHJ1QtkE8ogmsndiS5e";
        let mut wallet_config2 =  wallet_config.clone();
        wallet_config2.rekey = Some(wallet_key2.into());
        wallet_config2.rekey_derivation_method = Some(settings::WALLET_KDF_ARGON2I_INT.into());
        open_as_main_wallet(&wallet_config2).unwrap();
        let retrieved_record = get_record(record_type, id, &options).unwrap();
        assert_eq!(retrieved_record, expected_retrieved_record);
        close_main_wallet().unwrap();

        let rc = open_as_main_wallet(&wallet_config);
        assert_eq!(rc.unwrap_err().kind(), VcxErrorKind::WalletAccessFailed);

        let mut wallet_config3 =  wallet_config.clone();
        wallet_config3.wallet_key = wallet_key2.into();
        wallet_config3.wallet_key_derivation = settings::WALLET_KDF_ARGON2I_INT.into();
        open_as_main_wallet(&wallet_config3).unwrap();

        let retrieved_record = get_record(record_type, id, &options).unwrap();
        assert_eq!(retrieved_record, expected_retrieved_record);
        delete_record(record_type, id).unwrap();
        close_main_wallet().unwrap();

        settings::clear_config();
    }

    #[test]
    #[cfg(feature = "general_test")]
    #[cfg(feature = "to_restore")]
    fn test_wallet_import_export_with_different_wallet_key() {
        let _setup = SetupDefaults::init();

        let (export_path, wallet_name, wallet_config) = create_main_wallet_and_its_backup();

        close_main_wallet();
        delete_wallet(&wallet_config).unwrap();

        let xtype = "type1";
        let id = "id1";
        let value = "value1";

        // api_c::vcx::vcx_shutdown(true);

        let import_config = RestoreWalletConfigs {
            wallet_name: wallet_name.clone(),
            wallet_key: "new key".into(),
            exported_wallet_path: export_path.to_string(),
            backup_key: settings::DEFAULT_WALLET_BACKUP_KEY.to_string(),
            wallet_key_derivation: Some(settings::WALLET_KDF_RAW.into())
        };

        import(&import_config).unwrap();

        let wallet_config_2 = WalletConfig {
            wallet_name: wallet_name.into(),
            wallet_key: "new key".into(),
            wallet_key_derivation: settings::WALLET_KDF_RAW.into(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None, rekey: None, rekey_derivation_method: None
        };

        open_as_main_wallet(&wallet_config_2).unwrap();

        // If wallet was successfully imported, there will be an error trying to add this duplicate record
        assert_eq!(add_record(xtype, id, value, None).unwrap_err().kind(), VcxErrorKind::DuplicationWalletRecord);

        close_main_wallet();
        delete_wallet(&wallet_config_2).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_wallet_import_export() {
        let _setup = SetupDefaults::init();

        let (export_wallet_path, wallet_name, wallet_config) = create_main_wallet_and_its_backup();

        delete_wallet(&wallet_config).unwrap();

        settings::clear_config();

        let (type_, id, value) = _record();

        let import_config = RestoreWalletConfigs {
            wallet_name: wallet_name.clone(),
            wallet_key: settings::DEFAULT_WALLET_KEY.into(),
            exported_wallet_path: export_wallet_path.path.to_string(),
            backup_key: settings::DEFAULT_WALLET_BACKUP_KEY.to_string(),
            wallet_key_derivation: Some(settings::WALLET_KDF_RAW.into())
        };
        import(&import_config).unwrap();

        let wallet_config = WalletConfig {
            wallet_name: wallet_name.clone(),
            wallet_key: settings::DEFAULT_WALLET_KEY.into(),
            wallet_key_derivation: settings::WALLET_KDF_RAW.into(),
            wallet_type: None,
            storage_config: None,
            storage_credentials: None, rekey: None, rekey_derivation_method: None
        };
        open_as_main_wallet(&wallet_config).unwrap();

        // If wallet was successfully imported, there will be an error trying to add this duplicate record
        assert_eq!(add_record(type_, id, value, None).unwrap_err().kind(), VcxErrorKind::DuplicationWalletRecord);

        close_main_wallet().unwrap();
        delete_wallet(&wallet_config).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_import_wallet_fails_with_existing_wallet() {
        let _setup = SetupDefaults::init();

        let (export_wallet_path, wallet_name, wallet_config) = create_main_wallet_and_its_backup();

        let import_config = RestoreWalletConfigs {
            wallet_name: wallet_name.clone(),
            wallet_key: settings::DEFAULT_WALLET_KEY.into(),
            exported_wallet_path: export_wallet_path.path.to_string(),
            backup_key: settings::DEFAULT_WALLET_BACKUP_KEY.to_string(),
            wallet_key_derivation: Some(settings::WALLET_KDF_RAW.into())
        };
        let res = import(&import_config).unwrap_err();
        assert_eq!(res.kind(), VcxErrorKind::DuplicationWallet);

        delete_wallet(&wallet_config).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_import_wallet_fails_with_invalid_path() {
        let _setup = SetupDefaults::init();

        let import_config = RestoreWalletConfigs {
            wallet_name: settings::DEFAULT_WALLET_NAME.into(),
            wallet_key: settings::DEFAULT_WALLET_KEY.into(),
            exported_wallet_path: "DIFFERENT_PATH".to_string(),
            backup_key: settings::DEFAULT_WALLET_BACKUP_KEY.to_string(),
            wallet_key_derivation: Some(settings::WALLET_KDF_RAW.into())
        };
        let res = import(&import_config).unwrap_err();
        assert_eq!(res.kind(), VcxErrorKind::IOError);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_import_wallet_fails_with_invalid_backup_key() {
        let _setup = SetupDefaults::init();

        let (export_wallet_path, wallet_name, wallet_config) = create_main_wallet_and_its_backup();

        delete_wallet(&wallet_config).unwrap();

        let wallet_name_new = &format!("export_test_wallet_{}", uuid::Uuid::new_v4());
        let import_config = RestoreWalletConfigs {
            wallet_name: wallet_name.clone(),
            wallet_key: settings::DEFAULT_WALLET_KEY.into(),
            exported_wallet_path: export_wallet_path.path.to_string(),
            backup_key: "bad_backup_key".into(),
            wallet_key_derivation: Some(settings::WALLET_KDF_RAW.into())
        };
        let res = import(&import_config).unwrap_err();
        assert_eq!(res.kind(), VcxErrorKind::LibindyInvalidStructure);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_add_new_record_with_no_tag() {
        let _setup = SetupLibraryWallet::init();

        let (record_type, id, record) = _record();

        add_record(record_type, id, record, None).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_add_duplicate_record_fails() {
        let _setup = SetupLibraryWallet::init();

        let (record_type, id, record) = _record();

        add_record(record_type, id, record, None).unwrap();

        let rc = add_record(record_type, id, record, None);
        assert_eq!(rc.unwrap_err().kind(), VcxErrorKind::DuplicationWalletRecord);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_add_record_with_same_id_but_different_type_success() {
        let _setup = SetupLibraryWallet::init();

        let (_, id, record) = _record();

        let record_type = "Type";
        let record_type2 = "Type2";

        add_record(record_type, id, record, None).unwrap();
        add_record(record_type2, id, record, None).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_retrieve_missing_record_fails() {
        let _setup = SetupLibraryWallet::init();

        let record_type = "Type";
        let id = "123";
        let options = json!({
            "retrieveType": false,
            "retrieveValue": false,
            "retrieveTags": false
        }).to_string();

        let rc = get_record(record_type, id, &options);
        assert_eq!(rc.unwrap_err().kind(), VcxErrorKind::WalletRecordNotFound);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_retrieve_record_success() {
        let _setup = SetupLibraryWallet::init();

        let (record_type, id, record) = _record();

        let options = json!({
            "retrieveType": true,
            "retrieveValue": true,
            "retrieveTags": false
        }).to_string();
        let expected_retrieved_record = format!(r#"{{"type":"{}","id":"{}","value":"{}","tags":null}}"#, record_type, id, record);

        add_record(record_type, id, record, None).unwrap();
        let retrieved_record = get_record(record_type, id, &options).unwrap();

        assert_eq!(retrieved_record, expected_retrieved_record);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_delete_record_fails_with_no_record() {
        let _setup = SetupLibraryWallet::init();

        let (record_type, id, _) = _record();

        let rc = delete_record(record_type, id);
        assert_eq!(rc.unwrap_err().kind(), VcxErrorKind::WalletRecordNotFound);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_delete_record_success() {
        let _setup = SetupLibraryWallet::init();

        let (record_type, id, record) = _record();

        let options = json!({
            "retrieveType": true,
            "retrieveValue": true,
            "retrieveTags": false
        }).to_string();

        add_record(record_type, id, record, None).unwrap();
        delete_record(record_type, id).unwrap();
        let rc = get_record(record_type, id, &options);
        assert_eq!(rc.unwrap_err().kind(), VcxErrorKind::WalletRecordNotFound);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_update_record_value_fails_with_no_initial_record() {
        let _setup = SetupLibraryWallet::init();

        let (record_type, id, record) = _record();

        let rc = update_record_value(record_type, id, record);
        assert_eq!(rc.unwrap_err().kind(), VcxErrorKind::WalletRecordNotFound);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_update_record_value_success() {
        let _setup = SetupLibraryWallet::init();

        let initial_record = "Record1";
        let changed_record = "Record2";
        let record_type = "Type";
        let id = "123";
        let options = json!({
            "retrieveType": true,
            "retrieveValue": true,
            "retrieveTags": false
        }).to_string();
        let expected_initial_record = format!(r#"{{"type":"{}","id":"{}","value":"{}","tags":null}}"#, record_type, id, initial_record);
        let expected_updated_record = format!(r#"{{"type":"{}","id":"{}","value":"{}","tags":null}}"#, record_type, id, changed_record);

        add_record(record_type, id, initial_record, None).unwrap();
        let initial_record = get_record(record_type, id, &options).unwrap();
        update_record_value(record_type, id, changed_record).unwrap();
        let changed_record = get_record(record_type, id, &options).unwrap();

        assert_eq!(initial_record, expected_initial_record);
        assert_eq!(changed_record, expected_updated_record);
    }
}
