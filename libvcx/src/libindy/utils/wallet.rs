use indy::future::Future;
use indy::{ErrorCode, wallet};
use indy::{INVALID_WALLET_HANDLE, SearchHandle, WalletHandle};

use crate::error::prelude::*;
use crate::init::open_as_main_wallet;
use crate::settings;
use crate::libindy::utils::{anoncreds, signus};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WalletConfig {
    wallet_name: String,
    wallet_key: String,
    wallet_key_derivation: String,
    wallet_type: Option<String>,
    storage_config: Option<String>,
    storage_credentials: Option<String>
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

pub fn reset_wallet_handle() {
    set_wallet_handle(INVALID_WALLET_HANDLE);
    settings::get_agency_client_mut().unwrap().reset_wallet_handle();
}

pub fn create_wallet_from_config(config: &str) -> VcxResult<()> {
    let config: WalletConfig = serde_json::from_str(config)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize WalletConfig {:?}, err: {:?}", config, err)))?;

    let wh = create_and_open_as_main_wallet(
        &config.wallet_name,
        &config.wallet_key,
        &config.wallet_key_derivation,
        config.wallet_type.as_ref().map(String::as_str),
        config.storage_config.as_ref().map(String::as_str),
        config.storage_credentials.as_ref().map(String::as_str),
    )?;
    trace!("Wallet with handle {:?} and config {:?} created", wh, config);

    // If MS is already in wallet then just continue
    anoncreds::libindy_prover_create_master_secret(settings::DEFAULT_LINK_SECRET_ALIAS).ok();
    
    close_main_wallet()?;
    Ok(())
}

pub fn configure_issuer_wallet(enterprise_seed: &str) -> VcxResult<String> {

    let (institution_did, institution_verkey) = signus::create_and_store_my_did(Some(enterprise_seed), None)?;

    settings::set_config_value(settings::CONFIG_INSTITUTION_DID, &institution_did);
    settings::set_config_value(settings::CONFIG_INSTITUTION_VERKEY, &institution_verkey);
    // settings::get_agency_client()?.set_my_vk(&my_vk); // TODO: Set on client init
    let institution_config = json!({
        "institution_did": institution_did,
        "institution_verkey": institution_verkey,
    });
    Ok(institution_config.to_string())
}

pub fn build_wallet_config(wallet_name: &str, wallet_type: Option<&str>, storage_config: Option<&str>) -> String {
    let mut config = json!({
        "id": wallet_name,
        "storage_type": wallet_type
    });
    if let Some(_config) = storage_config { config["storage_config"] = serde_json::from_str(_config).unwrap(); }
    config.to_string()
}

pub fn build_wallet_credentials(key: &str, storage_creds: Option<&str>, key_derivation: &str) -> String {
    let mut credentials = json!({"key": key, "key_derivation_method": key_derivation});
    if let Some(storage_credentials) = storage_creds { credentials["storage_credentials"] = serde_json::from_str(&storage_credentials).unwrap(); }
    credentials.to_string()
}

pub fn create_wallet(wallet_name: &str, wallet_key: &str, key_derivation: &str, wallet_type: Option<&str>, storage_config: Option<&str>, storage_creds: Option<&str>) -> VcxResult<()> {
    trace!("creating wallet: {}", wallet_name);

    let config = build_wallet_config(wallet_name, wallet_type, storage_config);
    let credentials = build_wallet_credentials(wallet_key, storage_creds, key_derivation);

    match wallet::create_wallet(&config, &credentials)
        .wait() {
        Ok(()) => Ok(()),
        Err(err) => {
            match err.error_code.clone() {
                ErrorCode::WalletAlreadyExistsError => {
                    warn!("wallet \"{}\" already exists. skipping creation", wallet_name);
                    Ok(())
                }
                _ => {
                    warn!("could not create wallet {}: {:?}", wallet_name, err.message);
                    Err(VcxError::from_msg(VcxErrorKind::WalletCreate, format!("could not create wallet {}: {:?}", wallet_name, err.message)))
                }
            }
        }
    }
}

pub fn create_and_open_as_main_wallet(wallet_name: &str, wallet_key: &str, key_derivation: &str, wallet_type: Option<&str>, storage_config: Option<&str>, storage_creds: Option<&str>) -> VcxResult<WalletHandle> {
    if settings::indy_mocks_enabled() {
        warn!("open_as_main_wallet ::: Indy mocks enabled, skipping opening main wallet.");
        return Ok(set_wallet_handle(WalletHandle(1)));
    }
    create_wallet(wallet_name, wallet_key, key_derivation, wallet_type, storage_config, storage_creds)?;
    open_as_main_wallet(wallet_name, wallet_key, key_derivation, wallet_type, storage_config, storage_creds)
}

pub fn open_wallet_directly(wallet_config: &str) -> VcxResult<WalletHandle> {
    let config: WalletConfig = serde_json::from_str(wallet_config)
        .map_err(|err| VcxError::from_msg(VcxErrorKind::InvalidJson, format!("Cannot deserialize WalletConfig {:?}, err: {:?}", wallet_config, err)))?;
    open_as_main_wallet(&config.wallet_name, &config.wallet_key, &config.wallet_key_derivation, config.wallet_type.as_deref(), config.storage_config.as_deref(), config.storage_credentials.as_deref())
}

pub fn close_wallet_directly(wallet_handle: WalletHandle) -> VcxResult<()> {
    wallet::close_wallet(wallet_handle)
        .wait()?;

    reset_wallet_handle();
    Ok(())
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

    reset_wallet_handle();
    Ok(())
}

pub fn delete_wallet(wallet_name: &str, wallet_key: &str, key_derivation: &str, wallet_type: Option<&str>, storage_config: Option<&str>, storage_creds: Option<&str>) -> VcxResult<()> {
    trace!("delete_wallet >>> wallet_name: {}", wallet_name);

    let config = build_wallet_config(wallet_name, wallet_type, storage_config);
    let credentials = build_wallet_credentials(wallet_key, storage_creds, key_derivation);

    wallet::delete_wallet(&config, &credentials)
        .wait()
        .map_err(|err|
            match err.error_code.clone() {
                ErrorCode::WalletAccessFailed => {
                    err.to_vcx(VcxErrorKind::WalletAccessFailed,
                               format!("Can not open wallet \"{}\". Invalid key has been provided.", wallet_name))
                }
                ErrorCode::WalletNotFoundError => {
                    err.to_vcx(VcxErrorKind::WalletNotFound,
                               format!("Wallet \"{}\" not found or unavailable", wallet_name))
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

pub fn import(config: &str) -> VcxResult<()> {
    trace!("import >>> config {}", config);

    settings::process_config_string(config, false)?;

    let restore_config = RestoreWalletConfigs::from_str(config)?;
    let new_wallet_name = restore_config.wallet_name;
    let new_wallet_key = restore_config.wallet_key;
    let new_wallet_kdf = restore_config.wallet_key_derivation.unwrap_or(settings::WALLET_KDF_DEFAULT.into());

    let new_wallet_config = build_wallet_config(&new_wallet_name, None, None);
    let new_wallet_credentials = build_wallet_credentials(&new_wallet_key, None, &new_wallet_kdf);
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
    use crate::utils::devsetup::{SetupDefaults, SetupEmpty, SetupLibraryWallet, TempFile};
    use crate::utils::get_temp_dir_path;

    use super::*;

    fn _record() -> (&'static str, &'static str, &'static str) {
        ("type1", "id1", "value1")
    }

    pub fn create_main_wallet_and_its_backup() -> (TempFile, String) {
        let wallet_name = &format!("export_test_wallet_{}", uuid::Uuid::new_v4());

        let export_file = TempFile::prepare_path(wallet_name);

        let _handle = create_and_open_as_main_wallet(wallet_name, settings::DEFAULT_WALLET_KEY, settings::WALLET_KDF_RAW, None, None, None).unwrap();

        let (my_did, my_vk) = create_and_store_my_did(None, None).unwrap();

        settings::set_config_value(settings::CONFIG_INSTITUTION_DID, &my_did);
        settings::get_agency_client_mut().unwrap().set_my_vk(&my_vk);

        let backup_key = settings::get_config_value(settings::CONFIG_WALLET_BACKUP_KEY).unwrap();

        let (type_, id, value) = _record();
        add_record(type_, id, value, None).unwrap();

        export_main_wallet(&export_file.path, &backup_key).unwrap();

        close_main_wallet().unwrap();

        (export_file, wallet_name.to_string())
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_wallet() {
        let _setup = SetupLibraryWallet::init();

        assert_ne!(get_wallet_handle(), INVALID_WALLET_HANDLE);
        assert_eq!(VcxErrorKind::WalletCreate, create_and_open_as_main_wallet(&String::from(""), settings::DEFAULT_WALLET_KEY, settings::WALLET_KDF_RAW, None, None, None).unwrap_err().kind());
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_wallet_for_unknown_type() {
        let _setup = SetupDefaults::init();

        assert_eq!(VcxErrorKind::WalletCreate, create_and_open_as_main_wallet("test_wallet_for_unknown_type", "some_key", settings::WALLET_KDF_RAW, None, None, None).unwrap_err().kind());
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

        create_wallet(wallet_name, wallet_key, wallet_kdf, None, None, None).unwrap();

        // Open fails without Wallet Key Derivation set
        assert_eq!(open_as_main_wallet(wallet_name, wallet_key, wallet_wrong_kdf, None, None, None).unwrap_err().kind(), VcxErrorKind::WalletAccessFailed);

        // Open works when set
        assert!(open_as_main_wallet(wallet_name, wallet_key, wallet_kdf, None, None, None).is_ok());


        settings::clear_config();
        close_main_wallet().unwrap();

        // Delete fails
        assert_eq!(delete_wallet(wallet_name, wallet_key, wallet_wrong_kdf, None, None, None).unwrap_err().kind(), VcxErrorKind::WalletAccessFailed);

        // Delete works
        delete_wallet(wallet_name, wallet_key, wallet_kdf, None, None, None).unwrap()
    }

    #[test]
    #[cfg(feature = "general_test")]
    #[cfg(feature = "to_restore")]
    fn test_wallet_import_export_with_different_wallet_key() {
        let _setup = SetupDefaults::init();

        let (export_path, wallet_name) = create_main_wallet_and_its_backup();

        close_main_wallet();
        delete_wallet(&wallet_name, settings::DEFAULT_WALLET_KEY, settings::WALLET_KDF_RAW, None, None, None).unwrap();

        let xtype = "type1";
        let id = "id1";
        let value = "value1";

        api::vcx::vcx_shutdown(true);

        let import_config = json!({
            settings::CONFIG_WALLET_NAME: wallet_name.as_str(),
            settings::CONFIG_WALLET_KEY: "new key",
            settings::CONFIG_WALLET_KEY_DERIVATION: settings::WALLET_KDF_RAW,
            settings::CONFIG_EXPORTED_WALLET_PATH: export_path.path,
            settings::CONFIG_WALLET_BACKUP_KEY: settings::DEFAULT_WALLET_BACKUP_KEY,
        }).to_string();
        import(&import_config).unwrap();
        open_as_main_wallet(&wallet_name, "new key", settings::WALLET_KDF_RAW, None, None, None).unwrap();

        // If wallet was successfully imported, there will be an error trying to add this duplicate record
        assert_eq!(add_record(xtype, id, value, None).unwrap_err().kind(), VcxErrorKind::DuplicationWalletRecord);

        close_main_wallet();
        delete_wallet(&wallet_name, "new key", settings::WALLET_KDF_RAW, None, None, None).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_wallet_import_export() {
        let _setup = SetupDefaults::init();

        let (export_wallet_path, wallet_name) = create_main_wallet_and_its_backup();

        delete_wallet(&wallet_name, settings::DEFAULT_WALLET_KEY, settings::WALLET_KDF_RAW, None, None, None).unwrap();

        settings::clear_config();

        let (type_, id, value) = _record();

        let import_config = json!({
            settings::CONFIG_WALLET_NAME: wallet_name.as_str(),
            settings::CONFIG_WALLET_KEY: settings::DEFAULT_WALLET_KEY,
            settings::CONFIG_EXPORTED_WALLET_PATH: export_wallet_path.path,
            settings::CONFIG_WALLET_BACKUP_KEY: settings::DEFAULT_WALLET_BACKUP_KEY,
            settings::CONFIG_WALLET_KEY_DERIVATION: settings::WALLET_KDF_RAW,
        }).to_string();

        import(&import_config).unwrap();

        settings::process_config_string(&import_config, false).unwrap();

        open_as_main_wallet(&wallet_name, settings::DEFAULT_WALLET_KEY, settings::WALLET_KDF_RAW, None, None, None).unwrap();

        // If wallet was successfully imported, there will be an error trying to add this duplicate record
        assert_eq!(add_record(type_, id, value, None).unwrap_err().kind(), VcxErrorKind::DuplicationWalletRecord);

        close_main_wallet().unwrap();
        delete_wallet(&wallet_name, settings::DEFAULT_WALLET_KEY, settings::WALLET_KDF_RAW, None, None, None).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_import_fails_with_missing_configs() {
        let _setup = SetupEmpty::init();

        // Invalid json
        let res = import("").unwrap_err();
        assert_eq!(res.kind(), VcxErrorKind::InvalidJson);
        let mut config = json!({});

        // Missing wallet_key
        let res = import(&config.to_string()).unwrap_err();
        assert_eq!(res.kind(), VcxErrorKind::InvalidJson);
        config[settings::CONFIG_WALLET_KEY] = serde_json::to_value("wallet_key1").unwrap();

        // Missing wallet name
        let res = import(&config.to_string()).unwrap_err();
        assert_eq!(res.kind(), VcxErrorKind::InvalidJson);
        config[settings::CONFIG_WALLET_NAME] = serde_json::to_value("wallet_name1").unwrap();

        // Missing exported_wallet_path
        let res = import(&config.to_string()).unwrap_err();
        assert_eq!(res.kind(), VcxErrorKind::InvalidJson);
        config[settings::CONFIG_EXPORTED_WALLET_PATH] = serde_json::to_value(
            get_temp_dir_path(settings::DEFAULT_EXPORTED_WALLET_PATH).to_str().unwrap()
        ).unwrap();

        // Missing backup_key
        let res = import(&config.to_string()).unwrap_err();
        assert_eq!(res.kind(), VcxErrorKind::InvalidJson);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_import_wallet_fails_with_existing_wallet() {
        let _setup = SetupDefaults::init();

        let (export_wallet_path, wallet_name) = create_main_wallet_and_its_backup();

        let import_config = json!({
            settings::CONFIG_WALLET_NAME: wallet_name,
            settings::CONFIG_WALLET_KEY: settings::DEFAULT_WALLET_KEY,
            settings::CONFIG_EXPORTED_WALLET_PATH: export_wallet_path.path,
            settings::CONFIG_WALLET_BACKUP_KEY: settings::DEFAULT_WALLET_BACKUP_KEY,
            settings::CONFIG_WALLET_KEY_DERIVATION: settings::WALLET_KDF_RAW,
        }).to_string();

        let res = import(&import_config).unwrap_err();
        assert_eq!(res.kind(), VcxErrorKind::DuplicationWallet);

        delete_wallet(&wallet_name, settings::DEFAULT_WALLET_KEY, settings::WALLET_KDF_RAW, None, None, None).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_import_wallet_fails_with_invalid_path() {
        let _setup = SetupDefaults::init();

        let import_config = json!({
            settings::CONFIG_WALLET_NAME: settings::DEFAULT_WALLET_NAME,
            settings::CONFIG_WALLET_KEY: settings::DEFAULT_WALLET_KEY,
            settings::CONFIG_EXPORTED_WALLET_PATH: "DIFFERENT_PATH",
            settings::CONFIG_WALLET_BACKUP_KEY: settings::DEFAULT_WALLET_BACKUP_KEY,
            settings::CONFIG_WALLET_KEY_DERIVATION: settings::WALLET_KDF_RAW,
        }).to_string();

        let res = import(&import_config).unwrap_err();
        assert_eq!(res.kind(), VcxErrorKind::IOError);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_import_wallet_fails_with_invalid_backup_key() {
        let _setup = SetupDefaults::init();

        let (export_wallet_path, wallet_name) = create_main_wallet_and_its_backup();

        delete_wallet(&wallet_name, settings::DEFAULT_WALLET_KEY, settings::WALLET_KDF_RAW, None, None, None).unwrap();

        let wallet_name_new = &format!("export_test_wallet_{}", uuid::Uuid::new_v4());
        let import_config = json!({
            settings::CONFIG_WALLET_NAME: wallet_name_new,
            settings::CONFIG_WALLET_KEY: settings::DEFAULT_WALLET_KEY,
            settings::CONFIG_EXPORTED_WALLET_PATH: export_wallet_path.path,
            settings::CONFIG_WALLET_BACKUP_KEY: "bad_backup_key",
            settings::CONFIG_WALLET_KEY_DERIVATION: settings::WALLET_KDF_RAW,
        }).to_string();
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
