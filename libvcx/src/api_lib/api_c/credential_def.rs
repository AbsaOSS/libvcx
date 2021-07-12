use std::ptr;

use indy_sys::CommandHandle;
use libc::c_char;

use crate::api_lib::api_handle::credential_def;
use crate::api_lib::utils_c::cstring::CStringUtils;
use crate::api_lib::utils_c::runtime::execute;
use crate::error::prelude::*;
use crate::settings;
use crate::utils::error;

/// Create a new CredentialDef object and publish correspondent record on the ledger
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// source_id: Enterprise's personal identification for the user.
///
/// credentialdef_name: Name of credential definition
///
/// schema_id: The schema id given during the creation of the schema
///
/// issuer_did: did corresponding to entity issuing a credential. Needs to have Trust Anchor permissions on ledger
///
/// tag: way to create a unique credential def with the same schema and issuer did.
///
/// revocation details: type-specific configuration of credential definition revocation
///     TODO: Currently supports ISSUANCE BY DEFAULT, support for ISSUANCE ON DEMAND will be added as part of ticket: IS-1074
///     support_revocation: true|false - Optional, by default its false
///     tails_file: path to tails file - Optional if support_revocation is false
///     tails_url: URL where the holder can download the tails file - Optional if support_revocation is false
///     tails_base_url: incomplete URL where the holder can download the tails file - Optional if support_revocation is false
///     max_creds: size of tails file - Optional if support_revocation is false
/// If tails_location is specified, the exact value is written to the ledger and obtainable via vcx_credential_get_tails_location.
/// If tails_base_location in specified, the value written to the ledger and obtainable via vcx_credential_get_tails_location is "{tails_base_location}/{tails_hash}".
/// It is not allowed to specify both tails_location and tails_base_location.
/// # Examples config -> "{}" 
///    | "{"support_revocation":false}" 
///    | "{"support_revocation":true, "tails_file": "/tmp/tailsfile.txt", "max_creds": 1, "tails_url": "https://dummy.faber.org/DvVhi9j4a3RYdZoQxBerhUUHnyBf8k4j8a5Zp2vgLHpW"}"
///    | "{"support_revocation":true, "tails_file": "/tmp/tailsfile.txt", "max_creds": 1, "tails_base_url": "https://dummy.faber.org"}"
/// cb: Callback that provides CredentialDef handle and error status of request.
///
/// payment_handle: future use (currently uses any address in wallet)
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_credentialdef_create(command_handle: CommandHandle,
                                       source_id: *const c_char,
                                       credentialdef_name: *const c_char,
                                       schema_id: *const c_char,
                                       issuer_did: *const c_char,
                                       tag: *const c_char,
                                       revocation_details: *const c_char,
                                       _payment_handle: u32,
                                       cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, credentialdef_handle: u32)>) -> u32 {
    info!("vcx_credentialdef_create >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);
    check_useful_c_str!(credentialdef_name, VcxErrorKind::InvalidOption);
    check_useful_c_str!(source_id, VcxErrorKind::InvalidOption);
    check_useful_c_str!(schema_id, VcxErrorKind::InvalidOption);
    check_useful_c_str!(tag, VcxErrorKind::InvalidOption);
    check_useful_c_str!(revocation_details, VcxErrorKind::InvalidOption);

    let issuer_did: String = if !issuer_did.is_null() {
        check_useful_c_str!(issuer_did, VcxErrorKind::InvalidOption);
        issuer_did.to_owned()
    } else {
        match settings::get_config_value(settings::CONFIG_INSTITUTION_DID) {
            Ok(x) => x,
            Err(x) => return x.into(),
        }
    };

    trace!("vcx_credential_def_create(command_handle: {}, source_id: {}, credentialdef_name: {} schema_id: {}, issuer_did: {}, tag: {}, revocation_details: {:?})",
           command_handle,
           source_id,
           credentialdef_name,
           schema_id,
           issuer_did,
           tag,
           revocation_details);

    execute(move || {
        let (rc, handle) = match credential_def::create_and_publish_credentialdef(source_id,
                                                                                  credentialdef_name,
                                                                                  issuer_did,
                                                                                  schema_id,
                                                                                  tag,
                                                                                  revocation_details) {
            Ok(x) => {
                trace!("vcx_credential_def_create_cb(command_handle: {}, rc: {}, credentialdef_handle: {}), source_id: {:?}",
                       command_handle, error::SUCCESS.message, x, credential_def::get_source_id(x).unwrap_or_default());
                (error::SUCCESS.code_num, x)
            }
            Err(x) => {
                warn!("vcx_credential_def_create_cb(command_handle: {}, rc: {}, credentialdef_handle: {}), source_id: {:?}",
                      command_handle, x, 0, "");
                (x.into(), 0)
            }
        };
        cb(command_handle, rc, handle);

        Ok(())
    });

    error::SUCCESS.code_num
}

/// Takes the credentialdef object and returns a json string of all its attributes
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// credentialdef_handle: Credentialdef handle that was provided during creation. Used to access credentialdef object
///
/// cb: Callback that provides json string of the credentialdef's attributes and provides error status
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_credentialdef_serialize(command_handle: CommandHandle,
                                          credentialdef_handle: u32,
                                          cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, credentialdef_state: *const c_char)>) -> u32 {
    info!("vcx_credentialdef_serialize >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = credential_def::get_source_id(credentialdef_handle).unwrap_or_default();
    trace!("vcx_credentialdef_serialize(command_handle: {}, credentialdef_handle: {}), source_id: {:?}",
           command_handle, credentialdef_handle, source_id);

    if !credential_def::is_valid_handle(credentialdef_handle) {
        return VcxError::from(VcxErrorKind::InvalidCredDefHandle).into();
    };

    execute(move || {
        match credential_def::to_string(credentialdef_handle) {
            Ok(x) => {
                trace!("vcx_credentialdef_serialize_cb(command_handle: {}, credentialdef_handle: {}, rc: {}, state: {}), source_id: {:?}",
                       command_handle, credentialdef_handle, error::SUCCESS.message, x, source_id);
                let msg = CStringUtils::string_to_cstring(x);
                cb(command_handle, error::SUCCESS.code_num, msg.as_ptr());
            }
            Err(x) => {
                warn!("vcx_credentialdef_serialize_cb(command_handle: {}, credentialdef_handle: {}, rc: {}, state: {}), source_id: {:?}",
                      command_handle, credentialdef_handle, x, "null", source_id);
                cb(command_handle, x.into(), ptr::null_mut());
            }
        };

        Ok(())
    });

    error::SUCCESS.code_num
}

/// Takes a json string representing a credentialdef object and recreates an object matching the json
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// credentialdef_data: json string representing a credentialdef object
///
/// cb: Callback that provides credentialdef handle and provides error status
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_credentialdef_deserialize(command_handle: CommandHandle,
                                            credentialdef_data: *const c_char,
                                            cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, credentialdef_handle: u32)>) -> u32 {
    info!("vcx_credentialdef_deserialize >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);
    check_useful_c_str!(credentialdef_data, VcxErrorKind::InvalidOption);

    trace!("vcx_credentialdef_deserialize(command_handle: {}, credentialdef_data: {})", command_handle, credentialdef_data);

    execute(move || {
        let (rc, handle) = match credential_def::from_string(&credentialdef_data) {
            Ok(x) => {
                trace!("vcx_credentialdef_deserialize_cb(command_handle: {}, rc: {}, handle: {}), source_id: {}",
                       command_handle, error::SUCCESS.message, x, credential_def::get_source_id(x).unwrap_or_default());
                (error::SUCCESS.code_num, x)
            }
            Err(e) => {
                warn!("vcx_credentialdef_deserialize_cb(command_handle: {}, rc: {}, handle: {}), source_id: {}",
                      command_handle, e, 0, "");
                (e.into(), 0)
            }
        };
        cb(command_handle, rc, handle);

        Ok(())
    });

    error::SUCCESS.code_num
}

/// Retrieves credential definition's id
///
/// #Params
/// cred_def_handle: CredDef handle that was provided during creation. Used to access proof object
///
/// cb: Callback that provides credential definition id and provides error status
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_credentialdef_get_cred_def_id(command_handle: CommandHandle,
                                                cred_def_handle: u32,
                                                cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, cred_def_id: *const c_char)>) -> u32 {
    info!("vcx_credentialdef_get_cred_def_id >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = credential_def::get_source_id(cred_def_handle).unwrap_or_default();
    trace!("vcx_credentialdef_get_cred_def_id(command_handle: {}, cred_def_handle: {}) source_id: {}", command_handle, cred_def_handle, source_id);
    if !credential_def::is_valid_handle(cred_def_handle) {
        return VcxError::from(VcxErrorKind::InvalidCredDefHandle).into();
    }

    execute(move || {
        match credential_def::get_cred_def_id(cred_def_handle) {
            Ok(x) => {
                trace!("vcx_credentialdef_get_cred_def_id(command_handle: {}, cred_def_handle: {}, rc: {}, cred_def_id: {}) source_id: {}",
                       command_handle, cred_def_handle, error::SUCCESS.message, x, source_id);
                let msg = CStringUtils::string_to_cstring(x);
                cb(command_handle, error::SUCCESS.code_num, msg.as_ptr());
            }
            Err(x) => {
                warn!("vcx_credentialdef_get_cred_def_id(command_handle: {}, cred_def_handle: {}, rc: {}, cred_def_id: {}) source_id: {}",
                      command_handle, cred_def_handle, x, "", source_id);
                cb(command_handle, x.into(), ptr::null_mut());
            }
        };

        Ok(())
    });

    error::SUCCESS.code_num
}

/// Releases the credentialdef object by de-allocating memory
///
/// #Params
/// handle: Proof handle that was provided during creation. Used to access credential object
///
/// #Returns
/// Success
#[no_mangle]
pub extern fn vcx_credentialdef_release(credentialdef_handle: u32) -> u32 {
    info!("vcx_credentialdef_release >>>");

    let source_id = credential_def::get_source_id(credentialdef_handle).unwrap_or_default();
    match credential_def::release(credentialdef_handle) {
        Ok(()) => {
            trace!("vcx_credentialdef_release(credentialdef_handle: {}, rc: {}), source_id: {}",
                   credentialdef_handle, error::SUCCESS.message, source_id);
            error::SUCCESS.code_num
        }

        Err(x) => {
            warn!("vcx_credentialdef_release(credentialdef_handle: {}, rc: {}), source_id: {}",
                  credentialdef_handle, x, source_id);
            x.into()
        }
    }
}

/// Checks if credential definition is published on the Ledger and updates the state if it is.
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// credentialdef_handle: Credentialdef handle that was provided during creation. Used to access credentialdef object
///
/// cb: Callback that provides most current state of the credential definition and error status of request
///     States:
///         0 = Built
///         1 = Published
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_credentialdef_update_state(command_handle: CommandHandle,
                                             credentialdef_handle: u32,
                                             cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, state: u32)>) -> u32 {
    info!("vcx_credentialdef_update_state >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = credential_def::get_source_id(credentialdef_handle).unwrap_or_default();
    trace!("vcx_credentialdef_update_state(command_handle: {}, credentialdef_handle: {}) source_id: {}",
           command_handle, credentialdef_handle, source_id);

    if !credential_def::is_valid_handle(credentialdef_handle) {
        return VcxError::from(VcxErrorKind::InvalidCredDefHandle).into();
    }

    execute(move || {
        match credential_def::update_state(credentialdef_handle) {
            Ok(state) => {
                trace!("vcx_credentialdef_update_state(command_handle: {}, rc: {}, state: {})",
                       command_handle, error::SUCCESS.message, state);
                cb(command_handle, error::SUCCESS.code_num, state);
            }
            Err(x) => {
                warn!("vcx_credentialdef_update_state(command_handle: {}, rc: {}, state: {})",
                      command_handle, x, 0);
                cb(command_handle, x.into(), 0);
            }
        };

        Ok(())
    });

    error::SUCCESS.code_num
}

/// Get the current state of the credential definition object
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// credentialdef_handle: Credentialdef handle that was provided during creation. Used to access credentialdef object
///
/// cb: Callback that provides most current state of the credential definition and error status of request
///     States:
///         0 = Built
///         1 = Published
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_credentialdef_get_state(command_handle: CommandHandle,
                                          credentialdef_handle: u32,
                                          cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, state: u32)>) -> u32 {
    info!("vcx_credentialdef_get_state >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = credential_def::get_source_id(credentialdef_handle).unwrap_or_default();
    trace!("vcx_credentialdef_get_state(command_handle: {}, credentialdef_handle: {}) source_id: {}",
           command_handle, credentialdef_handle, source_id);

    if !credential_def::is_valid_handle(credentialdef_handle) {
        return VcxError::from(VcxErrorKind::InvalidCredDefHandle).into();
    }

    execute(move || {
        match credential_def::get_state(credentialdef_handle) {
            Ok(state) => {
                trace!("vcx_credentialdef_get_state(command_handle: {}, rc: {}, state: {})",
                       command_handle, error::SUCCESS.message, state);
                cb(command_handle, error::SUCCESS.code_num, state);
            }
            Err(x) => {
                warn!("vcx_credentialdef_get_state(command_handle: {}, rc: {}, state: {})",
                      command_handle, x, 0);
                cb(command_handle, x.into(), 0);
            }
        };

        Ok(())
    });

    error::SUCCESS.code_num
}

#[no_mangle]
pub extern fn vcx_credentialdef_rotate_rev_reg_def(command_handle: CommandHandle,
                                                   credentialdef_handle: u32,
                                                   revocation_details: *const c_char,
                                                   cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, credentialdef_state: *const c_char)>) -> u32 {
    info!("vcx_credentialdef_rotate_rev_reg_def >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);
    check_useful_c_str!(revocation_details, VcxErrorKind::InvalidOption);

    let source_id = credential_def::get_source_id(credentialdef_handle).unwrap_or_default();
    trace!("vcx_credentialdef_rotate_rev_reg_def(command_handle: {}, credentialdef_handle: {}, revocation_details: {}) source_id: {}",
           command_handle, credentialdef_handle, revocation_details, source_id);

    if !credential_def::is_valid_handle(credentialdef_handle) {
        return VcxError::from(VcxErrorKind::InvalidCredDefHandle).into();
    }

    execute(move || {
        match credential_def::rotate_rev_reg_def(credentialdef_handle, &revocation_details) {
            Ok(x) => {
                trace!("vcx_credentialdef_rotate_rev_reg_def(command_handle: {}, credentialdef_handle: {}, rc: {}, rev_reg_def: {}), source_id: {:?}",
                       command_handle, credentialdef_handle, error::SUCCESS.message, x, source_id);
                let msg = CStringUtils::string_to_cstring(x);
                cb(command_handle, error::SUCCESS.code_num, msg.as_ptr());
            }
            Err(x) => {
                warn!("vcx_credentialdef_rotate_rev_reg_def(command_handle: {}, credentialdef_handle: {}, rc: {}, rev_reg_def: {}), source_id: {:?}",
                      command_handle, credentialdef_handle, x, "null", source_id);
                cb(command_handle, x.into(), ptr::null_mut());
            }
        };

        Ok(())
    });

    error::SUCCESS.code_num
}

#[no_mangle]
pub extern fn vcx_credentialdef_publish_revocations(command_handle: CommandHandle,
                                                    credentialdef_handle: u32,
                                                    cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32)>) -> u32 {
    info!("vcx_credentialdef_publish_revocations >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = credential_def::get_source_id(credentialdef_handle).unwrap_or_default();

    trace!("vcx_credentialdef_get_state(command_handle: {}, credentialdef_handle: {}) source_id: {}",
           command_handle, credentialdef_handle, source_id);

    if !credential_def::is_valid_handle(credentialdef_handle) {
        return VcxError::from(VcxErrorKind::InvalidCredDefHandle).into();
    }

    execute(move || {
        match credential_def::publish_revocations(credentialdef_handle) {
            Ok(()) => {
                trace!("vcx_credentialdef_publish_revocations(command_handle: {}, credentialdef_handle: {}, rc: {})",
                       command_handle, credentialdef_handle, error::SUCCESS.message);
                cb(command_handle, error::SUCCESS.code_num);
            }
            Err(x) => {
                warn!("vcx_credentialdef_publish_revocations(command_handle: {}, credentialdef_handle: {}, rc: {})",
                      command_handle, credentialdef_handle, x);
                cb(command_handle, x.into());
            }
        };

        Ok(())
    });

    error::SUCCESS.code_num
}

#[no_mangle]
pub extern fn vcx_credentialdef_get_tails_hash(command_handle: CommandHandle,
                                               handle: u32,
                                               cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, hash: *const c_char)>) -> u32 {
    info!("vcx_credentialdef_get_tails_hash >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = credential_def::get_source_id(handle).unwrap_or_default();
    trace!("vcx_credentialdef_get_tails_hash(command_handle: {}) source_id: {}", command_handle, source_id);

    execute(move || {
        match credential_def::get_tails_hash(handle) {
            Ok(x) => {
                trace!("vcx_credentialdef_get_tails_hash_cb(command_handle: {}, rc: {}, hash: {}), source_id: {}",
                       command_handle, error::SUCCESS.message, x, credential_def::get_source_id(handle).unwrap_or_default());

                let hash = CStringUtils::string_to_cstring(x);
                cb(command_handle, 0, hash.as_ptr());
            }
            Err(x) => {
                error!("vcx_credentialdef_get_tails_hash_cb(command_handle: {}, rc: {}, hash: {}), source_id: {}",
                       command_handle, x, "null", credential_def::get_source_id(handle).unwrap_or_default());
                cb(command_handle, x.into(), ptr::null());
            }
        };

        Ok(())
    });

    error::SUCCESS.code_num
}

#[no_mangle]
pub extern fn vcx_credentialdef_get_rev_reg_id(command_handle: CommandHandle,
                                               handle: u32,
                                               cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, rev_reg_id: *const c_char)>) -> u32 {
    info!("vcx_credentialdef_get_rev_reg_id >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = credential_def::get_source_id(handle).unwrap_or_default();
    trace!("vcx_credentialdef_get_rev_reg_id(command_handle: {}) source_id: {}", command_handle, source_id);

    execute(move || {
        match credential_def::get_rev_reg_id(handle) {
            Ok(x) => {
                trace!("vcx_credentialdef_get_rev_reg_id_cb(command_handle: {}, rc: {}, rev_reg_id: {}), source_id: {}",
                       command_handle, error::SUCCESS.message, x, credential_def::get_source_id(handle).unwrap_or_default());

                let rev_reg_id = CStringUtils::string_to_cstring(x);
                cb(command_handle, 0, rev_reg_id.as_ptr());
            }
            Err(x) => {
                error!("vcx_credentialdef_get_rev_reg_id(command_handle: {}, rc: {}, rev_reg_id: {}), source_id: {}",
                       command_handle, x, "null", credential_def::get_source_id(handle).unwrap_or_default());
                cb(command_handle, x.into(), ptr::null());
            }
        };

        Ok(())
    });

    error::SUCCESS.code_num
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use crate::{api_lib, utils};
    use crate::api_lib::utils_c::return_types_u32;
    use crate::api_lib::utils_c::timeout::TimeoutUtils;
    use crate::utils::constants::SCHEMA_ID;
    use crate::utils::devsetup::*;

    use super::*;

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_create_credentialdef_success() {
        let _setup = SetupMocks::init();

        let cb = return_types_u32::Return_U32_U32::new().unwrap();
        assert_eq!(vcx_credentialdef_create(cb.command_handle,
                                            CString::new("Test Source ID").unwrap().into_raw(),
                                            CString::new("Test Credential Def").unwrap().into_raw(),
                                            CString::new(SCHEMA_ID).unwrap().into_raw(),
                                            CString::new("6vkhW3L28AophhA68SSzRS").unwrap().into_raw(),
                                            CString::new("tag").unwrap().into_raw(),
                                            CString::new("{}").unwrap().into_raw(),
                                            0,
                                            Some(cb.get_callback())), error::SUCCESS.code_num);
        cb.receive(TimeoutUtils::some_medium()).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_create_credentialdef_fails() {
        let _setup = SetupLibraryWallet::init();

        let cb = return_types_u32::Return_U32_U32::new().unwrap();
        assert_eq!(vcx_credentialdef_create(cb.command_handle,
                                            CString::new("Test Source ID").unwrap().into_raw(),
                                            CString::new("Test Credential Def").unwrap().into_raw(),
                                            CString::new(SCHEMA_ID).unwrap().into_raw(),
                                            ptr::null(),
                                            CString::new("tag").unwrap().into_raw(),
                                            CString::new("{}").unwrap().into_raw(),
                                            0,
                                            Some(cb.get_callback())), error::SUCCESS.code_num);
        assert!(cb.receive(TimeoutUtils::some_medium()).is_err());
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_credentialdef_serialize() {
        let _setup = SetupMocks::init();

        let cb = return_types_u32::Return_U32_U32::new().unwrap();
        assert_eq!(vcx_credentialdef_create(cb.command_handle,
                                            CString::new("Test Source ID").unwrap().into_raw(),
                                            CString::new("Test Credential Def").unwrap().into_raw(),
                                            CString::new(SCHEMA_ID).unwrap().into_raw(),
                                            ptr::null(),
                                            CString::new("tag").unwrap().into_raw(),
                                            CString::new("{}").unwrap().into_raw(),
                                            0,
                                            Some(cb.get_callback())), error::SUCCESS.code_num);

        let handle = cb.receive(TimeoutUtils::some_medium()).unwrap();
        let cb = return_types_u32::Return_U32_STR::new().unwrap();
        assert_eq!(vcx_credentialdef_serialize(cb.command_handle, handle, Some(cb.get_callback())), error::SUCCESS.code_num);
        let cred = cb.receive(TimeoutUtils::some_medium()).unwrap();
        assert!(cred.is_some());
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_credentialdef_deserialize_succeeds() {
        let _setup = SetupMocks::init();

        let cb = return_types_u32::Return_U32_U32::new().unwrap();

        let original = r#"{"version":"1.0", "data": {"id":"2hoqvcwupRTUNkXn6ArYzs:3:CL:1697","issuer_did":"2hoqvcwupRTUNkXn6ArYzs","tag":"tag","name":"Test Credential Definition","rev_ref_def":null,"rev_reg_entry":null,"rev_reg_id":null,"source_id":"SourceId"}}"#;
        assert_eq!(vcx_credentialdef_deserialize(cb.command_handle,
                                                 CString::new(original).unwrap().into_raw(),
                                                 Some(cb.get_callback())), error::SUCCESS.code_num);

        let handle = cb.receive(TimeoutUtils::some_short()).unwrap();
        assert!(handle > 0);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_credentialdef_deserialize_succeeds_with_old_data() {
        let _setup = SetupMocks::init();

        let cb = return_types_u32::Return_U32_U32::new().unwrap();

        let original = r#"{"data":{"id":"V4SGRU86Z58d6TV7PBUe6f:3:CL:912:tag1","name":"color","payment_txn":null,"source_id":"1","tag":"tag1"},"version":"1.0"}"#;
        assert_eq!(vcx_credentialdef_deserialize(cb.command_handle,
                                                 CString::new(original).unwrap().into_raw(),
                                                 Some(cb.get_callback())), error::SUCCESS.code_num);

        let handle = cb.receive(TimeoutUtils::some_short()).unwrap();
        assert!(handle > 0);
    }


    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_credentialdef_release() {
        let _setup = SetupMocks::init();

        let cb = return_types_u32::Return_U32_U32::new().unwrap();
        assert_eq!(vcx_credentialdef_create(cb.command_handle,
                                            CString::new("Test Source ID Release Test").unwrap().into_raw(),
                                            CString::new("Test Credential Def Release").unwrap().into_raw(),
                                            CString::new(SCHEMA_ID).unwrap().into_raw(),
                                            ptr::null(),
                                            CString::new("tag").unwrap().into_raw(),
                                            CString::new("{}").unwrap().into_raw(),
                                            0,
                                            Some(cb.get_callback())), error::SUCCESS.code_num);

        let handle = cb.receive(TimeoutUtils::some_medium()).unwrap();
        let unknown_handle = handle + 1;
        assert_eq!(vcx_credentialdef_release(unknown_handle), error::INVALID_CREDENTIAL_DEF_HANDLE.code_num);
    }


    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_creddef_get_id() {
        let _setup = SetupMocks::init();

        let cb = return_types_u32::Return_U32_U32::new().unwrap();
        assert_eq!(vcx_credentialdef_create(cb.command_handle,
                                            CString::new("Test Source ID").unwrap().into_raw(),
                                            CString::new("Test Credential Def").unwrap().into_raw(),
                                            CString::new(SCHEMA_ID).unwrap().into_raw(),
                                            CString::new("6vkhW3L28AophhA68SSzRS").unwrap().into_raw(),
                                            CString::new("tag").unwrap().into_raw(),
                                            CString::new("{}").unwrap().into_raw(),
                                            0,
                                            Some(cb.get_callback())), error::SUCCESS.code_num);
        let handle = cb.receive(TimeoutUtils::some_medium()).unwrap();
        let cb = return_types_u32::Return_U32_STR::new().unwrap();
        assert_eq!(vcx_credentialdef_get_cred_def_id(cb.command_handle, handle, Some(cb.get_callback())), error::SUCCESS.code_num);
        cb.receive(TimeoutUtils::some_medium()).unwrap();
    }

    // TODO: Update to not use prepare_credentialdef_for_endorser if possible
    #[test]
    #[cfg(feature = "to_restore")]
    #[cfg(feature = "general_test")]
    fn test_vcx_cred_def_get_state() {
        let _setup = SetupMocks::init();

        let (handle, _, _, _) = credential_def::prepare_credentialdef_for_endorser("testid".to_string(),
                                                                                   "Test Credential Def".to_string(),
                                                                                   "6vkhW3L28AophhA68SSzRS".to_string(),
                                                                                   SCHEMA_ID.to_string(),
                                                                                   "tag".to_string(),
                                                                                   "{}".to_string(),
                                                                                   "V4SGRU86Z58d6TV7PBUe6f".to_string()).unwrap();
        {
            let cb = return_types_u32::Return_U32_U32::new().unwrap();
            let _rc = vcx_credentialdef_get_state(cb.command_handle, handle, Some(cb.get_callback()));
            assert_eq!(cb.receive(TimeoutUtils::some_medium()).unwrap(), api_lib::PublicEntityStateType::Built as u32)
        }
        {
            let cb = return_types_u32::Return_U32_U32::new().unwrap();
            let _rc = vcx_credentialdef_update_state(cb.command_handle, handle, Some(cb.get_callback()));
            assert_eq!(cb.receive(TimeoutUtils::some_medium()).unwrap(), api_lib::PublicEntityStateType::Published as u32);
        }
        {
            let cb = return_types_u32::Return_U32_U32::new().unwrap();
            let _rc = vcx_credentialdef_get_state(cb.command_handle, handle, Some(cb.get_callback()));
            assert_eq!(cb.receive(TimeoutUtils::some_medium()).unwrap(), api_lib::PublicEntityStateType::Published as u32)
        }
    }
}
