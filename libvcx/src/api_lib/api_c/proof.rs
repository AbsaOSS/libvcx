use std::ptr;

use indy_sys::CommandHandle;
use libc::c_char;

use crate::api_lib::api_handle::connection;
use crate::api_lib::api_handle::proof;
use crate::api_lib::utils_c::cstring::CStringUtils;
use crate::api_lib::utils_c::runtime::execute;
use crate::error::prelude::*;
use crate::utils::error;

/*
    APIs in this module are called by a verifier throughout the request-proof-and-verify process.
    Assumes that pairwise connection between Verifier and Prover is already established.

    # State

    The set of object states, messages and transitions depends on the communication method is used.
    The communication method can be specified as a config option on one of *_init functions.

    aries:
        VcxStateType::VcxStateInitialized - once `vcx_proof_create` (create Proof object) is called.

        VcxStateType::VcxStateOfferSent - once `vcx_credential_send_request` (send `PresentationRequest` message) is called.

        VcxStateType::VcxStateAccepted - once `Presentation` messages is received.
        VcxStateType::None - once `ProblemReport` messages is received.
        VcxStateType::None - once `PresentationProposal` messages is received.
        VcxStateType::None - on `Presentation` validation failed.
                                                use `vcx_proof_update_state` or `vcx_proof_update_state_with_message` functions for state updates.

    # Transitions

    aries: RFC - https://github.com/hyperledger/aries-rfcs/tree/7b6b93acbaf9611d3c892c4bada142fe2613de6e/features/0037-present-proof#propose-presentation
        VcxStateType::None - `vcx_proof_create` - VcxStateType::VcxStateInitialized

        VcxStateType::VcxStateInitialized - `vcx_credential_send_request` - VcxStateType::VcxStateOfferSent

        VcxStateType::VcxStateOfferSent - received `Presentation` - VcxStateType::VcxStateAccepted
        VcxStateType::VcxStateOfferSent - received `PresentationProposal` - VcxStateType::None
        VcxStateType::VcxStateOfferSent - received `ProblemReport` - VcxStateType::None

    # Messages

    aries:
        PresentationRequest - https://github.com/hyperledger/aries-rfcs/tree/7b6b93acbaf9611d3c892c4bada142fe2613de6e/features/0037-present-proof#request-presentation
        Presentation - https://github.com/hyperledger/aries-rfcs/tree/7b6b93acbaf9611d3c892c4bada142fe2613de6e/features/0037-present-proof#presentation
        PresentationProposal - https://github.com/hyperledger/aries-rfcs/tree/7b6b93acbaf9611d3c892c4bada142fe2613de6e/features/0037-present-proof#propose-presentation
        Ack - https://github.com/hyperledger/aries-rfcs/tree/master/features/0015-acks#explicit-acks
*/

/// Create a new Proof object that requests a proof for an enterprise
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// source_id: Enterprise's personal identification for the user.
///
/// requested_attrs: Describes requested attribute
///     {
///         "name": Optional<string>, // attribute name, (case insensitive and ignore spaces)
///         "names": Optional<[string, string]>, // attribute names, (case insensitive and ignore spaces)
///                                              // NOTE: should either be "name" or "names", not both and not none of them.
///                                              // Use "names" to specify several attributes that have to match a single credential.
///         "restrictions":  Optional<wql query> - set of restrictions applying to requested credentials. (see below)
///         "non_revoked": {
///             "from": Optional<(u64)> Requested time represented as a total number of seconds from Unix Epoch, Optional
///             "to": Optional<(u64)>
///                 //Requested time represented as a total number of seconds from Unix Epoch, Optional
///         }
///     }
///
/// # Example requested_attrs -> "[{"name":"attrName","restrictions":["issuer_did":"did","schema_id":"id","schema_issuer_did":"did","schema_name":"name","schema_version":"1.1.1","cred_def_id":"id"}]]"
///
/// requested_predicates: predicate specifications prover must provide claim for
///          { // set of requested predicates
///             "name": attribute name, (case insensitive and ignore spaces)
///             "p_type": predicate type (Currently ">=" only)
///             "p_value": int predicate value
///             "restrictions":  Optional<wql query> -  set of restrictions applying to requested credentials. (see below)
///             "non_revoked": Optional<{
///                 "from": Optional<(u64)> Requested time represented as a total number of seconds from Unix Epoch, Optional
///                 "to": Optional<(u64)> Requested time represented as a total number of seconds from Unix Epoch, Optional
///             }>
///          },
///
/// # Example requested_predicates -> "[{"name":"attrName","p_type":"GE","p_value":9,"restrictions":["issuer_did":"did","schema_id":"id","schema_issuer_did":"did","schema_name":"name","schema_version":"1.1.1","cred_def_id":"id"}]]"
///
/// revocation_interval:  Optional<<revocation_interval>>, // see below,
///                        // If specified, prover must proof non-revocation
///                        // for date in this interval for each attribute
///                        // (can be overridden on attribute level)
///     from: Optional<u64> // timestamp of interval beginning
///     to: Optional<u64> // timestamp of interval beginning
///         // Requested time represented as a total number of seconds from Unix Epoch, Optional
/// # Examples config ->  "{}" | "{"to": 123} | "{"from": 100, "to": 123}"
///
/// wql query: indy-sdk/docs/design/011-wallet-query-language/README.md
///     The list of allowed keys that can be combine into complex queries.
///         "schema_id": <credential schema id>,
///         "schema_issuer_did": <credential schema issuer did>,
///         "schema_name": <credential schema name>,
///         "schema_version": <credential schema version>,
///         "issuer_did": <credential issuer did>,
///         "cred_def_id": <credential definition id>,
///         "rev_reg_id": <credential revocation registry id>, // "None" as string if not present
///         // the following keys can be used for every `attribute name` in credential.
///         "attr::<attribute name>::marker": "1", - to filter based on existence of a specific attribute
///         "attr::<attribute name>::value": <attribute raw value>, - to filter based on value of a specific attribute
///
/// cb: Callback that provides proof handle and error status of request.
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_proof_create(command_handle: CommandHandle,
                               source_id: *const c_char,
                               requested_attrs: *const c_char,
                               requested_predicates: *const c_char,
                               revocation_interval: *const c_char,
                               name: *const c_char,
                               cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, proof_handle: u32)>) -> u32 {
    info!("vcx_proof_create >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);
    check_useful_c_str!(requested_attrs, VcxErrorKind::InvalidOption);
    check_useful_c_str!(requested_predicates, VcxErrorKind::InvalidOption);
    check_useful_c_str!(name, VcxErrorKind::InvalidOption);
    check_useful_c_str!(source_id, VcxErrorKind::InvalidOption);
    check_useful_c_str!(revocation_interval, VcxErrorKind::InvalidOption);

    trace!("vcx_proof_create(command_handle: {}, source_id: {}, requested_attrs: {}, requested_predicates: {}, revocation_interval: {}, name: {})",
           command_handle, source_id, requested_attrs, requested_predicates, revocation_interval, name);

    execute(move || {
        let (rc, handle) = match proof::create_proof(source_id, requested_attrs, requested_predicates, revocation_interval, name) {
            Ok(x) => {
                trace!("vcx_proof_create_cb(command_handle: {}, rc: {}, handle: {}) source_id: {}",
                       command_handle, error::SUCCESS.message, x, proof::get_source_id(x).unwrap_or_default());
                (error::SUCCESS.code_num, x)
            }
            Err(x) => {
                warn!("vcx_proof_create_cb(command_handle: {}, rc: {}, handle: {}) source_id: {}",
                      command_handle, x, 0, x);
                (x.into(), 0)
            }
        };
        cb(command_handle, rc, handle);

        Ok(())
    });

    error::SUCCESS.code_num
}

/// Query the agency for the received messages.
/// Checks for any messages changing state in the object and updates the state attribute.
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// proof_handle: Proof handle that was provided during creation. Used to access proof object
///
/// connection_handle: Connection handle of the proof interaction is associated with.
///
/// cb: Callback that provides most current state of the proof and error status of request
///     States:
///         1 - Initialized
///         2 - Request Sent
///         3 - Proof Received
///         4 - Accepted
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_v2_proof_update_state(command_handle: CommandHandle,
                                        proof_handle: u32,
                                        connection_handle: u32,
                                        cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, state: u32)>) -> u32 {
    info!("vcx_v2_proof_update_state >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = proof::get_source_id(proof_handle).unwrap_or_default();
    trace!("vcx_v2_proof_update_state(command_handle: {}, proof_handle: {}, connection_handle: {}) source_id: {}",
           command_handle, proof_handle, connection_handle, source_id);

    if !proof::is_valid_handle(proof_handle) {
        return VcxError::from(VcxErrorKind::InvalidProofHandle).into();
    }

    if !connection::is_valid_handle(connection_handle) {
        return VcxError::from(VcxErrorKind::InvalidConnectionHandle).into();
    }

    execute(move || {
        match proof::update_state(proof_handle, None, connection_handle) {
            Ok(x) => {
                trace!("vcx_v2_proof_update_state_cb(command_handle: {}, rc: {}, proof_handle: {}, state: {}) source_id: {}",
                       command_handle, error::SUCCESS.message, proof_handle, x, source_id);
                cb(command_handle, error::SUCCESS.code_num, x);
            }
            Err(x) => {
                error!("vcx_v2_proof_update_state_cb(command_handle: {}, rc: {}, proof_handle: {}, state: {}) source_id: {}",
                       command_handle, x, proof_handle, 0, source_id);
                cb(command_handle, x.into(), 0);
            }
        }

        Ok(())
    });

    error::SUCCESS.code_num
}

/// Update the state of the proof based on the given message.
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// proof_handle: Proof handle that was provided during creation. Used to access proof object
///
/// connection_handle: Connection handle of connection associated with this proof exchange interaction.
///
/// message: message to process for state changes
///
/// cb: Callback that provides most current state of the proof and error status of request
///     States:
///         1 - Initialized
///         2 - Request Sent
///         3 - Proof Received
///         4 - Accepted
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_v2_proof_update_state_with_message(command_handle: CommandHandle,
                                                     proof_handle: u32,
                                                     connection_handle: u32,
                                                     message: *const c_char,
                                                     cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, state: u32)>) -> u32 {
    info!("vcx_v2_proof_update_state_with_message >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);
    check_useful_c_str!(message, VcxErrorKind::InvalidOption);

    let source_id = proof::get_source_id(proof_handle).unwrap_or_default();
    trace!("vcx_v2_proof_update_state_with_message(command_handle: {}, proof_handle: {}) source_id: {}",
           command_handle, proof_handle, source_id);

    if !proof::is_valid_handle(proof_handle) {
        return VcxError::from(VcxErrorKind::InvalidProofHandle).into();
    }

    if !connection::is_valid_handle(connection_handle) {
        return VcxError::from(VcxErrorKind::InvalidConnectionHandle).into();
    }

    execute(move || {
        match proof::update_state(proof_handle, Some(&message), connection_handle) {
            Ok(x) => {
                trace!("vcx_v2_proof_update_state_with_message_cb(command_handle: {}, rc: {}, proof_handle: {}, state: {}) source_id: {}",
                       command_handle, error::SUCCESS.message, proof_handle, x, source_id);
                cb(command_handle, error::SUCCESS.code_num, x);
            }
            Err(x) => {
                warn!("vcx_v2_proof_update_state_with_message_cb(command_handle: {}, rc: {}, proof_handle: {}, state: {}) source_id: {}",
                      command_handle, x, proof_handle, 0, source_id);
                cb(command_handle, x.into(), 0);
            }
        }

        Ok(())
    });

    error::SUCCESS.code_num
}

/// Get the current state of the proof object
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// proof_handle: Proof handle that was provided during creation. Used to access proof object
///
/// cb: Callback that provides most current state of the proof and error status of request
///     States:
///         1 - Initialized
///         2 - Request Sent
///         3 - Proof Received
///         4 - Accepted
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_proof_get_state(command_handle: CommandHandle,
                                  proof_handle: u32,
                                  cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, state: u32)>) -> u32 {
    info!("vcx_proof_get_state >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = proof::get_source_id(proof_handle).unwrap_or_default();
    trace!("vcx_proof_get_state(command_handle: {}, proof_handle: {}), source_id: {}",
           command_handle, proof_handle, source_id);

    if !proof::is_valid_handle(proof_handle) {
        return VcxError::from(VcxErrorKind::InvalidProofHandle).into();
    }

    execute(move || {
        match proof::get_state(proof_handle) {
            Ok(x) => {
                trace!("vcx_proof_get_state_cb(command_handle: {}, rc: {}, proof_handle: {}, state: {}) source_id: {}",
                       command_handle, error::SUCCESS.message, proof_handle, x, source_id);
                cb(command_handle, error::SUCCESS.code_num, x);
            }
            Err(x) => {
                warn!("vcx_proof_get_state_cb(command_handle: {}, rc: {}, proof_handle: {}, state: {}) source_id: {}",
                      command_handle, x, proof_handle, 0, source_id);
                cb(command_handle, x.into(), 0);
            }
        }

        Ok(())
    });

    error::SUCCESS.code_num
}

/// Takes the proof object and returns a json string of all its attributes
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// proof_handle: Proof handle that was provided during creation. Used to access proof object
///
/// cb: Callback that provides json string of the proof's attributes and provides error status
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_proof_serialize(command_handle: CommandHandle,
                                  proof_handle: u32,
                                  cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, proof_state: *const c_char)>) -> u32 {
    info!("vcx_proof_serialize >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = proof::get_source_id(proof_handle).unwrap_or_default();
    trace!("vcx_proof_serialize(command_handle: {}, proof_handle: {}) source_id: {}", command_handle, proof_handle, source_id);

    if !proof::is_valid_handle(proof_handle) {
        return VcxError::from(VcxErrorKind::InvalidProofHandle).into();
    };

    execute(move || {
        match proof::to_string(proof_handle) {
            Ok(x) => {
                trace!("vcx_proof_serialize_cb(command_handle: {}, proof_handle: {}, rc: {}, state: {}) source_id: {}",
                       command_handle, proof_handle, error::SUCCESS.message, x, source_id);
                let msg = CStringUtils::string_to_cstring(x);
                cb(command_handle, error::SUCCESS.code_num, msg.as_ptr());
            }
            Err(x) => {
                warn!("vcx_proof_serialize_cb(command_handle: {}, proof_handle: {}, rc: {}, state: {}) source_id: {}",
                      command_handle, proof_handle, x, "null", source_id);
                cb(command_handle, x.into(), ptr::null_mut());
            }
        };

        Ok(())
    });

    error::SUCCESS.code_num
}

/// Takes a json string representing a proof object and recreates an object matching the json
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// proof_data: json string representing a proof object
///
/// cb: Callback that provides proof handle and provides error status
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_proof_deserialize(command_handle: CommandHandle,
                                    proof_data: *const c_char,
                                    cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, proof_handle: u32)>) -> u32 {
    info!("vcx_proof_deserialize >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);
    check_useful_c_str!(proof_data, VcxErrorKind::InvalidOption);

    trace!("vcx_proof_deserialize(command_handle: {}, proof_data: {})",
           command_handle, proof_data);

    execute(move || {
        let (rc, handle) = match proof::from_string(&proof_data) {
            Ok(x) => {
                trace!("vcx_proof_deserialize_cb(command_handle: {}, rc: {}, handle: {}) source_id: {}",
                       command_handle, error::SUCCESS.message, x, proof::get_source_id(x).unwrap_or_default());
                (error::SUCCESS.code_num, x)
            }
            Err(x) => {
                warn!("vcx_proof_deserialize_cb(command_handle: {}, rc: {}, handle: {}) source_id: {}",
                      command_handle, x, 0, "");
                (x.into(), 0)
            }
        };
        cb(command_handle, rc, handle);

        Ok(())
    });

    error::SUCCESS.code_num
}

/// Releases the proof object by de-allocating memory
///
/// #Params
/// proof_handle: Proof handle that was provided during creation. Used to access proof object
///
/// #Returns
/// Success
#[no_mangle]
pub extern fn vcx_proof_release(proof_handle: u32) -> u32 {
    info!("vcx_proof_release >>>");

    let source_id = proof::get_source_id(proof_handle).unwrap_or_default();
    match proof::release(proof_handle) {
        Ok(()) => {
            trace!("vcx_proof_release(proof_handle: {}, rc: {}), source_id: {}",
                   proof_handle, error::SUCCESS.message, source_id);
            error::SUCCESS.code_num
        }
        Err(e) => {
            warn!("vcx_proof_release(proof_handle: {}, rc: {}), source_id: {}",
                  proof_handle, e, source_id);
            e.into()
        }
    }
}

/// Sends a proof request to pairwise connection
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// proof_handle: Proof handle that was provided during creation. Used to access proof object
///
/// connection_handle: Connection handle that identifies pairwise connection
///
/// cb: provides any error status of the proof_request
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_proof_send_request(command_handle: CommandHandle,
                                     proof_handle: u32,
                                     connection_handle: u32,
                                     cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32)>) -> u32 {
    info!("vcx_proof_send_request >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = proof::get_source_id(proof_handle).unwrap_or_default();
    trace!("vcx_proof_send_request(command_handle: {}, proof_handle: {}, connection_handle: {}) source_id: {}",
           command_handle, proof_handle, connection_handle, source_id);
    if !proof::is_valid_handle(proof_handle) {
        return VcxError::from(VcxErrorKind::InvalidProofHandle).into();
    }

    if !connection::is_valid_handle(connection_handle) {
        return VcxError::from(VcxErrorKind::InvalidConnectionHandle).into();
    }

    execute(move || {
        let err = match proof::send_proof_request(proof_handle, connection_handle, None) {
            Ok(x) => {
                trace!("vcx_proof_send_request_cb(command_handle: {}, rc: {}, proof_handle: {}) source_id: {}",
                       command_handle, 0, proof_handle, source_id);
                x
            }
            Err(x) => {
                warn!("vcx_proof_send_request_cb(command_handle: {}, rc: {}, proof_handle: {}) source_id: {}",
                      command_handle, x, proof_handle, source_id);
                x.into()
            }
        };

        cb(command_handle, err);

        Ok(())
    });

    error::SUCCESS.code_num
}


/// Get the proof request message that can be sent to the specified connection
///
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// proof_handle: Proof handle that was provided during creation. Used to access proof object
///
/// cb: provides any error status of the proof_request
///
/// # Example proof_request -> "{'@topic': {'tid': 0, 'mid': 0}, '@type': {'version': '1.0', 'name': 'PROOF_REQUEST'}, 'proof_request_data': {'name': 'proof_req', 'nonce': '118065925949165739229152', 'version': '0.1', 'requested_predicates': {}, 'non_revoked': None, 'requested_attributes': {'attribute_0': {'name': 'name', 'restrictions': {'$or': [{'issuer_did': 'did'}]}}}, 'ver': '1.0'}, 'thread_id': '40bdb5b2'}"
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_proof_get_request_msg(command_handle: CommandHandle,
                                        proof_handle: u32,
                                        cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, msg: *const c_char)>) -> u32 {
    info!("vcx_proof_get_request_msg >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = proof::get_source_id(proof_handle).unwrap_or_default();
    trace!("vcx_proof_get_request_msg(command_handle: {}, proof_handle: {}) source_id: {}",
           command_handle, proof_handle, source_id);
    if !proof::is_valid_handle(proof_handle) {
        return VcxError::from(VcxErrorKind::InvalidProofHandle).into();
    }

    execute(move || {
        match proof::generate_proof_request_msg(proof_handle) {
            Ok(msg) => {
                let msg = CStringUtils::string_to_cstring(msg);
                trace!("vcx_proof_get_request_msg_cb(command_handle: {}, rc: {}, proof_handle: {}) source_id: {}",
                       command_handle, error::SUCCESS.code_num, proof_handle, source_id);
                cb(command_handle, error::SUCCESS.code_num, msg.as_ptr());
            }
            Err(x) => {
                warn!("vcx_proof_get_request_msg_cb(command_handle: {}, rc: {}, proof_handle: {}) source_id: {}",
                      command_handle, x, proof_handle, source_id);
                cb(command_handle, x.into(), ptr::null_mut())
            }
        };


        Ok(())
    });

    error::SUCCESS.code_num
}


/// Get Proof Msg
///
/// *Note* This replaces vcx_get_proof. You no longer need a connection handle.
/// #Params
/// command_handle: command handle to map callback to user context.
///
/// proof_handle: Proof handle that was provided during creation. Used to identify proof object
///
/// cb: Callback that provides Proof attributes and error status of sending the credential
///
/// #Returns
/// Error code as a u32
#[no_mangle]
pub extern fn vcx_get_proof_msg(command_handle: CommandHandle,
                                proof_handle: u32,
                                cb: Option<extern fn(xcommand_handle: CommandHandle, err: u32, proof_state: u32, response_data: *const c_char)>) -> u32 {
    info!("vcx_get_proof_msg >>>");

    check_useful_c_callback!(cb, VcxErrorKind::InvalidOption);

    let source_id = proof::get_source_id(proof_handle).unwrap_or_default();
    trace!("vcx_get_proof_msg(command_handle: {}, proof_handle: {}) source_id: {}",
           command_handle, proof_handle, source_id);

    if !proof::is_valid_handle(proof_handle) {
        return VcxError::from(VcxErrorKind::InvalidProofHandle).into();
    }

    execute(move || {
        let source_id = proof::get_source_id(proof_handle).unwrap_or_default();

        match proof::get_proof(proof_handle) {
            Ok(proof_msg) => {
                trace!("vcx_get_proof_cb(command_handle: {}, proof_handle: {}, rc: {}, proof: {}) source_id: {}", command_handle, proof_handle, 0, proof_msg, source_id);
                let msg = CStringUtils::string_to_cstring(proof_msg);
                cb(command_handle, error::SUCCESS.code_num, proof::get_proof_state(proof_handle).unwrap_or(0), msg.as_ptr());
            }
            Err(err) => {
                warn!("vcx_get_proof_cb(command_handle: {}, proof_handle: {}, rc: {}, proof: {}) source_id: {}", command_handle, proof_handle, err, "null", source_id);
                cb(command_handle, err.into(), proof::get_proof_state(proof_handle).unwrap_or(0), ptr::null_mut());
            }
        };
        Ok(())
    });

    error::SUCCESS.code_num
}

#[allow(unused_variables)]
pub extern fn vcx_proof_accepted(proof_handle: u32, response_data: *const c_char) -> u32 {
    info!("vcx_proof_accepted >>>");
    error::SUCCESS.code_num
}


#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr;
    use std::str;

    use crate::api_lib::{ProofStateType, VcxStateType};
    use crate::api_lib::api_handle::connection::tests::build_test_connection_inviter_requested;
    use crate::api_lib::api_handle::proof;
    use crate::api_lib::utils_c::return_types_u32;
    use crate::api_lib::utils_c::timeout::TimeoutUtils;
    use crate::utils::constants::*;
    use crate::utils::devsetup::*;
    use crate::utils::mockdata::mock_settings::MockBuilder;
    use crate::utils::mockdata::mockdata_proof;
    use crate::aries::handlers::proof_presentation::verifier::verifier::VerifierState;

    use super::*;

    static DEFAULT_PROOF_NAME: &'static str = "PROOF_NAME";

    fn create_proof_util() -> Result<u32, u32> {
        let cb = return_types_u32::Return_U32_U32::new().unwrap();
        let rc = vcx_proof_create(cb.command_handle,
                                  CString::new(DEFAULT_PROOF_NAME).unwrap().into_raw(),
                                  CString::new(REQUESTED_ATTRS).unwrap().into_raw(),
                                  CString::new(REQUESTED_PREDICATES).unwrap().into_raw(),
                                  CString::new(r#"{"support_revocation":false}"#).unwrap().into_raw(),
                                  CString::new("optional").unwrap().into_raw(),
                                  Some(cb.get_callback()));
        if rc != error::SUCCESS.code_num {
            return Err(rc);
        }
        cb.receive(TimeoutUtils::some_medium())
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_create_proof_success() {
        let _setup = SetupMocks::init();

        let handle = create_proof_util().unwrap();
        assert!(handle > 0);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_create_proof_fails() {
        let _setup = SetupMocks::init();

        let cb = return_types_u32::Return_U32_U32::new().unwrap();
        assert_eq!(vcx_proof_create(cb.command_handle,
                                    ptr::null(),
                                    ptr::null(),
                                    ptr::null(),
                                    CString::new(r#"{"support_revocation":false}"#).unwrap().into_raw(),
                                    ptr::null(),
                                    None),
                   error::INVALID_OPTION.code_num);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_proof_get_request_msg() {
        let _setup = SetupMocks::init();

        let proof_handle = create_proof_util().unwrap();

        let cb = return_types_u32::Return_U32_STR::new().unwrap();
        assert_eq!(vcx_proof_get_request_msg(cb.command_handle, proof_handle, Some(cb.get_callback())),
                   error::SUCCESS.code_num);
        let _msg = cb.receive(TimeoutUtils::some_medium()).unwrap().unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_proof_serialize() {
        let _setup = SetupMocks::init();

        let proof_handle = create_proof_util().unwrap();

        let cb = return_types_u32::Return_U32_STR::new().unwrap();
        assert_eq!(vcx_proof_serialize(cb.command_handle,
                                       proof_handle,
                                       Some(cb.get_callback())),
                   error::SUCCESS.code_num);
        let _ser = cb.receive(TimeoutUtils::some_medium()).unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_proof_deserialize_succeeds() {
        let _setup = SetupMocks::init();

        let cb = return_types_u32::Return_U32_U32::new().unwrap();
        assert_eq!(vcx_proof_deserialize(cb.command_handle,
                                         CString::new(mockdata_proof::SERIALIZIED_PROOF_INITIATED).unwrap().into_raw(),
                                         Some(cb.get_callback())),
                   error::SUCCESS.code_num);
        let handle = cb.receive(TimeoutUtils::some_medium()).unwrap();
        assert!(handle > 0);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_proof_update_state() {
        let _setup = SetupMocks::init();

        let connection_handle = build_test_connection_inviter_requested();
        let proof_handle = create_proof_util().unwrap();

        let cb = return_types_u32::Return_U32_U32::new().unwrap();
        assert_eq!(vcx_v2_proof_update_state(cb.command_handle,
                                             proof_handle,
                                             connection_handle,
                                             Some(cb.get_callback())),
                   error::SUCCESS.code_num);
        let state = cb.receive(TimeoutUtils::some_medium()).unwrap();
        assert_eq!(state, VerifierState::Initial as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_proof_send_request() {
        let _setup = SetupMocks::init();
        let _mock_builder = MockBuilder::init().
            set_mock_result_for_validate_indy_proof(Ok(true));

        let proof_handle = create_proof_util().unwrap();

        assert_eq!(proof::get_state(proof_handle).unwrap(), VerifierState::Initial as u32);

        let connection_handle = build_test_connection_inviter_requested();

        let cb = return_types_u32::Return_U32::new().unwrap();
        assert_eq!(vcx_proof_send_request(cb.command_handle,
                                          proof_handle,
                                          connection_handle,
                                          Some(cb.get_callback())),
                   error::SUCCESS.code_num);
        cb.receive(TimeoutUtils::some_medium()).unwrap();

        assert_eq!(proof::get_state(proof_handle).unwrap(), VerifierState::PresentationRequestSent as u32);

        let cb = return_types_u32::Return_U32_U32::new().unwrap();
        assert_eq!(vcx_v2_proof_update_state_with_message(cb.command_handle,
                                                          proof_handle,
                                                          connection_handle,
                                                          CString::new(mockdata_proof::ARIES_PROOF_PRESENTATION).unwrap().into_raw(),
                                                          Some(cb.get_callback())),
                   error::SUCCESS.code_num);
        let _state = cb.receive(TimeoutUtils::some_medium()).unwrap();

        assert_eq!(proof::get_state(proof_handle).unwrap(), VerifierState::Finished as u32);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_get_proof_fails_when_not_ready_with_proof() {
        let _setup = SetupMocks::init();

        let proof_handle = create_proof_util().unwrap();

        let cb = return_types_u32::Return_U32_U32_STR::new().unwrap();
        assert_eq!(vcx_get_proof_msg(cb.command_handle,
                                     proof_handle,
                                     Some(cb.get_callback())),
                   error::SUCCESS.code_num);
        let _ = cb.receive(TimeoutUtils::some_medium()).is_err();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_get_proof_returns_proof_with_proof_state_invalid() {
        let _setup = SetupMocks::init();

        let proof_handle = proof::from_string(mockdata_proof::SERIALIZIED_PROOF_REVOKED).unwrap();

        let cb = return_types_u32::Return_U32_U32_STR::new().unwrap();
        assert_eq!(vcx_get_proof_msg(cb.command_handle,
                                     proof_handle,
                                     Some(cb.get_callback())),
                   error::SUCCESS.code_num);
        let (state, _) = cb.receive(TimeoutUtils::some_medium()).unwrap();
        assert_eq!(state, ProofStateType::ProofInvalid as u32);

        vcx_proof_release(proof_handle);
        assert_eq!(vcx_proof_release(proof_handle), error::INVALID_PROOF_HANDLE.code_num);
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_vcx_connection_get_state() {
        let _setup = SetupMocks::init();

        let cb = return_types_u32::Return_U32_U32::new().unwrap();
        let handle = proof::from_string(mockdata_proof::SERIALIZIED_PROOF_PRESENTATION_REQUEST_SENT).unwrap();

        let rc = vcx_proof_get_state(cb.command_handle, handle, Some(cb.get_callback()));
        assert_eq!(rc, error::SUCCESS.code_num);
        let state = cb.receive(TimeoutUtils::some_short()).unwrap();
        assert_eq!(state, VerifierState::PresentationRequestSent as u32);
    }
}
