extern crate rust_base58;

use crate::error::prelude::*;
use crate::settings::Actors;
use crate::utils::qualifier;

use self::rust_base58::FromBase58;

pub fn validate_did(did: &str) -> VcxResult<String> {
    if qualifier::is_fully_qualified(did) {
        Ok(did.to_string())
    } else {
        //    assert len(base58.b58decode(did)) == 16
        let check_did = String::from(did);
        match check_did.from_base58() {
            Ok(ref x) if x.len() == 16 => Ok(check_did),
            Ok(_) => {
                warn!("ok(_)");
                return Err(VcxError::from_msg(VcxErrorKind::InvalidDid, "Invalid DID length"));
            }
            Err(x) => {
                warn!("Err(x)");
                return Err(VcxError::from_msg(VcxErrorKind::NotBase58, format!("Invalid DID: {}", x)));
            }
        }
    }
}

pub fn validate_verkey(verkey: &str) -> VcxResult<String> {
    let check_verkey = String::from(verkey);
    match check_verkey.from_base58() {
        Ok(ref x) if x.len() == 32 => Ok(check_verkey),
        Ok(_) => Err(VcxError::from_msg(VcxErrorKind::InvalidVerkey, "Invalid Verkey length")),
        Err(x) => Err(VcxError::from_msg(VcxErrorKind::NotBase58, format!("Invalid Verkey: {}", x))),
    }
}

pub fn validate_payment_method(payment_method: &str) -> VcxResult<()> {
    if payment_method.is_empty() {
        return Err(VcxError::from(VcxErrorKind::MissingPaymentMethod));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::utils::devsetup::SetupDefaults;

    use super::*;

    #[test]
    #[cfg(feature = "general_test")]
    fn test_did_is_b58_and_valid_length() {
        let _setup = SetupDefaults::init();

        let to_did = "8XFh8yBzrpJQmNyZzgoTqB";
        match validate_did(&to_did) {
            Err(_) => panic!("Should be valid did"),
            Ok(x) => assert_eq!(x, to_did.to_string())
        }
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_did_is_b58_but_invalid_length() {
        let _setup = SetupDefaults::init();

        let to_did = "8XFh8yBzrpJQmNyZzgoT";
        match validate_did(&to_did) {
            Err(x) => assert_eq!(x.kind(), VcxErrorKind::InvalidDid),
            Ok(_) => panic!("Should be invalid did"),
        }
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_validate_did_with_non_base58() {
        let _setup = SetupDefaults::init();

        let to_did = "8*Fh8yBzrpJQmNyZzgoTqB";
        match validate_did(&to_did) {
            Err(x) => assert_eq!(x.kind(), VcxErrorKind::NotBase58),
            Ok(_) => panic!("Should be invalid did"),
        }
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_verkey_is_b58_and_valid_length() {
        let _setup = SetupDefaults::init();

        let verkey = "EkVTa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A";
        match validate_verkey(&verkey) {
            Err(_) => panic!("Should be valid verkey"),
            Ok(x) => assert_eq!(x, verkey)
        }
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_verkey_is_b58_but_invalid_length() {
        let _setup = SetupDefaults::init();

        let verkey = "8XFh8yBzrpJQmNyZzgoT";
        match validate_verkey(&verkey) {
            Err(x) => assert_eq!(x.kind(), VcxErrorKind::InvalidVerkey),
            Ok(_) => panic!("Should be invalid verkey"),
        }
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_validate_verkey_with_non_base58() {
        let _setup = SetupDefaults::init();

        let verkey = "*kVTa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A";
        match validate_verkey(&verkey) {
            Err(x) => assert_eq!(x.kind(), VcxErrorKind::NotBase58),
            Ok(_) => panic!("Should be invalid verkey"),
        }
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_payment_plugin_validation() {
        let _setup = SetupDefaults::init();

        validate_payment_method("null").unwrap();
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_payment_plugin_validation_empty_string() {
        let _setup = SetupDefaults::init();

        assert_eq!(validate_payment_method("").unwrap_err().kind(), VcxErrorKind::MissingPaymentMethod);
    }
}
