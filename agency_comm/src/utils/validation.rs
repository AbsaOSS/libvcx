extern crate rust_base58;

use regex::Regex;
use url::Url;
use self::rust_base58::FromBase58;

use crate::utils::error::{AgencyCommErrorKind, AgencyCommError, VcxResult};

lazy_static! {
    pub static ref REGEX: Regex = Regex::new("did:([a-z0-9]+):([a-zA-Z0-9:.-_]*)").unwrap();
}

pub fn is_fully_qualified(entity: &str) -> bool {
    REGEX.is_match(&entity)
}

pub fn validate_did(did: &str) -> VcxResult<String> {
    if is_fully_qualified(did) {
        Ok(did.to_string())
    } else {
        let check_did = String::from(did);
        match check_did.from_base58() {
            Ok(ref x) if x.len() == 16 => Ok(check_did),
            Ok(_) => {
                warn!("ok(_)");
                return Err(AgencyCommError::from_msg(AgencyCommErrorKind::InvalidDid, "Invalid DID length"));
            }
            Err(x) => {
                warn!("Err(x)");
                return Err(AgencyCommError::from_msg(AgencyCommErrorKind::NotBase58, format!("Invalid DID: {}", x)));
            }
        }
    }
}

pub fn validate_verkey(verkey: &str) -> VcxResult<String> {
    let check_verkey = String::from(verkey);
    match check_verkey.from_base58() {
        Ok(ref x) if x.len() == 32 => Ok(check_verkey),
        Ok(_) => Err(AgencyCommError::from_msg(AgencyCommErrorKind::InvalidVerkey, "Invalid Verkey length")),
        Err(x) => Err(AgencyCommError::from_msg(AgencyCommErrorKind::NotBase58, format!("Invalid Verkey: {}", x))),
    }
}

pub fn validate_url(url: &str) -> VcxResult<String> {
    Url::parse(url)
        .map_err(|err| AgencyCommError::from_msg(AgencyCommErrorKind::InvalidUrl, err))?;
    Ok(url.to_string())
}

#[cfg(test)]
mod tests {
    // use utils::devsetup::SetupDefaults;

    use super::*;
    use crate::utils::error::AgencyCommErrorKind;

    #[test]
    #[cfg(feature = "general_test")]
    fn test_did_is_b58_and_valid_length() {
        let to_did = "8XFh8yBzrpJQmNyZzgoTqB";
        match validate_did(&to_did) {
            Err(_) => panic!("Should be valid did"),
            Ok(x) => assert_eq!(x, to_did.to_string())
        }
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_did_is_b58_but_invalid_length() {
        let to_did = "8XFh8yBzrpJQmNyZzgoT";
        match validate_did(&to_did) {
            Err(x) => assert_eq!(x.kind(), AgencyCommErrorKind::InvalidDid),
            Ok(_) => panic!("Should be invalid did"),
        }
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_validate_did_with_non_base58() {
        let to_did = "8*Fh8yBzrpJQmNyZzgoTqB";
        match validate_did(&to_did) {
            Err(x) => assert_eq!(x.kind(), AgencyCommErrorKind::NotBase58),
            Ok(_) => panic!("Should be invalid did"),
        }
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_verkey_is_b58_and_valid_length() {
        let verkey = "EkVTa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A";
        match validate_verkey(&verkey) {
            Err(_) => panic!("Should be valid verkey"),
            Ok(x) => assert_eq!(x, verkey)
        }
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_verkey_is_b58_but_invalid_length() {
        let verkey = "8XFh8yBzrpJQmNyZzgoT";
        match validate_verkey(&verkey) {
            Err(x) => assert_eq!(x.kind(), AgencyCommErrorKind::InvalidVerkey),
            Ok(_) => panic!("Should be invalid verkey"),
        }
    }

    #[test]
    #[cfg(feature = "general_test")]
    fn test_validate_verkey_with_non_base58() {
        let verkey = "*kVTa7SCJ5SntpYyX7CSb2pcBhiVGT9kWSagA8a9T69A";
        match validate_verkey(&verkey) {
            Err(x) => assert_eq!(x.kind(), AgencyCommErrorKind::NotBase58),
            Ok(_) => panic!("Should be invalid verkey"),
        }
    }
}
