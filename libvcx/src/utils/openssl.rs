use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::error::prelude::*;

pub fn encode(s: &str) -> VcxResult<String> {
    match s.parse::<u32>() {
        Ok(val) => Ok(val.to_string()),
        Err(_) => {
            let mut hasher = Sha256::new();
            hasher.update(s.as_bytes());
            let hash = hasher.finalize();
            let bignum = BigUint::from_bytes_be(&hash.as_slice());
            let encoded = bignum.to_str_radix(10);
            Ok(encoded)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "general_test")]
    fn test_encoding() {
        // number
        {
            let value = "1234";
            let expected_value = value;

            let encoded_value = encode(value).unwrap();
            assert_eq!(expected_value, encoded_value);
        }

        // number with leading zero
        {
            let value = "01234";
            let expected_value = "1234";

            let encoded_value = encode(value).unwrap();
            assert_eq!(expected_value, encoded_value);
        }

        // string
        {
            let value = "Cat";
            let expected_value = "32770349619296211525721019403974704547883091481854305319049714074652726739013";

            let encoded_value = encode(value).unwrap();
            assert_eq!(expected_value, encoded_value);
        }
    }
}