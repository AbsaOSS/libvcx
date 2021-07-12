use std::env;
use std::path::PathBuf;

#[macro_use]
pub mod version_constants;

#[macro_use]
#[cfg(test)]
pub mod devsetup;

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! secret {
    ($val:expr) => {{ $val }};
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! secret {
    ($val:expr) => {{ "_" }};
}

#[cfg(test)]
macro_rules! map (
    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = std::collections::HashMap::new();
            $(
                m.insert($key, $value);
            )+
            m
        }
     };
);

pub mod error;
pub mod constants;
pub mod openssl;
pub mod json;
pub mod uuid;
pub mod author_agreement;
pub mod qualifier;
pub mod file;
pub mod mockdata;
pub mod provision;
pub mod random;

pub mod plugins;

#[macro_use]
pub mod logger;
pub mod validation;
pub mod serialization;

pub fn get_temp_dir_path(filename: &str) -> PathBuf {
    let mut path = env::temp_dir();
    path.push(filename);
    path
}
