#[macro_use]
pub mod handlers;
pub mod messages;
pub mod utils;

#[cfg(test)]
pub mod test {
    pub fn source_id() -> String {
        String::from("test source id")
    }
}
