pub mod client;
pub mod finding;
pub mod target;

#[cfg(test)]
mod tests {
    #[test]
    fn core_crate_loads() {
        assert_eq!(env!("CARGO_PKG_NAME"), "wallfacer-core");
    }
}
