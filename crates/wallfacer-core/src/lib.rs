// Phase A introduces `missing_docs = "warn"` so future modules grow rustdoc.
// Existing 0.1 surface is undocumented; allowing here keeps the warning useful
// for new code. To be lifted progressively in Phase B/C.
#![allow(missing_docs)]

pub mod client;
pub mod corpus;
pub mod coverage;
pub mod differential;
pub mod finding;
pub mod fuzz_corpus;
pub mod mutate;
pub mod property;
pub mod redact;
pub mod report;
pub mod run;
pub mod sarif;
pub mod seed;
pub mod shrink;
pub mod suggest;
pub mod target;

#[cfg(test)]
mod tests {
    #[test]
    fn core_crate_loads() {
        assert_eq!(env!("CARGO_PKG_NAME"), "wallfacer-core");
    }
}
