use sha2::{Digest, Sha256};

pub fn derive_seed(master_seed: u64, tool: &str, iteration: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(master_seed.to_le_bytes());
    hasher.update(tool.as_bytes());
    hasher.update(iteration.to_le_bytes());
    let hash = hasher.finalize();
    u64::from_le_bytes(hash[..8].try_into().expect("seed hash length"))
}
