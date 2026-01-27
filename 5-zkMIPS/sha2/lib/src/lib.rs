use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct for SHA2 verification.
    struct PublicValuesStruct {
        bool all_valid;
    }
}

/// Compute SHA256 hash of a message.
pub fn sha256(message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(message);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Compute SHA256 hash of a message using the same logic as 4-zkVM version.
pub fn compute_sha256_hash(message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(message);
    let mut ret = [0u8; 32];
    ret.copy_from_slice(&hash);
    ret
}