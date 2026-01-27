use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct for SHA3 verification.
    struct PublicValuesStruct {
        bool all_valid;
    }
}

/// Compute SHA3-256 hash of a message.
pub fn sha3_256(message: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let hash = Sha3_256::digest(message);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

#[cfg(feature = "host")]
use zkm_sdk::HashableKey;

#[cfg(feature = "host")]
pub struct SerializedProof {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
    pub vk_bytes: Vec<u8>,
}

#[cfg(feature = "host")]
pub fn serialize_stark_proof(
    proof: &zkm_sdk::ZKMProofWithPublicValues,
    vk: &zkm_sdk::ZKMVerifyingKey,
) -> SerializedProof {
    let vk_bytes = bincode::serialize(vk).expect("序列化vk失败");
    SerializedProof {
        proof: proof.bytes().to_vec(),
        public_values: proof.public_values.to_vec(),
        vk_bytes,
    }
}

#[cfg(feature = "host")]
pub fn serialize_plonk_proof(
    proof: &zkm_sdk::ZKMProofWithPublicValues,
    vk: &zkm_sdk::ZKMVerifyingKey,
) -> SerializedProof {
    SerializedProof {
        proof: proof.bytes().to_vec(),
        public_values: proof.public_values.to_vec(),
        vk_bytes: vk.bytes32().into_bytes(),
    }
}
