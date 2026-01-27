use alloy_sol_types::sol; 

// 定义公共值结构体
sol! {
    struct PublicValuesStruct {
        bool allValid;
    }
}

// 用于测试的默认消息
pub const DEFAULT_MESSAGE: &[u8] = b"Test message for Keccak hash verification";

// 用于测试的默认Keccak哈希值（hex格式）
pub const DEFAULT_HASH: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

// 仅在host特性启用时编译以下代码
#[cfg(feature = "host")]
extern crate bincode;

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