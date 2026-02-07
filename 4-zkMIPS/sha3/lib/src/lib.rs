use alloy_sol_types::sol;
#[cfg(feature = "host")]
use rkyv::{Archive, Deserialize, Serialize};
#[cfg(feature = "host")]
use std::fs::File;
#[cfg(feature = "host")]
use std::io::{Read, Error as IoError, ErrorKind};
#[cfg(feature = "host")]
use std::path::Path;

// 定义单个哈希结果数据结构
#[cfg_attr(feature = "host", derive(Archive, Serialize, Deserialize))]
#[derive(Debug)]
#[cfg_attr(feature = "host", archive(check_bytes))]
pub struct HashResult {
    pub message: String,
    pub hash: String,
}

// 定义多个哈希结果的集合数据结构
#[cfg_attr(feature = "host", derive(Archive, Serialize, Deserialize))]
#[derive(Debug)]
#[cfg_attr(feature = "host", archive(check_bytes))]
pub struct HashResults {
    pub results: Vec<HashResult>,
}

sol! {
    /// The public values encoded as a struct for SHA3 verification.
    struct PublicValuesStruct {
        bool all_valid;
    }
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

#[cfg(feature = "host")]
pub fn read_and_deserialize(file_path: &str) -> Result<HashResults, IoError> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(IoError::new(ErrorKind::NotFound, "文件不存在"));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    // 使用rkyv反序列化
    let deserialized = rkyv::from_bytes(&bytes)
        .map_err(|_| IoError::new(ErrorKind::Other, "反序列化失败"))?;
    
    Ok(deserialized)
}
