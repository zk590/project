use alloy_sol_types::sol;
use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Error as IoError, ErrorKind};
use std::path::Path;

// 定义公共值结构体
sol! {
    struct PublicValuesStruct {
        uint256 n;
        uint256 a;
        uint256 b;
    }
}

// 用于测试的默认值
pub const DEFAULT_N: u32 = 10;

// 定义斐波那契结果数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct FibonacciResult {
    pub n: u64,
    pub a: u64,
    pub b: u64,
}

// 仅在host特性启用时编译以下代码
#[cfg(feature = "host")]
extern crate bincode;

// 从文件读取并使用rkyv反序列化
#[cfg(feature = "host")]
pub fn read_and_deserialize(file_path: &str) -> Result<FibonacciResult, IoError> {
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