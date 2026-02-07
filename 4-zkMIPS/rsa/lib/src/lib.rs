use alloy_sol_types::sol;

#[cfg(feature = "host")]
use rkyv::{Archive, Deserialize, Serialize};
#[cfg(feature = "host")]
use std::fs::File;
#[cfg(feature = "host")]
use std::io::{Read, Error as IoError, ErrorKind};
#[cfg(feature = "host")]
use std::path::Path;

sol! {
    /// The public values encoded as a struct for RSA verification.
    struct PublicValuesStruct {
        bool all_valid;
    }
}

// 定义单个签名结果数据结构
#[cfg_attr(feature = "host", derive(Archive, Serialize, Deserialize, Debug))]
#[cfg_attr(feature = "host", archive(check_bytes))]
pub struct SignatureResult {
    pub message: String,
    pub signature_hex: String,
}

// 定义多个签名结果的集合数据结构
#[cfg_attr(feature = "host", derive(Archive, Serialize, Deserialize, Debug))]
#[cfg_attr(feature = "host", archive(check_bytes))]
pub struct SignatureResults {
    pub results: Vec<SignatureResult>,
}

// 定义用于序列化证明和公共值的数据结构
#[cfg_attr(feature = "host", derive(Archive, Serialize, Deserialize, Debug))]
#[cfg_attr(feature = "host", archive(check_bytes))]
pub struct ProofData {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
    pub vk_bytes: String,
}

// 从文件读取并使用rkyv反序列化
#[cfg(feature = "host")]
pub fn read_and_deserialize(file_path: &str) -> Result<SignatureResults, IoError> {
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