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

// 仅在host特性启用时编译以下代码
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
