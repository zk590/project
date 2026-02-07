use alloy_sol_types::sol; 

#[cfg(feature = "host")]
use rkyv::{Archive, Deserialize, Serialize};
#[cfg(feature = "host")]
use std::fs::File;
#[cfg(feature = "host")]
use std::io::{Read, Error as IoError, ErrorKind};
#[cfg(feature = "host")]
use std::path::Path;

// 定义公共值结构体
sol! {
    struct PublicValuesStruct {
        bool allValid;
    }
}

// 定义单个ECDSA签名结果数据结构
#[cfg_attr(feature = "host", derive(Archive, Serialize, Deserialize, Debug))]
#[cfg_attr(feature = "host", archive(check_bytes))]
pub struct EcdsaResult {
    pub message: String,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub is_valid: bool,
}

// 定义多个ECDSA签名结果的集合数据结构
#[cfg_attr(feature = "host", derive(Archive, Serialize, Deserialize, Debug))]
#[cfg_attr(feature = "host", archive(check_bytes))]
pub struct EcdsaResults {
    pub results: Vec<EcdsaResult>,
}

// 从文件读取并使用rkyv反序列化
#[cfg(feature = "host")]
pub fn read_and_deserialize(file_path: &str) -> Result<EcdsaResults, IoError> {
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

// 用于测试的默认消息
pub const DEFAULT_MESSAGE: &[u8] = b"Test message for ECDSA signature verification";

// 用于测试的默认公钥（hex格式）
pub const DEFAULT_PUBLIC_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// 用于测试的默认签名（hex格式）
pub const DEFAULT_SIGNATURE: &str = "30450221009328d16a626c4609fc853a753a46c733b60f554854a38e091b9806679a737d8502200f76a8810a5f45b67e5d1b6f1c248a51079012d850009f19e237c8301035e01e";