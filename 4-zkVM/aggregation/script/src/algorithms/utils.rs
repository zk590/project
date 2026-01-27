use std::fs::File;
use std::io::Read;
use std::path::Path;
use rkyv::{Archive, Deserialize, Serialize};
use rkyv::de::deserializers::SharedDeserializeMap;
use rkyv::validation::validators::DefaultValidator;
use crate::algorithms::errors::AggregationError;

/// 通用的文件读取和反序列化函数
pub fn read_and_deserialize<T>(file_path: &str) -> Result<T, std::io::Error> 
where 
    T: Archive,
    T::Archived: Deserialize<T, SharedDeserializeMap> + for<'a> rkyv::CheckBytes<DefaultValidator<'a>>,
{
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "文件不存在"));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    // 使用rkyv反序列化
    println!("尝试反序列化文件: {}, 数据大小: {} 字节", file_path, bytes.len());
    let deserialized = rkyv::from_bytes::<T>(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("反序列化失败: {:?}", e)))?;
    
    Ok(deserialized)
}

/// 通用的证明生成包装函数
pub fn generate_proof_with_error_handling<F, E>(f: F) -> Result<(), AggregationError>
where
    F: FnOnce() -> Result<(), E>,
    E: std::fmt::Display,
{
    f().map_err(|e| AggregationError::ProofGenerationError(e.to_string()))
}