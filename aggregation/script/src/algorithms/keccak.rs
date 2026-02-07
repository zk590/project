use super::algorithm_trait::AlgorithmHandler;
use hex;
use rkyv::{Archive, Deserialize, Serialize};
use crate::algorithms::errors::AggregationError;
use crate::algorithms::utils::read_and_deserialize;

// 定义Keccak哈希结果数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct HashResult {
    pub message: String,
    pub hash: String,
}

// 定义多个Keccak哈希结果的集合数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct HashResults {
    pub results: Vec<HashResult>,
}

/// Keccak算法处理器
pub struct KeccakHandler {
    elf: &'static [u8],
    data_file: String,
    data: Option<HashResults>,
}

impl KeccakHandler {
    pub fn new(elf: &'static [u8], data_file: &str) -> Self {
        Self {
            elf,
            data_file: data_file.to_string(),
            data: None,
        }
    }
    
    /// 从文件读取并使用rkyv反序列化HashResults
    pub fn read_hash_data(file_path: &str) -> Result<HashResults, AggregationError> {
        read_and_deserialize(file_path).map_err(|e| AggregationError::IoError(e))
    }
}

impl AlgorithmHandler for KeccakHandler {
    fn name(&self) -> &str {
        "keccak"
    }
    
    fn get_elf(&self) -> &'static [u8] {
        self.elf
    }
    
    fn read_data(&mut self) -> Result<(), AggregationError> {
        let data = Self::read_hash_data(&self.data_file)?;
        self.data = Some(data);
        Ok(())
    }
    
    fn get_input_data(&self) -> Result<Vec<u8>, AggregationError> {
        // 获取输入数据
        let hash_results = self.data.as_ref()
            .ok_or_else(|| AggregationError::DataLoadError("尚未读取数据".to_string()))?;
        
        // 先写入结果列表的长度
        let mut input_data = Vec::new();
        input_data.extend_from_slice(&u32::to_le_bytes(hash_results.results.len() as u32));
        
        // 然后逐个写入每个哈希结果
        for result in &hash_results.results {
            let message = result.message.as_bytes();
            let hash_value = hex::decode(&result.hash).map_err(|_| {
                AggregationError::DataFormatError("无效的hex哈希值".to_string())
            })?;
            
            // 先写入消息长度和内容
            input_data.extend_from_slice(&u32::to_le_bytes(message.len() as u32));
            input_data.extend_from_slice(message);
            
            // 先写入哈希值长度和内容
            input_data.extend_from_slice(&u32::to_le_bytes(hash_value.len() as u32));
            input_data.extend_from_slice(&hash_value);
        }
        
        Ok(input_data)
    }
}