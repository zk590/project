use super::algorithm_trait::AlgorithmHandler;
use rkyv::{Archive, Deserialize, Serialize}; 
use crate::algorithms::errors::AggregationError;
use crate::algorithms::utils::read_and_deserialize;

// 定义斐波那契结果数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct FibonacciResult {
    pub n: u32,
    pub a: u64,
    pub b: u64,
}

/// 斐波那契算法处理器
pub struct FibonacciHandler {
    elf: &'static [u8],
    data_file: String,
    data: Option<FibonacciResult>,
}

impl FibonacciHandler {
    pub fn new(elf: &'static [u8], data_file: &str) -> Self {
        Self {
            elf,
            data_file: data_file.to_string(),
            data: None,
        }
    }
    
    /// 从文件读取并使用rkyv反序列化FibonacciResult
    pub fn read_fibonacci_data(file_path: &str) -> Result<FibonacciResult, AggregationError> {
        read_and_deserialize(file_path).map_err(|e| AggregationError::IoError(e))
    }
}

impl AlgorithmHandler for FibonacciHandler {
    fn name(&self) -> &str {
        "fibonacci"
    }
    
    fn get_elf(&self) -> &'static [u8] {
        self.elf
    }
    
    fn read_data(&mut self) -> Result<(), AggregationError> {
        let data = Self::read_fibonacci_data(&self.data_file)?;
        self.data = Some(data);
        Ok(())
    }
    
    fn get_input_data(&self) -> Result<Vec<u8>, AggregationError> {
        // 获取n值并转换为字节数组
        let n = self.data.as_ref()
            .ok_or_else(|| AggregationError::DataLoadError("尚未读取数据".to_string()))?
            .n;
        
        // 将u32转换为字节数组
        let bytes = n.to_le_bytes().to_vec();
        Ok(bytes)
    }
}