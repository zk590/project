use rkyv::{Archive, Deserialize, Serialize};
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey};
use crate::errors::AggregationError;
use crate::utils::read_and_deserialize;
use hex;
use super::algorithm_trait::AggregationInput;

// 定义哈希结果数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct HashResult {
    pub message: String,
    pub hash: String,
}

/// 哈希算法处理的通用实现
pub struct HashAlgorithmHandler {
    name: String,
    elf: &'static [u8],
    data_file: String,
    data: Option<HashResult>,
}

impl HashAlgorithmHandler {
    /// 创建新的哈希算法处理器
    pub fn new(name: &str, elf: &'static [u8], data_file: &str) -> Self {
        Self {
            name: name.to_string(),
            elf,
            data_file: data_file.to_string(),
            data: None,
        }
    }
    
    /// 从文件读取并使用rkyv反序列化HashResult
    pub fn read_hash_result(file_path: &str) -> Result<HashResult, AggregationError> {
        read_and_deserialize(file_path)
    }
}

impl super::algorithm_trait::AlgorithmHandler for HashAlgorithmHandler {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn get_elf(&self) -> &'static [u8] {
        self.elf
    }
    
    fn read_data(&mut self) -> Result<(), AggregationError> {
        let result = Self::read_hash_result(&self.data_file)?;
        self.data = Some(result);
        Ok(())
    }
    
    fn prepare_stdin(&self) -> Result<SP1Stdin, AggregationError> {
        let data = self.data.as_ref().ok_or(AggregationError::DataLoadError("未读取数据".to_string()))?;
        
        // 先保存哈希字符串用于打印和hex解码
        let hash_str = data.hash.clone();
        
        // 提取消息和哈希值
        let message = data.message.as_bytes(); // 转换为&[u8]类型
        let hash_value = hex::decode(&hash_str)
            .map_err(|e| AggregationError::DataLoadError(format!("哈希解码失败: {}", e)))?; // Vec<u8>类型

        let mut stdin = SP1Stdin::new();
        // 先写入消息长度
        stdin.write(&(message.len() as u32));
        // 写入消息
        stdin.write(&message);
        // 写入哈希值长度
        stdin.write(&(hash_value.len() as u32));
        // 写入哈希值
        stdin.write(&hash_value);
        
        Ok(stdin)
    }
    
    fn generate_proof(
        &self,
        client: &ProverClient,
        pk: &SP1VerifyingKey,
    ) -> Result<SP1ProofWithPublicValues, AggregationError> {
        let data = Self::read_hash_result(&self.data_file)?;
        
        // 打印加载的哈希数据
        println!("从文件加载哈希数据成功:");
        println!("- 消息: {}", data.message);
        println!("- 哈希: {}", data.hash);
        
        let message = data.message.as_bytes();
        let hash_value = hex::decode(&data.hash)
            .map_err(|e| AggregationError::DataLoadError(format!("哈希解码失败: {}", e)))?;

        let mut stdin = SP1Stdin::new();
        stdin.write(&(message.len() as u32));
        stdin.write(&message);
        stdin.write(&(hash_value.len() as u32));
        stdin.write(&hash_value);
        
        let proof = client.prove(&pk, &stdin).compressed().run()
            .map_err(|e| AggregationError::Sp1Error(e.to_string()))?;
        Ok(proof)
    }
}