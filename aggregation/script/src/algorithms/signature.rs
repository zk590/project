use super::algorithm_trait::AlgorithmHandler;
use rkyv::{Archive, Deserialize, Serialize};
use crate::algorithms::errors::AggregationError;
use crate::algorithms::utils::read_and_deserialize;
use hex;

// 定义RSA签名结果数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct SignatureResult {
    pub message: String,
    pub signature_hex: String,
}

// 定义RSA签名结果批量数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct RSASignatureResults {
    pub results: Vec<SignatureResult>,
}

// 定义ECDSA签名结果数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct EcdsaResult {
    pub message: String,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub is_valid: bool,
}

// 定义ECDSA签名结果批量数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct ECDSASignatureResults {
    pub results: Vec<EcdsaResult>,
}

// 定义Schnorr签名结果数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct SchnorrResult {
    pub message: String,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub is_valid: bool,
}

// 定义Schnorr签名结果批量数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct SchnorrSignatureResults {
    pub results: Vec<SchnorrResult>,
}

/// RSA算法处理器
pub struct RSAHandler {
    elf: &'static [u8],
    data_file: String,
    data: Option<RSASignatureResults>,
}

impl RSAHandler {
    pub fn new(elf: &'static [u8], data_file: &str) -> Self {
        Self {
            elf,
            data_file: data_file.to_string(),
            data: None,
        }
    }
    
    /// 从文件读取并使用rkyv反序列化RSASignatureResults
    pub fn read_rsa_data(file_path: &str) -> Result<RSASignatureResults, AggregationError> {
        read_and_deserialize(file_path).map_err(|e| AggregationError::IoError(e))
    }
}

impl AlgorithmHandler for RSAHandler {
    fn name(&self) -> &str {
        "rsa"
    }
    
    fn get_elf(&self) -> &'static [u8] {
        self.elf
    }
    
    fn read_data(&mut self) -> Result<(), AggregationError> {
        let rsa_results = Self::read_rsa_data(&self.data_file)?;
        println!("成功读取RSA数据，包含 {} 条记录", rsa_results.results.len());
        self.data = Some(rsa_results);
        Ok(())
    }
    
    fn get_input_data(&self) -> Result<Vec<u8>, AggregationError> {
        // 获取输入数据并转换为字节数组
        let signature_results = self.data.as_ref()
            .ok_or_else(|| AggregationError::DataLoadError("尚未读取数据".to_string()))?;
        
        // 创建一个Vec<u8>来存储序列化后的数据
        let mut buffer = Vec::new();
        
        // 写入结果列表长度
        buffer.extend_from_slice(&(signature_results.results.len() as u32).to_le_bytes());
        
        let original_count = signature_results.results.len();
        let mut processed_count = 0;
        let mut skipped_count = 0;
        
        // 循环写入每条记录
        for result in &signature_results.results {
            // 写入消息长度
            let message_bytes = result.message.as_bytes();
            buffer.extend_from_slice(&(message_bytes.len() as u32).to_le_bytes());
            
            // 写入消息内容
            buffer.extend_from_slice(message_bytes);
            
            // 写入签名长度（注意：result.signature_hex是十六进制字符串，需要先解码）
            let signature_bytes = match hex::decode(&result.signature_hex) {
                Ok(bytes) => bytes,
                Err(err) => {
                    println!("解码签名失败: {}，跳过该记录", err);
                    skipped_count += 1;
                    // 因为我们已经写入了消息长度和内容，这里需要从buffer中移除这些数据
                    let message_size = 4 + message_bytes.len(); // 4字节长度 + 消息内容
                    buffer.truncate(buffer.len() - message_size);
                    continue;
                }
            };
            buffer.extend_from_slice(&(signature_bytes.len() as u32).to_le_bytes());
            
            // 写入签名内容
            buffer.extend_from_slice(&signature_bytes);
            processed_count += 1;
        }
        
        // 更新buffer中的结果列表长度
        if processed_count < original_count {
            // 重新写入实际处理的记录数量
            let mut updated_buffer = Vec::new();
            updated_buffer.extend_from_slice(&(processed_count as u32).to_le_bytes());
            updated_buffer.extend_from_slice(&buffer[4..]); // 跳过原来的长度
            buffer = updated_buffer;
        }
        
        println!("处理RSA输入数据: 总共 {} 条记录，成功处理 {} 条，跳过 {} 条", 
                 original_count, processed_count, skipped_count);
        println!("生成的输入数据大小: {} 字节", buffer.len());
        
        Ok(buffer)
    }
}

/// ECDSA算法处理器
pub struct ECDSAHandler {
    elf: &'static [u8],
    data_file: String,
    data: Option<ECDSASignatureResults>,
}

impl ECDSAHandler {
    pub fn new(elf: &'static [u8], data_file: &str) -> Self {
        Self {
            elf,
            data_file: data_file.to_string(),
            data: None,
        }
    }
    
    /// 从文件读取并使用rkyv反序列化ECDSASignatureResults
    pub fn read_ecdsa_data(file_path: &str) -> Result<ECDSASignatureResults, AggregationError> {
        read_and_deserialize(file_path).map_err(|e| AggregationError::IoError(e))
    }
    
    /// 获取原始的ECDSA数据
    pub fn get_data(&self) -> Result<&ECDSASignatureResults, AggregationError> {
        self.data.as_ref().ok_or_else(|| AggregationError::DataLoadError("尚未读取数据".to_string()))
    }
}

impl AlgorithmHandler for ECDSAHandler {
    fn name(&self) -> &str {
        "ecdsa"
    }
    
    fn get_elf(&self) -> &'static [u8] {
        self.elf
    }
    
    fn read_data(&mut self) -> Result<(), AggregationError> {
        let ecdsa_results = Self::read_ecdsa_data(&self.data_file)?;
        println!("成功读取ECDSA数据，包含 {} 条记录", ecdsa_results.results.len());
        self.data = Some(ecdsa_results);
        Ok(())
    }
    
    fn get_input_data(&self) -> Result<Vec<u8>, AggregationError> {
        // 获取输入数据并转换为字节数组
        let ecdsa_results = self.data.as_ref()
            .ok_or_else(|| AggregationError::DataLoadError("尚未读取数据".to_string()))?;
        
        // 创建一个Vec<u8>来临时存储记录数据
        let mut records_buffer = Vec::new();
        
        let original_count = ecdsa_results.results.len();
        let mut processed_count = 0;
        let mut skipped_count = 0;
        
        // 循环写入每条记录到临时buffer
        for result in &ecdsa_results.results {
            // 保存当前buffer长度，用于失败时回滚
            let start_pos = records_buffer.len();
            
            // 写入消息长度
            let message_bytes = result.message.as_bytes();
            records_buffer.extend_from_slice(&(message_bytes.len() as u32).to_le_bytes());
            
            // 写入消息内容
            records_buffer.extend_from_slice(message_bytes);
            
            // 写入签名长度（注意：result.signature_hex是十六进制字符串，需要先解码）
            let signature_bytes = match hex::decode(&result.signature_hex) {
                Ok(bytes) => bytes,
                Err(err) => {
                    println!("解码签名失败: {}，跳过该记录", err);
                    skipped_count += 1;
                    // 回滚buffer到开始位置
                    records_buffer.truncate(start_pos);
                    continue;
                }
            };
            records_buffer.extend_from_slice(&(signature_bytes.len() as u32).to_le_bytes());
            
            // 写入签名内容
            records_buffer.extend_from_slice(&signature_bytes);
            
            // 写入公钥长度
            let public_key_bytes = match hex::decode(&result.public_key_hex) {
                Ok(bytes) => bytes,
                Err(err) => {
                    println!("解码公钥失败: {}，跳过该记录", err);
                    skipped_count += 1;
                    // 回滚buffer到开始位置
                    records_buffer.truncate(start_pos);
                    continue;
                }
            };
            records_buffer.extend_from_slice(&(public_key_bytes.len() as u32).to_le_bytes());
            
            // 写入公钥内容
            records_buffer.extend_from_slice(&public_key_bytes);
            processed_count += 1;
        }
        
        // 创建最终的buffer，先写入实际处理的记录数量
        let mut final_buffer = Vec::new();
        final_buffer.extend_from_slice(&(processed_count as u32).to_le_bytes());
        // 然后添加所有成功处理的记录数据
        final_buffer.extend_from_slice(&records_buffer);
        
        println!("处理ECDSA输入数据: 总共 {} 条记录，成功处理 {} 条，跳过 {} 条", 
                 original_count, processed_count, skipped_count);
        println!("生成的输入数据大小: {} 字节", final_buffer.len());
        
        Ok(final_buffer)
    }
}

/// Schnorr算法处理器
pub struct SchnorrHandler {
    elf: &'static [u8],
    data_file: String,
    data: Option<SchnorrSignatureResults>,
}

impl SchnorrHandler {
    pub fn new(elf: &'static [u8], data_file: &str) -> Self {
        Self {
            elf,
            data_file: data_file.to_string(),
            data: None,
        }
    }
    
    /// 从文件读取并使用rkyv反序列化SchnorrSignatureResults
    pub fn read_schnorr_data(file_path: &str) -> Result<SchnorrSignatureResults, AggregationError> {
        read_and_deserialize(file_path).map_err(|e| AggregationError::IoError(e))
    }
}

impl AlgorithmHandler for SchnorrHandler {
    fn name(&self) -> &str {
        "schnorr"
    }
    
    fn get_elf(&self) -> &'static [u8] {
        self.elf
    }
    
    fn read_data(&mut self) -> Result<(), AggregationError> {
        let schnorr_results = Self::read_schnorr_data(&self.data_file)?;
        println!("成功读取Schnorr数据，包含 {} 条记录", schnorr_results.results.len());
        self.data = Some(schnorr_results);
        Ok(())
    }
    
    fn get_input_data(&self) -> Result<Vec<u8>, AggregationError> {
        // 获取输入数据并转换为字节数组
        let schnorr_results = self.data.as_ref()
            .ok_or_else(|| AggregationError::DataLoadError("尚未读取数据".to_string()))?;
        
        // 创建一个Vec<u8>来存储序列化后的数据
        let mut buffer = Vec::new();
        
        // 写入结果列表长度
        buffer.extend_from_slice(&(schnorr_results.results.len() as u32).to_le_bytes());
        
        let original_count = schnorr_results.results.len();
        let mut processed_count = 0;
        let mut skipped_count = 0;
        
        // 循环写入每条记录
        for result in &schnorr_results.results {
            // 写入消息长度
            let message_bytes = result.message.as_bytes();
            buffer.extend_from_slice(&(message_bytes.len() as u32).to_le_bytes());
            
            // 写入消息内容
            buffer.extend_from_slice(message_bytes);
            
            // 写入签名长度（注意：result.signature_hex是十六进制字符串，需要先解码）
            let signature_bytes = match hex::decode(&result.signature_hex) {
                Ok(bytes) => bytes,
                Err(err) => {
                    println!("解码签名失败: {}，跳过该记录", err);
                    skipped_count += 1;
                    // 因为我们已经写入了消息长度和内容，这里需要从buffer中移除这些数据
                    let message_size = 4 + message_bytes.len(); // 4字节长度 + 消息内容
                    buffer.truncate(buffer.len() - message_size);
                    continue;
                }
            };
            buffer.extend_from_slice(&(signature_bytes.len() as u32).to_le_bytes());
            
            // 写入签名内容
            buffer.extend_from_slice(&signature_bytes);
            
            // 写入公钥长度
            let public_key_bytes = match hex::decode(&result.public_key_hex) {
                Ok(bytes) => bytes,
                Err(err) => {
                    println!("解码公钥失败: {}，跳过该记录", err);
                    skipped_count += 1;
                    // 因为我们已经写入了消息长度、内容、签名长度和内容，这里需要从buffer中移除这些数据
                    let message_size = 4 + message_bytes.len(); // 4字节长度 + 消息内容
                    let signature_size = 4 + signature_bytes.len(); // 4字节长度 + 签名内容
                    buffer.truncate(buffer.len() - message_size - signature_size);
                    continue;
                }
            };
            buffer.extend_from_slice(&(public_key_bytes.len() as u32).to_le_bytes());
            
            // 写入公钥内容
            buffer.extend_from_slice(&public_key_bytes);
            processed_count += 1;
        }
        
        // 更新buffer中的结果列表长度
        if processed_count < original_count {
            // 重新写入实际处理的记录数量
            let mut updated_buffer = Vec::new();
            updated_buffer.extend_from_slice(&(processed_count as u32).to_le_bytes());
            updated_buffer.extend_from_slice(&buffer[4..]); // 跳过原来的长度
            buffer = updated_buffer;
        }
        
        println!("处理Schnorr输入数据: 总共 {} 条记录，成功处理 {} 条，跳过 {} 条", 
                 original_count, processed_count, skipped_count);
        println!("生成的输入数据大小: {} 字节", buffer.len());
        
        Ok(buffer)
    }
}