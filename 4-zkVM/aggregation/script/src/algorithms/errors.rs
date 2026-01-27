use std::io;
use thiserror::Error;

/// 聚合脚本的自定义错误类型
#[derive(Debug, Error)]
pub enum AggregationError {
    /// IO错误
    #[error("IO错误: {0}")]
    IoError(#[from] io::Error),
    
    /// 反序列化错误
    #[error("反序列化错误: {0}")]
    DeserializationError(String),
    
    /// 数据加载错误
    #[error("数据加载错误: {0}")]
    DataLoadError(String),
    
    /// 证明生成错误
    #[error("证明生成错误: {0}")]
    ProofGenerationError(String),
    
    /// 未知算法错误
    #[error("未知算法: {0}")]
    UnknownAlgorithm(String),
    
    /// 无有效输入错误
    #[error("无有效输入")]
    NoValidInputsError,
    
    /// SP1相关错误
    #[error("SP1错误: {0}")]
    Sp1Error(String),
    
    /// 数据格式错误
    #[error("数据格式错误: {0}")]
    DataFormatError(String),
}