// 库定义，用于测试
pub mod algorithms;
// pub mod algorithms::errors;
// pub mod algorithms::utils;

// 暴露主要函数和类型供测试使用
pub use algorithms::algorithm_trait::AlgorithmHandler;
pub use algorithms::errors::AggregationError;
pub use algorithms::utils::{read_and_deserialize, generate_proof_with_error_handling};
