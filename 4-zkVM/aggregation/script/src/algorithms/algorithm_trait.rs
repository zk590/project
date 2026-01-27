use crate::algorithms::errors::AggregationError;

/// 算法处理的通用接口
pub trait AlgorithmHandler {
    /// 获取算法名称
    fn name(&self) -> &str;

    /// 获取对应的ELF文件
    fn get_elf(&self) -> &'static [u8];
    
    /// 从文件读取数据
    fn read_data(&mut self) -> Result<(), AggregationError>;
    
    /// 获取算法所需的输入数据
    fn get_input_data(&self) -> Result<Vec<u8>, AggregationError>;
}