// 各种算法的共享常量库

// 导出constants模块，使其他项目可以引用这些常量
pub mod constants;

// 重新导出constants模块下的所有公共项
pub use constants::*;
