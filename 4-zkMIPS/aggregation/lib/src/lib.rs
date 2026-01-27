//! 聚合证明项目的公共库

use alloy_sol_types::{sol, SolType};

/// 公共值结构体，用于存储聚合结果（默克尔根）
sol! {
    struct PublicValuesStruct {
        bytes32 merkleRoot;
    }
}

/// 默认的测试值
pub const DEFAULT_VKEY: [u32; 8] = [0u32; 8];
pub const DEFAULT_PUBLIC_VALUE: &[u8] = &[0u8; 32];