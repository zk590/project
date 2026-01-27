//! 斐波那契乘法项目的公共库

use alloy_sol_types::{sol, SolType};

/// 公共值结构体，用于存储斐波那契结果
sol! {
    struct PublicValuesStruct {
        uint256 n;
        uint256 a;
        uint256 b;
    }
}

/// 默认的测试值
pub const DEFAULT_N: u32 = 8;

/// 乘法斐波那契实现
pub fn fibonacci_mul(n: u64) -> (u64, u64) {
    let mut a = 1;   // 初始化变量 a 为 1，对7919取模
    let mut b = 2;   // 初始化变量 b 为 2，对7919取模
    for _ in 0..n {
        let c = (a * b) % 7919;  // 计算下一个斐波那契数 c = a * b，对7919取模
        a = b % 7919;                    // 更新 a 为当前的 b 值
        b = c;                    // 更新 b 为新计算的 c 值
    }
    (a, b)
}

// 仅在host特性启用时编译以下代码
#[cfg(feature = "host")]
extern crate bincode;

#[cfg(feature = "host")]
use zkm_sdk::HashableKey;

#[cfg(feature = "host")]
pub struct SerializedProof {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
    pub vk_bytes: Vec<u8>,
}

#[cfg(feature = "host")]
pub fn serialize_stark_proof(
    proof: &zkm_sdk::ZKMProofWithPublicValues,
    vk: &zkm_sdk::ZKMVerifyingKey,
) -> SerializedProof {
    let vk_bytes = bincode::serialize(vk).expect("序列化vk失败");
    SerializedProof {
        proof: proof.bytes().to_vec(),
        public_values: proof.public_values.to_vec(),
        vk_bytes,
    }
}

#[cfg(feature = "host")]
pub fn serialize_plonk_proof(
    proof: &zkm_sdk::ZKMProofWithPublicValues,
    vk: &zkm_sdk::ZKMVerifyingKey,
) -> SerializedProof {
    SerializedProof {
        proof: proof.bytes().to_vec(),
        public_values: proof.public_values.to_vec(),
        vk_bytes: vk.bytes32().into_bytes(),
    }
}