#![no_main]
zkm_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use fibonacci_mul_lib::{PublicValuesStruct, fibonacci_mul};

pub fn main() {
    // 从输入读取n的值
    let n = zkm_zkvm::io::read::<u32>();

    // 计算斐波那契乘法结果
    let (a, b) = fibonacci_mul(n as u64);

    // 使用PublicValuesStruct提交结果
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        n: alloy_sol_types::private::Uint::<256, 4>::from(n as u128),
        a: alloy_sol_types::private::Uint::<256, 4>::from(a as u128),
        b: alloy_sol_types::private::Uint::<256, 4>::from(b as u128),
    });
    zkm_zkvm::io::commit_slice(&bytes);
}