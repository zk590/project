#![no_main]
zkm_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use keccak_lib::PublicValuesStruct;
use tiny_keccak::{Hasher, Keccak};

pub fn main() {
    // 先读取哈希结果列表的长度
    let results_len = zkm_zkvm::io::read::<u32>();
    
    // 用于存储所有验证结果
    let mut all_valid = true;
    
    // 循环处理每条哈希结果
    for _ in 0..results_len {
        // 先读取消息长度
        let message_len = zkm_zkvm::io::read::<u32>();
        // 然后根据长度读取消息内容
        let message = (0..message_len).map(|_| zkm_zkvm::io::read::<u8>()).collect::<Vec<u8>>();
        
        // 先读取哈希值长度
        let hash_len = zkm_zkvm::io::read::<u32>();
        // 然后根据长度读取哈希值内容
        let hash_value = (0..hash_len).map(|_| zkm_zkvm::io::read::<u8>()).collect::<Vec<u8>>();

        // 计算KECCAK-256哈希值
        let mut hasher = Keccak::v256();
        hasher.update(&message);
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        
        // 验证计算的哈希值是否与提供的哈希值匹配
        let is_valid = &output[..] == &hash_value[..];
        
        // 更新总体验证结果
        all_valid = all_valid && is_valid;
    }
    
    // 提交最终的总体验证结果
    // 使用PublicValuesStruct提交结果
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        allValid: all_valid,
    });
    zkm_zkvm::io::commit_slice(&bytes);
}