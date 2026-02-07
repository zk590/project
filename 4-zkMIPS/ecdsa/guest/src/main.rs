#![no_main]
zkm_zkvm::entrypoint!(main);
extern crate alloc;

use ecdsa_lib::PublicValuesStruct;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::ecdsa::signature::Verifier;
use zkm_zkvm::io::{read, commit_slice};
use alloy_sol_types::SolType;
use alloc::vec::Vec;

pub fn main() {
    // 先读取ECDSA结果列表的长度
    let results_len = read::<u32>();
    
    // 用于存储所有验证结果
    let mut all_valid = true;
    
    // 循环处理每条ECDSA结果
    for i in 0..results_len {
        // 读取消息长度
        let message_len = read::<u32>();
        // 读取消息内容
        let message = (0..message_len).map(|_| read::<u8>()).collect::<Vec<u8>>();
        
        // 读取签名长度
        let signature_len = read::<u32>();
        // 读取签名内容
        let signature_bytes = (0..signature_len).map(|_| read::<u8>()).collect::<Vec<u8>>();
        
        // 读取公钥长度
        let public_key_len = read::<u32>();
        // 读取公钥内容
        let public_key_bytes = (0..public_key_len).map(|_| read::<u8>()).collect::<Vec<u8>>();
        
        // 解析验证密钥（公钥）
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
            .expect("无效的公钥数据");
        
        // 解析签名
        let signature = Signature::from_bytes((&signature_bytes[..64]).into())
            .expect("无效的签名数据");
        
        // 验证签名
        let is_valid = verifying_key.verify(&message, &signature).is_ok();
        
        // 输出验证结果
        
        // 更新总体验证结果
        all_valid = all_valid && is_valid;
    }
    
    // 提交最终的总体验证结果
    
    // 使用PublicValuesStruct提交结果
    let public_values = PublicValuesStruct {
        allValid: all_valid,
    };
    
    let bytes = PublicValuesStruct::abi_encode(&public_values);
    commit_slice(&bytes);
}