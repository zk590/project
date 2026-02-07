#![no_main]
zkm_zkvm::entrypoint!(main);

use k256::schnorr::{Signature, VerifyingKey};
use k256::schnorr::signature::Verifier;
use schnorr_lib::PublicValuesStruct;
use zkm_zkvm::io::{read, commit_slice};
use alloy_sol_types::SolType;

pub fn main() {
    // 读取结果列表的长度
    let results_len = read::<u32>();

    // 用于存储所有验证结果
    let mut all_valid = true;

    // 循环处理每条签名数据
    for i in 0..results_len {
        // 读取消息长度
        let message_len = read::<u32>();
        // 读取消息内容
        let message = (0..message_len).map(|_| read::<u8>()).collect::<Vec<u8>>();

        // 读取签名长度
        let signature_len = read::<u32>();
        // 读取签名内容
        let signature_bytes = (0..signature_len).map(|_| read::<u8>()).collect::<Vec<u8>>();
        
        // 验证签名长度
        if signature_bytes.len() != 64 {
            panic!("无效的签名长度: {}, 期望64字节", signature_bytes.len());
        }

        // 读取公钥长度
        let public_key_len = read::<u32>();
        // 读取公钥内容
        let public_key_bytes = (0..public_key_len).map(|_| read::<u8>()).collect::<Vec<u8>>();

        // 解析验证密钥（公钥）
        // 注意：使用from_bytes而不是from_sec1_bytes，因为我们接收的是32字节的x坐标格式公钥
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .expect("无效的公钥数据");

        // 解析签名
        let signature = Signature::try_from(signature_bytes.as_slice())
            .expect("无效的签名数据");

        // 验证签名
        let is_valid = verifying_key.verify(&message, &signature).is_ok();

        // 输出验证结果
        println!("Schnorr签名验证结果 #{}: {}", i + 1, is_valid);

        // 更新总体验证结果
        all_valid = all_valid && is_valid;
    }

    // 提交最终的总体验证结果

    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { all_valid });
    commit_slice(&bytes);
}