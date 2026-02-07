#![no_main]
zkm_zkvm::entrypoint!(main);

use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
use sha2_lib::sha256;
use sha2::Sha256;
use rsa_lib::PublicValuesStruct;
use zkm_zkvm::io::{read, commit_slice};
use alloy_sol_types::SolType;


pub fn main() {
    // 先读取签名结果列表的长度
    let results_len = read::<u32>();

    // 用于存储所有验证结果
    let mut all_valid = true;

    // 循环处理每条签名结果
    for i in 0..results_len {
        // 先读取消息长度
        let message_len = read::<u32>();
        // 然后根据长度读取消息内容
        let message = (0..message_len).map(|_| read::<u8>()).collect::<Vec<u8>>();

        // 先读取签名长度
        let signature_len = read::<u32>();
        // 然后根据长度读取签名内容
        let signature = (0..signature_len).map(|_| read::<u8>()).collect::<Vec<u8>>();

        // 先读取公钥长度
        let public_key_der_len = read::<u32>();
        // 然后根据长度读取公钥内容
        let public_key_der = (0..public_key_der_len).map(|_| read::<u8>()).collect::<Vec<u8>>();

        // 执行签名验证，添加错误处理
        let is_valid = match RsaPublicKey::from_public_key_der(&public_key_der) {
            Ok(public_key) => {
                // 计算消息的SHA-256哈希值
                let hashed_message = sha256(&message);

                // 验证签名
                public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_message, &signature).is_ok()
            }
            Err(_err) => {
                    // 公钥解析失败，返回验证失败
                    false
                }
        };



        // 更新总体验证结果
        all_valid = all_valid && is_valid;
    }

    // 提交最终的总体验证结果

    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { all_valid });
    commit_slice(&bytes);
}