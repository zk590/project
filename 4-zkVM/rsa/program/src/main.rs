#![no_main]
sp1_zkvm::entrypoint!(main);

use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256};

pub fn main() {
    // 先读取签名结果列表的长度
    let results_len = sp1_zkvm::io::read::<u32>();
    println!("收到 {} 条签名结果需要验证", results_len);
    
    // 用于存储所有验证结果
    let mut all_valid = true;
    
    // 循环处理每条签名结果
    for i in 0..results_len {
        // 先读取消息长度
        let message_len = sp1_zkvm::io::read::<u32>();
        // 然后根据长度读取消息内容
        let message = (0..message_len).map(|_| sp1_zkvm::io::read::<u8>()).collect::<Vec<u8>>();
        
        // 先读取签名长度
        let signature_len = sp1_zkvm::io::read::<u32>();
        // 然后根据长度读取签名内容
        let signature = (0..signature_len).map(|_| sp1_zkvm::io::read::<u8>()).collect::<Vec<u8>>();
        
        // 先读取公钥长度
        let public_key_der_len = sp1_zkvm::io::read::<u32>();
        // 然后根据长度读取公钥内容
        let public_key_der = (0..public_key_der_len).map(|_| sp1_zkvm::io::read::<u8>()).collect::<Vec<u8>>();

        // 执行签名验证，添加错误处理
        let is_valid = match RsaPublicKey::from_public_key_der(&public_key_der) {
            Ok(public_key) => {
                // 计算消息的SHA-256哈希值
                let mut hasher = Sha256::new();
                hasher.update(&message);
                let hashed_message = hasher.finalize();
                
                // 验证签名
                public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_message, &signature).is_ok()
            },
            Err(err) => {
                // 公钥解析失败，记录错误并返回验证失败
                println!("公钥解析错误: {:?}", err);
                false
            }
        };
        
        println!("验证结果 #{}: {}", i + 1, is_valid);
        
        // 更新总体验证结果
        all_valid = all_valid && is_valid;
    }
    
    // 提交最终的总体验证结果
    println!("所有签名结果验证完成，总体结果: {}", all_valid);
    sp1_zkvm::io::commit(&all_valid);
}