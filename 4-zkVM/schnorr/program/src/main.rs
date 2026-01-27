#![no_main]
sp1_zkvm::entrypoint!(main);

use k256::schnorr::{Signature, VerifyingKey};
use k256::schnorr::signature::Verifier;

pub fn main() {
    // 读取结果列表的长度
    let results_count = sp1_zkvm::io::read::<u32>();
    
    // 用于存储所有验证结果
    let mut all_valid = true;
    
    // 循环处理每条签名数据
    for i in 0..results_count {
        // 读取消息长度
        let message_len = sp1_zkvm::io::read::<u32>();
        // 读取消息内容
        let message = (0..message_len).map(|_| sp1_zkvm::io::read::<u8>()).collect::<Vec<u8>>();
        
        // 读取签名长度
        let signature_len = sp1_zkvm::io::read::<u32>();
        // 读取签名内容
        let signature_bytes = (0..signature_len).map(|_| sp1_zkvm::io::read::<u8>()).collect::<Vec<u8>>();
        
        // 读取公钥长度
        let public_key_len = sp1_zkvm::io::read::<u32>();
        // 读取公钥内容
        let public_key_bytes = (0..public_key_len).map(|_| sp1_zkvm::io::read::<u8>()).collect::<Vec<u8>>();
        
        // 解析验证密钥（公钥）
        let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
            .expect("无效的公钥数据");
        
        // 解析签名
        let signature = match Signature::try_from(&signature_bytes[..64]) {
            Ok(sig) => sig,
            Err(_) => panic!("无效的签名数据")
        };
        
        // 验证签名
        let is_valid = verifying_key.verify(&message, &signature).is_ok();
        
        // 更新总体验证结果
        all_valid = all_valid && is_valid;
        
        // 输出验证结果
        println!("Schnorr签名验证结果 #{i}: {}", is_valid);
    }
    
    // 提交总体验证结果
    sp1_zkvm::io::commit(&all_valid);
}