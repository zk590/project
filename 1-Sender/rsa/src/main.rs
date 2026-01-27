// 导入RSA相关库，用于私钥解析和签名生成
use rsa::{pkcs8::DecodePrivateKey, Pkcs1v15Sign, RsaPrivateKey};
// 导入SHA-256哈希函数库，用于计算消息哈希值
use sha2::{Digest, Sha256};
// 导入文件系统操作相关库
use std::fs::File;
use std::io::{Write, Read};
use std::path::Path;
use clap::Parser;
use rkyv::{Archive, Serialize, Deserialize};
use hex;

use common::constants::RSA_HASH_FILE;

// 定义命令行参数结构
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 要签名的消息
    #[arg(short, long)]
    message: String,
}

// 定义输出数据结构，使用rkyv序列化
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct SignatureResult {
    message: String,
    signature_hex: String,
}

/// 生成RSA签名的函数
/// 
/// 该函数使用RSA私钥对给定消息生成数字签名。签名过程包括：
/// 1. 从DER格式解析RSA私钥
/// 2. 计算消息的SHA-256哈希值
/// 3. 使用PKCS#1 v1.5填充方案和私钥生成签名
/// 
/// # 参数
/// - `private_key_der`: DER格式的RSA私钥数据
/// - `message`: 要签名的原始消息数据
/// 
/// # 返回值
/// - 成功时返回二进制格式的RSA签名
/// - 失败时返回包含错误信息的Box<dyn std::error::Error>
fn generate_rsa_signature(private_key_der: &[u8], message: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 从DER格式解析RSA私钥
    let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)?;
    
    // 计算消息的SHA-256哈希值
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hashed_message = hasher.finalize();
    
    // 使用私钥和PKCS#1 v1.5填充方案生成签名
    let signature = private_key.sign(Pkcs1v15Sign::new::<Sha256>(), &hashed_message)?;
    
    Ok(signature)
}

// 使用rkyv将结果序列化并写入文件
fn serialize_and_write(result: &SignatureResult, file_path: &str) -> Result<(), std::io::Error> {
    // 使用rkyv序列化结果
    let bytes = rkyv::to_bytes::<_, 2048>(result)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "序列化失败"))?;
    
    // 打开或创建文件
    let mut file = File::create(file_path)?;
    
    // 写入序列化后的字节
    file.write_all(&bytes)?;
    
    println!("序列化字节大小: {} 字节", bytes.len());
    
    Ok(())
}

// 从文件读取并使用rkyv反序列化
fn read_and_deserialize(file_path: &str) -> Result<SignatureResult, std::io::Error> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "文件不存在"));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    // 使用rkyv反序列化
    let deserialized = rkyv::from_bytes(&bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "反序列化失败"))?;
    
    Ok(deserialized)
}

fn main() {
    // 解析命令行参数
    let args = Args::parse();
    
    println!("处理消息: {}", args.message);
    
    // 从内置资源加载2048位RSA私钥
    let private_key_der = include_bytes!("rsa2048-priv.der");
    
    // 尝试生成RSA签名
    match generate_rsa_signature(private_key_der, args.message.as_bytes()) {
        Ok(signature) => {
            println!("签名生成成功!");
            println!("签名长度: {} 字节", signature.len());
            println!("签名(前32字节): {:?}", &signature[..32.min(signature.len())]);
            
            // 将签名转换为十六进制字符串
            let signature_hex = hex::encode(&signature);
            
            // 创建结果数据结构
            let result = SignatureResult {
                message: args.message,
                signature_hex,
            };
            
            // 将结果使用rkyv序列化并写入文件
            match serialize_and_write(&result, RSA_HASH_FILE) {
                Ok(_) => {
                    println!("结果已成功写入文件: {}", RSA_HASH_FILE);
                    
                    // 测试反序列化功能
                    match read_and_deserialize(RSA_HASH_FILE) {
                        Ok(deserialized) => {
                            println!("\n反序列化测试成功!");
                            println!("反序列化后的消息: {}", deserialized.message);
                            println!("反序列化后的签名: {}", deserialized.signature_hex);
                        },
                        Err(err) => eprintln!("反序列化失败: {}", err),
                    }
                },
                Err(err) => eprintln!("序列化或写入文件失败: {}", err),
            }
        },
        Err(err) => {
            eprintln!("签名生成失败: {}", err);
        }
    }
}

// 单元测试模块，用于验证签名生成和验证功能
#[cfg(test)]
mod tests {
    use super::*;
    // 导入公钥相关功能，用于验证测试
    use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Sign, RsaPublicKey};
    
    /// 测试签名生成和验证过程
    /// 
    /// 该测试函数验证：
    /// 1. 使用私钥生成的签名可以被对应的公钥成功验证
    /// 2. 篡改消息后，签名验证会失败
    #[test]
    fn test_sign_and_verify() {
        // let private_key_der = include_bytes!("rsa2048-priv.der");
        // let public_key_der = include_bytes!("rsa2048-pub.der");
        let private_key_der = include_bytes!("../../ecies/ecies-priv.der");
        let public_key_der = include_bytes!("../../ecies/ecies-pub.der");
        let message = b"Test message for signature verification";
        
        // 生成签名
        let signature = generate_rsa_signature(private_key_der, message).unwrap();
        
        // 验证签名
        let public_key = RsaPublicKey::from_public_key_der(public_key_der).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(message);
        let hashed_message = hasher.finalize();
        
        // 验证应该成功 - 未篡改的消息
        assert!(public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed_message, &signature).is_ok());
        
        // 篡改消息后验证应该失败
        let mut modified_message = message.to_vec();
        if !modified_message.is_empty() {
            modified_message[0] ^= 0x01; // 简单篡改：翻转第一个字节的最低位
            let mut modified_hasher = Sha256::new();
            modified_hasher.update(&modified_message);
            let modified_hashed = modified_hasher.finalize();
            assert!(public_key.verify(Pkcs1v15Sign::new::<Sha256>(), &modified_hashed, &signature).is_err());
        }
    }
}