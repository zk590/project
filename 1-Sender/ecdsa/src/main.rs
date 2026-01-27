use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer, signature::Verifier};
use hex;
use std::fs::File;
use std::io::{Write, Read};
use std::path::Path;
use clap::Parser;
use rkyv::{Archive, Deserialize, Serialize};

use common::constants::ECDSA_DATA_FILE;
use common::constants::{PUB_KEY_PATH, PRIV_KEY_PATH};

// 定义命令行参数结构
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 要签名的消息
    #[arg(short, long)]
    message: String,
}

// 定义ECDSA签名结果数据结构，使用rkyv序列化
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct EcdsaResult {
    message: String,
    signature_hex: String,
    public_key_hex: String,
    is_valid: bool,
}

fn main() {
    // 解析命令行参数
    let args = Args::parse();
    let message = args.message;
    
    println!("处理消息: {}", message);
    
    // 执行ECDSA签名和验证
    let result = ecdsa_sign_verify(&message);
    
    // 将结果使用rkyv序列化并写入文件
    match serialize_and_write(&result, ECDSA_DATA_FILE) {
        Ok(_) => {
            println!("结果已成功写入文件: {}", ECDSA_DATA_FILE);
            println!("\nECDSA签名验证结果:");
            println!("消息: {}", result.message);
            println!("签名: {}", result.signature_hex);
            println!("公钥: {}", result.public_key_hex);
            println!("验证结果: {}", if result.is_valid { "成功" } else { "失败" });
            
            // 测试反序列化功能
            match read_and_deserialize(ECDSA_DATA_FILE) {
                Ok(deserialized) => {
                    println!("\n反序列化测试成功!");
                    println!("反序列化后验证结果: {}", if deserialized.is_valid { "成功" } else { "失败" });
                },
                Err(err) => eprintln!("反序列化失败: {}", err),
            }
        },
        Err(err) => eprintln!("序列化或写入文件失败: {}", err),
    }
}

// // 执行ECDSA签名和验证
fn ecdsa_sign_verify(message: &str) -> EcdsaResult {
    // 从文件读取ECIES私钥
    let priv_key_bytes = std::fs::read(PRIV_KEY_PATH).unwrap_or_else(|e| {
        panic!("无法读取私钥文件: {}", e);
    });
    
    // 从私钥字节创建SigningKey
    let signing_key = SigningKey::from_bytes((&priv_key_bytes[..32]).into()).unwrap_or_else(|e| {
        panic!("无法从字节创建签名密钥: {}", e);
    });
    
    // 从文件读取ECIES公钥
    let pub_key_bytes = std::fs::read(PUB_KEY_PATH).unwrap_or_else(|e| {
        panic!("无法读取公钥文件: {}", e);
    });
    
    // 从公钥字节创建VerifyingKey
    let verifying_key = VerifyingKey::from_sec1_bytes(&pub_key_bytes).unwrap_or_else(|e| {
        panic!("无法从字节创建验证密钥: {}", e);
    });
    
    // 对消息进行签名
    let signature: Signature = signing_key.sign(message.as_bytes());
    
    // 验证签名
    let is_valid = verifying_key.verify(message.as_bytes(), &signature).is_ok();
    
    // 将公钥、签名转换为十六进制字符串
    let public_key_hex = hex::encode(verifying_key.to_sec1_bytes());
    let signature_hex = hex::encode(signature.to_bytes());
    
    // 创建结果数据结构
    EcdsaResult {
        message: message.to_string(),
        signature_hex,
        public_key_hex,
        is_valid,
    }
}


// 执行ECDSA签名和验证
// fn ecdsa_sign_verify(message: &str) -> EcdsaResult {
//     // 生成随机签名密钥
//     let signing_key = SigningKey::random(&mut OsRng);
//     // 获取对应的验证密钥
//     let verifying_key = signing_key.verifying_key();
    
//     // 对消息进行签名
//     let signature: Signature = signing_key.sign(message.as_bytes());
    
//     // 验证签名
//     let is_valid = verifying_key.verify(message.as_bytes(), &signature).is_ok();
    
//     // 将公钥、签名转换为十六进制字符串
//     let public_key_hex = hex::encode(verifying_key.to_sec1_bytes());
//     let signature_hex = hex::encode(signature.to_bytes());
    
//     // 创建结果数据结构
//     EcdsaResult {
//         message: message.to_string(),
//         signature_hex,
//         public_key_hex,
//         is_valid,
//     }
// }


// 使用rkyv将结果序列化并写入文件
fn serialize_and_write(result: &EcdsaResult, file_path: &str) -> Result<(), std::io::Error> {
    // 使用rkyv序列化结果
    let bytes = rkyv::to_bytes::<_, 256>(result)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "序列化失败"))?;
    
    // 打开或创建文件
    let mut file = File::create(file_path)?;
    
    // 写入序列化后的字节
    file.write_all(&bytes)?;
    
    println!("序列化字节大小: {} 字节", bytes.len());
    
    Ok(())
}

// 从文件读取并使用rkyv反序列化
fn read_and_deserialize(file_path: &str) -> Result<EcdsaResult, std::io::Error> {
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