use k256::schnorr::SigningKey;
use k256::schnorr::VerifyingKey;
use k256::schnorr::signature::{SignerMut, Verifier};
use hex;
use std::fs::File;
use std::io::{Write, Read};
use std::path::Path;
use clap::Parser;
use serde::{Serialize, Deserialize};
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

use common::constants::SCHNORR_DATA_FILE;

// 定义命令行参数结构
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 要签名的消息
    #[arg(short, long)]
    message: Option<String>,
    
    /// 生成的批量数据大小
    #[arg(short, long, default_value_t = 1)]
    count: u32,
}

// 定义Schnorr签名结果数据结构，同时支持serde和rkyv序列化
#[derive(Serialize, Deserialize, Debug, Archive, RkyvSerialize, RkyvDeserialize)]
#[archive_attr(derive(Debug))]
struct SchnorrResult {
    message: String,
    signature_hex: String,
    public_key_hex: String,
    is_valid: bool,
}

// 定义多个Schnorr签名结果的集合数据结构
#[derive(Serialize, Deserialize, Debug, Archive, RkyvSerialize, RkyvDeserialize)]
#[archive_attr(derive(Debug))]
struct SchnorrResults {
    results: Vec<SchnorrResult>,
}

fn main() {
    // 解析命令行参数
    let args = Args::parse();
    let base_message = args.message.unwrap_or_else(|| "默认测试消息".to_string());
    let count = args.count;
    
    println!("生成 {} 条Schnorr签名数据", count);
    
    // 生成多个Schnorr签名结果
    let mut results = Vec::new();
    for i in 0..count {
        // 为每条记录生成唯一消息
        let message = if count > 1 {
            format!("{}_{}", base_message, i + 1)
        } else {
            base_message.clone()
        };
        
        println!("处理消息 {}: {}", i + 1, message);
        let result = schnorr_sign_verify(&message);
        results.push(result);
    }
    
    // 创建结果集合
    let results_collection = SchnorrResults {
        results,
    };
    
    // 将结果使用rkyv序列化并写入文件
    match serialize_and_write(&results_collection, SCHNORR_DATA_FILE) {
        Ok(_) => {
            println!("\n结果已成功写入文件: {}", SCHNORR_DATA_FILE);
            println!("总共有 {} 条记录", results_collection.results.len());
            
            // 打印前3条记录作为示例
            let display_count = results_collection.results.len().min(3);
            for (index, result) in results_collection.results.iter().take(display_count).enumerate() {
                println!("\n示例记录 #{}", index + 1);
                println!("消息: {}", result.message);
                println!("签名: {}", result.signature_hex);
                println!("公钥: {}", result.public_key_hex);
                println!("验证结果: {}", if result.is_valid { "成功" } else { "失败" });
            }
            
            // 测试反序列化功能
            match read_and_deserialize(SCHNORR_DATA_FILE) {
                Ok(deserialized) => {
                    println!("\n反序列化测试成功!");
                    println!("反序列化后记录数量: {}", deserialized.results.len());
                },
                Err(err) => eprintln!("反序列化失败: {}", err),
            }
        },
        Err(err) => eprintln!("序列化或写入文件失败: {}", err),
    }
}

// 执行Schnorr签名和验证
fn schnorr_sign_verify(message: &str) -> SchnorrResult {
    // 从文件读取ECIES私钥
    let priv_key_bytes = std::fs::read("../ecies/ecies-priv.der").unwrap_or_else(|e| {
        panic!("无法读取私钥文件: {}", e);
    });
    
    // 从私钥字节创建SigningKey
    let mut signing_key = SigningKey::from_bytes((&priv_key_bytes[..32]).into()).unwrap_or_else(|e| {
        panic!("无法从字节创建签名密钥: {}", e);
    });
    
    // 从文件读取ECIES公钥
    let pub_key_bytes = std::fs::read("../ecies/ecies-pub.der").unwrap_or_else(|e| {
        panic!("无法读取公钥文件: {}", e);
    });
    
    // 检查公钥字节长度
    println!("ECIES公钥字节长度: {}", pub_key_bytes.len());
    
    // 从公钥字节创建VerifyingKey（如果公钥是65字节格式，我们取中间32字节）
    let verifying_key = if pub_key_bytes.len() == 65 {
        // SEC1格式公钥（0x04 + x + y），取x坐标的32字节
        VerifyingKey::from_bytes(&pub_key_bytes[1..33]).unwrap_or_else(|e| {
            panic!("无法从字节创建验证密钥: {}", e);
        })
    } else if pub_key_bytes.len() == 32 {
        // 直接使用32字节公钥
        VerifyingKey::from_bytes(&pub_key_bytes).unwrap_or_else(|e| {
            panic!("无法从字节创建验证密钥: {}", e);
        })
    } else {
        panic!("不支持的公钥格式，长度: {}", pub_key_bytes.len());
    };
    
    // 使用签名密钥生成Schnorr签名
    let signature = signing_key.sign(message.as_bytes());
    
    // 验证Schnorr签名是否有效
    let is_valid = verifying_key.verify(message.as_bytes(), &signature).is_ok();
    
    // 将公钥和签名转换为十六进制字符串
    let public_key_bytes: [u8; 32] = verifying_key.to_bytes().into();
    let public_key_hex = hex::encode(public_key_bytes);
    let signature_hex = hex::encode(signature.to_bytes());
    
    // 创建结果数据结构
    SchnorrResult {
        message: message.to_string(),
        signature_hex,
        public_key_hex,
        is_valid,
    }
}


// // 执行Schnorr签名和验证
// fn schnorr_sign_verify(message: &str) -> SchnorrResult {
//     // 生成随机Schnorr签名密钥
//     let mut signing_key = SigningKey::random(&mut OsRng);

//     // 使用签名密钥生成Schnorr签名
//     let signature = signing_key.sign(message.as_bytes());
    
//     // 获取对应的验证密钥
//     let verifying_key = signing_key.verifying_key();
    
//     // 验证Schnorr签名是否有效
//     let is_valid = verifying_key.verify(message.as_bytes(), &signature).is_ok();
    
//     // 将公钥和签名转换为十六进制字符串
//     let public_key_bytes: [u8; 32] = verifying_key.to_bytes().into();
//     let public_key_hex = hex::encode(public_key_bytes);
//     let signature_hex = hex::encode(signature.to_bytes());
    
//     // 创建结果数据结构
//     SchnorrResult {
//         message: message.to_string(),
//         signature_hex,
//         public_key_hex,
//         is_valid,
//     }
// }

// 使用rkyv将结果序列化并写入文件
fn serialize_and_write(result: &SchnorrResults, file_path: &str) -> Result<(), std::io::Error> {
    // 使用rkyv序列化结果
    let bytes = rkyv::to_bytes::<_, 4096>(result)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("序列化失败: {}", e)))?;
    
    // 打开或创建文件
    let mut file = File::create(file_path)?;
    
    // 写入序列化后的二进制数据
    file.write_all(&bytes)?;
    
    println!("序列化后大小: {} 字节", bytes.len());
    
    Ok(())
}

// 从文件读取并使用rkyv反序列化
fn read_and_deserialize(file_path: &str) -> Result<SchnorrResults, std::io::Error> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "文件不存在"));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    
    // 使用rkyv反序列化
    // 注意：archived_root 不会进行安全检查，应只用于从可信来源读取数据
    let archived = unsafe {
        rkyv::archived_root::<SchnorrResults>(&buffer)
    };
    
    // 将存档值转换回原始类型
    let deserialized = archived.deserialize(&mut rkyv::Infallible).unwrap();
    
    Ok(deserialized)
}