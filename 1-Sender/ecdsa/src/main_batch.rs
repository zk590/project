use clap::Parser;
use rkyv::{Archive, Serialize, Deserialize};
use k256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::Signer, signature::Verifier};
use hex;
use std::fs::File;
use std::io::{Write, Read, BufRead, BufReader};
use std::path::Path;
use std::time::Instant;

use common::constants::{PUB_KEY_PATH, PRIV_KEY_PATH, ECDSA_BATCH_DATA_FILE};

// 定义命令行参数结构
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 包含多行消息的输入文件路径
    #[arg(short, long)]
    input_file: String,
}

// 定义单个ECDSA签名结果数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct EcdsaResult {
    message: String,
    signature_hex: String,
    public_key_hex: String,
    is_valid: bool,
}

// 定义多个ECDSA签名结果的集合数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct EcdsaResults {
    results: Vec<EcdsaResult>,
}

// 读取公私钥文件并创建SigningKey和VerifyingKey（只需执行一次）
fn load_keys() -> (SigningKey, VerifyingKey) {
    // 从文件读取私钥
    let priv_key_bytes = std::fs::read(PRIV_KEY_PATH).unwrap_or_else(|e| {
        panic!("无法读取私钥文件: {}", e);
    });
    
    // 从私钥字节创建SigningKey
    let signing_key = SigningKey::from_bytes((&priv_key_bytes[..32]).into()).unwrap_or_else(|e| {
        panic!("无法从字节创建签名密钥: {}", e);
    });
    
    // 从文件读取公钥
    let pub_key_bytes = std::fs::read(PUB_KEY_PATH).unwrap_or_else(|e| {
        panic!("无法读取公钥文件: {}", e);
    });
    
    // 从公钥字节创建VerifyingKey
    let verifying_key = VerifyingKey::from_sec1_bytes(&pub_key_bytes).unwrap_or_else(|e| {
        panic!("无法从字节创建验证密钥: {}", e);
    });
    
    // 将密钥转换为十六进制字符串打印
    println!("ECDSA.sk = {}", hex::encode(signing_key.to_bytes()));
    println!("ECDSA.PK = {}", hex::encode(verifying_key.to_sec1_bytes()));
    
    (signing_key, verifying_key)
}

// 对消息进行签名和验证
fn ecdsa_sign_verify(message: &str, signing_key: &SigningKey, verifying_key: &VerifyingKey) -> EcdsaResult {
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

fn main() {
    // 解析命令行参数
    let args = Args::parse();
    
    
    // 检查输入文件是否存在
    if !Path::new(&args.input_file).exists() {
        eprintln!("错误: 输入文件 {} 不存在", args.input_file);
        std::process::exit(1);
    }
    
    // 从文件读取多行消息
    let messages = match read_messages_from_file(&args.input_file) {
        Ok(messages) => messages,
        Err(err) => {
            eprintln!("读取文件失败: {}", err);
            std::process::exit(1);
        }
    };
    
    println!("从文件{}成功读取 {} 条message",args.input_file, messages.len());
    
    // 为每条消息生成ECDSA签名
    let mut results = Vec::new();
    
    // 记录开始时间
    let start_time = Instant::now();
    
    // 只加载一次密钥
    let (signing_key, verifying_key) = load_keys();
    
    for (index, message) in messages.iter().enumerate() {   
        // let msg_start_time = Instant::now();
        
        // 执行ECDSA签名和验证
        let result = ecdsa_sign_verify(message, &signing_key, &verifying_key);
        
        // let msg_duration = msg_start_time.elapsed();
        // println!("消息 #{} 处理时间: {:?}", index + 1, msg_duration);
        if index == 1 {
            println!("The message = {}",result.message);
            println!("ECDSA.sig = {}",result.signature_hex);
        }
        // 添加到结果集合
        results.push(result);
    }
    
    // 计算总执行时间
    let total_duration = start_time.elapsed();
    // let avg_duration = if !messages.is_empty() {
    //     total_duration / messages.len() as u32
    // } else {
    //     total_duration
    // };
    
    println!("使用ECDSA签名算法对 {} 条消息进行签名耗时: {:?}", messages.len(), total_duration);
    
    // 创建结果集合
    let ecdsa_results = EcdsaResults {
        results,
    };
    
    // 将结果使用rkyv序列化并写入文件
    match serialize_results(&ecdsa_results, ECDSA_BATCH_DATA_FILE) {
        Ok(_) => {
            println!("签名结果已成功写入文件");
        },
        Err(err) => eprintln!("序列化或写入文件失败: {}", err),
    }
}

// 从文件读取多行消息
fn read_messages_from_file(file_path: &str) -> Result<Vec<String>, std::io::Error> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut messages = Vec::new();
    
    for line in reader.lines() {
        match line {
            Ok(message) => {
                // 跳过空行
                if !message.trim().is_empty() {
                    messages.push(message);
                }
            },
            Err(err) => return Err(err),
        }
    }
    
    Ok(messages)
}

// 使用rkyv将结果集合序列化并写入文件
fn serialize_results(results: &EcdsaResults, file_path: &str) -> Result<(), std::io::Error> {
    // 使用rkyv序列化结果
    let bytes = rkyv::to_bytes::<_, 4096>(results)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "序列化失败"))?;
    
    // 打开或创建文件
    let mut file = File::create(file_path)?;
    
    // 写入序列化后的字节
    file.write_all(&bytes)?;
    
    // println!("序列化字节大小: {} 字节", bytes.len());
    
    Ok(())
}

// 从文件读取并使用rkyv反序列化结果集合
fn read_results(file_path: &str) -> Result<EcdsaResults, std::io::Error> {
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