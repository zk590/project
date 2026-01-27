use clap::Parser;
use rkyv::{Archive, Serialize, Deserialize};
use sha2::{Digest, Sha256};
use hex;
use std::fs::File;
use std::io::{Write, Read, BufRead, BufReader};
use std::path::Path;
use std::time::Instant;
use common::constants::SHA2_HASH_BATCH_FILE;

// 定义命令行参数结构
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 包含多行消息的输入文件路径
    #[arg(short, long)]
    input_file: String,
}

// 定义单个哈希结果数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct HashResult {
    message: String,
    hash: String,
}

// 定义多个哈希结果的集合数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct HashResults {
    results: Vec<HashResult>,
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
    
    
    // 为每条消息计算SHA-256哈希
    let mut results = Vec::new();
    // 记录加密开始时间
    let start_time = Instant::now();
    
    for (index, message) in messages.iter().enumerate() {
        
        // 计算SHA-256哈希值
        let hash = Sha256::digest(message.as_bytes());
        let hash_hex = hex::encode(hash);
        if index==1 {
            println!("The SHA256.Preimage = {}",message);
            println!("The SHA256.hash = {}",hash_hex);
        }
        
        // 创建结果数据结构
        results.push(HashResult {
            message: message.clone(),
            hash: hash_hex,
        });
    }
     // 记录加密结束时间
    let end_time = Instant::now();
    let duration = end_time.duration_since(start_time);
    println!("使用SHA-256算法对 {} 条消息进行哈希耗时: {:?}", messages.len(), duration);
    
    // 创建结果集合
    let hash_results = HashResults {
        results,
    };
    
    // 将结果使用rkyv序列化并写入文件
    match serialize_results(&hash_results, SHA2_HASH_BATCH_FILE) {
        Ok(_) => {
            println!("所有结果已成功写入文件");
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
fn serialize_results(results: &HashResults, file_path: &str) -> Result<(), std::io::Error> {
    // 使用rkyv序列化结果
    let bytes = rkyv::to_bytes::<_, 256>(results)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "序列化失败"))?;
    
    // 打开或创建文件
    let mut file = File::create(file_path)?;
    
    // 写入序列化后的字节
    file.write_all(&bytes)?;
    
    Ok(())
}

// 从文件读取并使用rkyv反序列化结果集合
fn read_results(file_path: &str) -> Result<HashResults, std::io::Error> {
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