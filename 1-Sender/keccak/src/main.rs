use clap::Parser;
use rkyv::{Archive, Serialize, Deserialize};
use hex;
use std::fs::File;
use std::io::{Write, Read};
use std::path::Path;
use tiny_keccak::{Hasher, Keccak};

use common::constants::KECCAK_HASH_FILE;

// 定义命令行参数结构
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 要计算哈希的消息
    #[arg(short, long)]
    message: String,
}

// 定义输出数据结构，使用rkyv序列化
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct HashResult {
    message: String,
    hash: String,
}

fn main() {
    // 解析命令行参数
    let args = Args::parse();
    
    println!("处理消息: {}", args.message);
    
    // 计算KECCAK-256哈希值
    let mut hasher = Keccak::v256();
    hasher.update(args.message.as_bytes());
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    let hash_hex = hex::encode(output);
    
    println!("KECCAK-256哈希值: {}", hash_hex);
    
    // 创建结果数据结构
    let result = HashResult {
        message: args.message,
        hash: hash_hex,
    };
    
    // 将结果使用rkyv序列化并写入文件
    match serialize_and_write(&result, KECCAK_HASH_FILE) {
        Ok(_) => {
            println!("结果已成功写入文件: {}", KECCAK_HASH_FILE);
            
            // 测试反序列化功能
            match read_and_deserialize(KECCAK_HASH_FILE) {
                Ok(deserialized) => {
                    println!("\n反序列化测试成功!");
                    println!("反序列化后的消息: {}", deserialized.message);
                    println!("反序列化后的哈希: {}", deserialized.hash);
                },
                Err(err) => eprintln!("反序列化失败: {}", err),
            }
        },
        Err(err) => eprintln!("序列化或写入文件失败: {}", err),
    }
}

// 使用rkyv将结果序列化并写入文件
fn serialize_and_write(result: &HashResult, file_path: &str) -> Result<(), std::io::Error> {
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
fn read_and_deserialize(file_path: &str) -> Result<HashResult, std::io::Error> {
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