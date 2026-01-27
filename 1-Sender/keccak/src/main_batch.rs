use rkyv::{Archive, Serialize, Deserialize};
use hex;
use std::fs::File;
use std::io::{Write, Read};
use std::path::Path;
use tiny_keccak::{Hasher, Keccak};
use clap::Parser;
use common::constants::KECCAK_HASH_BATCH_FILE;
use std::time::Instant;

// 定义命令行参数结构
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 包含多条消息的输入文件路径
    #[arg(short, long)]
    input_file: String,
}

// 定义单条哈希结果数据结构，使用rkyv序列化
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct HashResult {
    message: String,
    hash: String,
}

// 定义多条哈希结果集合数据结构，使用rkyv序列化
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct HashResults {
    results: Vec<HashResult>,
}

fn main() {
    // 解析命令行参数
    let args = Args::parse();
    
    // 从文件读取多条消息
    match read_messages_from_file(&args.input_file) {
        Ok(messages) => {
            // println!("成功读取 {} 条消息", messages.len());
            
            // 为每条消息计算KECCAK-256哈希值
            let mut results = Vec::new();
            // 记录加密开始时间
            let start_time = Instant::now();

            for (i, message) in messages.iter().enumerate() {            
                // 计算KECCAK-256哈希值
                let mut hasher = Keccak::v256();
                hasher.update(message.as_bytes());
                // Keccak-256标准输出大小为256位(32字节)
                let mut output = [0u8; 32];  
                hasher.finalize(&mut output);
                let hash_hex = hex::encode(output);
                if i==1 {
                    println!("The KECCAK.Preimage = {}",message);
                    println!("The KECCAK.hash = {}",hash_hex);
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
            println!("使用KECCAK-256算法对 {} 条消息进行哈希耗时: {:?}", messages.len(), duration);
            
            // 创建结果集合数据结构
            let hash_results = HashResults {
                results,
            };
            
            // 将结果使用rkyv序列化并写入文件
            match serialize_results(&hash_results, KECCAK_HASH_BATCH_FILE) {
                Ok(_) => {
                    println!("结果已成功写入文件");
                },
                Err(err) => eprintln!("序列化或写入文件失败: {}", err),
            }
        },
        Err(err) => eprintln!("读取文件失败: {}", err),
    }
}

// 从文件中读取多条消息，每行一条
fn read_messages_from_file(file_path: &str) -> Result<Vec<String>, std::io::Error> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "文件不存在"));
    }
    
    // 打开文件并读取所有行
    let mut file = File::open(file_path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    
    // 按行分割并过滤空行
    let messages: Vec<String> = content.lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    
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