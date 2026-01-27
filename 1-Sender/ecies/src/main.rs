use ecies::{PublicKey, SecretKey};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use clap::Parser;
use rand::rngs::ThreadRng;
use rand::Rng;
use std::time::Instant;
use hex;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 包含多条消息的输入文件路径
    #[arg(short, long, default_value = "messages.txt")]
    input_file: String,
    
    /// 加密结果输出文件路径
    #[arg(short, long, default_value = "ecies_encrypted.bin")]
    output_file: String,
    
    /// 接收方公钥文件路径
    #[arg(long, default_value = "ecies-pub.der")]

    pub_key_file: String,
    
    #[arg(long, default_value = "ecies-priv.der")]
    priv_file: String,
}

// 定义ECIES加密结果结构，包含原始消息和密文
struct EncryptedResult {
    message: String,
    encrypted_data: Vec<u8>,
}

fn main() {
    // 解析命令行参数
    let args = Args::parse();
    
    
    // 读取接收方公钥，如果读取失败则退出程序
    let receiver_pk = match read_public_key(&args.pub_key_file,&args.priv_file) {
        Ok(pk) => {
            pk
        },
        Err(err) => {
            eprintln!("读取公钥失败: {}", err);
            std::process::exit(1);
        }
    };
    
    // 从文件读取多条消息
    match read_messages_from_file(&args.input_file) {
        Ok(messages) => {
            
            // 为每条消息执行ECIES加密
            let mut encrypted_results = Vec::new();
            let mut rng = rand::thread_rng();

            // 记录加密开始时间
            let start_time = Instant::now();
            
            for (i, message) in messages.iter().enumerate() {               
                // 执行ECIES加密
                let encrypted_data = receiver_pk.clone().encrypt(&mut rng, message.as_bytes());
                if i==1 {
                    println!("The message = {}",message);
                    println!("ECIES.Ciphertext = {}",hex::encode(&encrypted_data));
                }
                // 保存加密结果，包含原始消息和密文
                encrypted_results.push(EncryptedResult {
                    message: message.clone(),
                    encrypted_data,
                });
            }
            // 记录加密结束时间
            let end_time = Instant::now();
            let duration = end_time.duration_since(start_time);
            println!("使用ECIES加密算法对 {} 条消息进行加密耗时: {:?}", messages.len(), duration);
            
            
            // 将加密结果写入文件
            match write_encrypted_results(&encrypted_results, &args.output_file) {
                Ok(_) => {
                    println!("\n所有消息已成功加密并写入文件");
                },
                Err(err) => eprintln!("写入加密结果失败: {}", err),
            }
        },
        Err(err) => eprintln!("读取输入文件失败: {}", err),
    }
}

// 从文件读取公钥
fn read_public_key(file_path: &str,priv_file_path: &str) -> Result<PublicKey, String> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(format!("公钥文件不存在: {}", file_path));
    }
    
    // 读取公钥文件内容
    let mut file = File::open(file_path).map_err(|e| format!("无法打开公钥文件: {}", e))?;
    let mut pub_key_bytes = Vec::new();
    file.read_to_end(&mut pub_key_bytes).map_err(|e| format!("读取公钥文件失败: {}", e))?;

    println!("ECIES.PK = {}", hex::encode(&pub_key_bytes));

    let mut priv_file = File::open(priv_file_path).map_err(|e| format!("无法打开私钥文件: {}", e))?;
    let mut priv_key_bytes = Vec::new();
    priv_file.read_to_end(&mut priv_key_bytes).map_err(|e| format!("读取私钥文件失败: {}", e))?;
    println!("ECIES.sk = {}", hex::encode(priv_key_bytes));

    // 解析公钥
    PublicKey::try_from_bytes(&pub_key_bytes).map_err(|_| "公钥格式无效".to_string())
}

// 从文件中读取多条消息，每行一条
fn read_messages_from_file(file_path: &str) -> Result<Vec<String>, String> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(format!("输入文件不存在: {}", file_path));
    }
    
    // 打开文件并读取所有行
    let mut file = File::open(file_path).map_err(|e| format!("无法打开输入文件: {}", e))?;
    let mut content = String::new();
    file.read_to_string(&mut content).map_err(|e| format!("读取输入文件失败: {}", e))?;
    
    // 按行分割并过滤空行
    let messages: Vec<String> = content.lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();
    //  println!("从文件{}成功读取 {} 条message",file_path, messages.len());
    Ok(messages)
}

// 将加密结果写入文件，包含原始消息和密文
fn write_encrypted_results(results: &[EncryptedResult], file_path: &str) -> Result<(), String> {
    // 创建输出文件
    let mut file = File::create(file_path).map_err(|e| format!("无法创建输出文件: {}", e))?;
    
    // 写入加密结果数量
    let count_bytes = (results.len() as u64).to_le_bytes();
    file.write_all(&count_bytes).map_err(|e| format!("写入加密结果数量失败: {}", e))?;
    
    // 逐个写入加密结果
    for result in results {
        // 写入原始消息长度和内容
        let message_len = result.message.len() as u64;
        file.write_all(&message_len.to_le_bytes()).map_err(|e| format!("写入消息长度失败: {}", e))?;
        file.write_all(result.message.as_bytes()).map_err(|e| format!("写入消息内容失败: {}", e))?;
        
        // 写入加密数据长度和内容
        let data_len = result.encrypted_data.len() as u64;
        file.write_all(&data_len.to_le_bytes()).map_err(|e| format!("写入加密数据长度失败: {}", e))?;
        file.write_all(&result.encrypted_data).map_err(|e| format!("写入加密数据失败: {}", e))?;
    }
    
    Ok(())
}