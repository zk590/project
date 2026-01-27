use clap::Parser;
use dotenv::dotenv;
use ecdsa_lib::{PublicValuesStruct, DEFAULT_MESSAGE, DEFAULT_PUBLIC_KEY, DEFAULT_SIGNATURE};
use hex;
use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;
use zkm_sdk::{ZKMStdin, ProverClient};

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

// 从文件读取并使用rkyv反序列化
fn read_and_deserialize(file_path: &str) -> Result<EcdsaResults, std::io::Error> {
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

#[derive(Parser)]
struct Args {
    /// 执行模式: execute, core, compressed
    #[clap(short, long, default_value = "execute")]
    mode: String,
    
    /// 输入文件路径
    #[clap(short, long)]
    input: Option<String>,
    
    /// 输出证明文件路径
    #[clap(short, long, default_value = "proof.bin")]
    output: String,
}

fn main() {
    dotenv().ok();
    let args = Args::parse();
    
    // 初始化证明器客户端
    let client = ProverClient::new();
    
    // 创建输入流
    let mut stdin = ZKMStdin::new();
    
    // 处理输入数据
    if let Some(input_path) = args.input {
        // 从文件读取输入数据
        let ecdsa_results = read_and_deserialize(&input_path).expect("无法从文件中反序列化数据");
        
        println!("从文件中加载的数据:");
        println!("- 总共有 {} 条记录", ecdsa_results.results.len());
        
        // 打印前3条记录作为示例
        let display_count = ecdsa_results.results.len().min(3);
        for (index, result) in ecdsa_results.results.iter().take(display_count).enumerate() {
            println!("示例记录 #{}:", index + 1);
            println!("  消息: {}", result.message);
            println!("  签名: {}", result.signature_hex);
            println!("  公钥: {}", result.public_key_hex);
            println!("  预期验证结果: {}", result.is_valid);
        }
        
        // 先写入结果列表的长度
        stdin.write(&(ecdsa_results.results.len() as u32));
        
        // 然后逐个写入每个ECDSA结果
        for result in &ecdsa_results.results {
            let message = result.message.as_bytes();
            let signature_bytes = hex::decode(&result.signature_hex).expect("无效的hex签名数据");
            let public_key_bytes = hex::decode(&result.public_key_hex).expect("无效的hex公钥数据");
            
            // 先写入消息长度和内容
            stdin.write(&(message.len() as u32));
            for byte in message {
                stdin.write(&byte);
            }
            
            // 先写入签名长度和内容
            stdin.write(&(signature_bytes.len() as u32));
            for byte in signature_bytes {
                stdin.write(&byte);
            }
            
            // 先写入公钥长度和内容
            stdin.write(&(public_key_bytes.len() as u32));
            for byte in public_key_bytes {
                stdin.write(&byte);
            }
        }
    } else {
        // 使用默认测试数据
        println!("使用默认测试数据");
        println!("- 消息: {}", String::from_utf8_lossy(DEFAULT_MESSAGE));
        println!("- 公钥: {}", DEFAULT_PUBLIC_KEY);
        println!("- 签名: {}", DEFAULT_SIGNATURE);
        
        // 写入结果列表的长度（1条）
        stdin.write(&1u32);
        
        // 写入消息
        let message = DEFAULT_MESSAGE;
        stdin.write(&(message.len() as u32));
        for byte in message {
            stdin.write(&byte);
        }
        
        // 写入签名
        let signature_bytes = hex::decode(DEFAULT_SIGNATURE).expect("无效的hex签名数据");
        stdin.write(&(signature_bytes.len() as u32));
        for byte in signature_bytes {
            stdin.write(&byte);
        }
        
        // 写入公钥
        let public_key_bytes = hex::decode(DEFAULT_PUBLIC_KEY).expect("无效的hex公钥数据");
        stdin.write(&(public_key_bytes.len() as u32));
        for byte in public_key_bytes {
            stdin.write(&byte);
        }
    }
    
    // 执行证明
    println!("执行证明...");
    let start = Instant::now();
    
    let proof = match args.mode.as_str() {
        "execute" => client.execute_with_stdin(stdin),
        "core" => client.core_prove_with_stdin(stdin),
        "compressed" => client.compressed_prove_with_stdin(stdin),
        _ => panic!("无效的模式: {}", args.mode),
    };
    
    let duration = start.elapsed();
    println!("证明生成完成，耗时: {:?}", duration);
    
    // 验证证明
    println!("验证证明...");
    let start = Instant::now();
    proof.verify()?;
    let duration = start.elapsed();
    println!("证明验证通过，耗时: {:?}", duration);
    
    // 解析并显示公共值
    let public_values: PublicValuesStruct = proof.public_values()?;
    println!("验证结果: 所有签名有效 = {}", public_values.allValid);
    
    // 保存证明到文件
    println!("保存证明到文件: {}", args.output);
    let mut file = File::create(&args.output)?;
    file.write_all(&proof.to_bytes())?;
    println!("证明文件保存成功");
    
    Ok(())
}