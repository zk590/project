use clap::Parser;
use dotenv::dotenv;
use alloy_sol_types::SolType;
use hex;
use keccak_lib::{PublicValuesStruct, DEFAULT_MESSAGE, DEFAULT_HASH};
use common::constants::KECCAK_HASH_FILE;
use zkm_sdk::include_elf;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("keccak");
use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;
use zkm_sdk::{ZKMStdin, ProverClient};

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

// 从文件读取并使用rkyv反序列化
fn read_and_deserialize(file_path: &str) -> Result<HashResults, std::io::Error> {
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
    /// 仅执行程序，不生成证明
    #[clap(long)]
    execute: bool,
    
    /// 生成core proof
    #[clap(long)]
    core: bool,
    
    /// 生成compressed proof
    #[clap(long)]
    compressed: bool,
    
    /// 证明系统类型，如plonk
    #[arg(long)]
    system: Option<String>,
    
    /// 输入文件路径
    #[clap(short, long)]
    input: Option<String>,
    
    /// 输出证明文件路径
    #[clap(short, long, default_value = "proof.bin")]
    output: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let args = Args::parse();
    
    // 初始化证明器客户端
    let client = ProverClient::new();
    
    // 创建输入流
    let mut stdin = ZKMStdin::new();
    
    // 处理输入数据
    let input_path = args.input.as_deref().unwrap_or(KECCAK_HASH_FILE);
    
    // 从文件读取输入数据
    let hash_results = read_and_deserialize(input_path).expect("无法从文件中反序列化数据");
    
    println!("从文件中加载的数据:");
    println!("- 总共有 {} 条记录", hash_results.results.len());
    
    // 打印前3条记录作为示例
    let display_count = hash_results.results.len().min(3);
    for (index, result) in hash_results.results.iter().take(display_count).enumerate() {
        println!("示例记录 #{}:", index + 1);
        println!("  消息: {}", result.message);
        println!("  哈希值: {}", result.hash);
    }
    
    // 先写入结果列表的长度
    stdin.write(&(hash_results.results.len() as u32));
    
    // 然后逐个写入每个哈希结果
    for result in &hash_results.results {
        let message = result.message.as_bytes();
        let hash_value = hex::decode(&result.hash).expect("无效的hex哈希值");
        
        // 先写入消息长度和内容
        stdin.write(&(message.len() as u32));
        for byte in message {
            stdin.write(&byte);
        }
        
        // 先写入哈希值长度和内容
        stdin.write(&(hash_value.len() as u32));
        for byte in hash_value {
            stdin.write(&byte);
        }
    }
    
    // Setup the program for proving.
    let (pk, vk) = client.setup(ELF);

    // 检查参数是否合法
    let mut specified_count = 0;
    if args.execute { specified_count += 1; }
    if args.core { specified_count += 1; }
    if args.compressed { specified_count += 1; }
    if args.system.is_some() { specified_count += 1; }
    
    if specified_count != 1 {
        eprintln!("Error: You must specify exactly one of --execute, --core, --compressed, or --system");
        std::process::exit(1);
    }

    // 确定执行模式
    let proof = if args.execute {
        // 仅执行程序，不生成证明
        let start = Instant::now();
        let (output, report) = client.execute(ELF, stdin).run()?;
        let duration = start.elapsed();
        println!("程序执行成功。执行周期数: {}", report.total_instruction_count());
        println!("程序执行耗时: {:?}", duration);
         // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        let PublicValuesStruct { allValid } = decoded;
        println!("All tests passed: {}", allValid);
        return Ok(());
    } else if args.core {
        // 生成core proof
        let start = Instant::now();
        let proof = client.prove(&pk, stdin).compressed().run()?;
        let duration = start.elapsed();
        println!("证明生成完成，耗时: {:?}", duration);
        proof
    } else if args.compressed {
        // 生成compressed proof
        let start = Instant::now();
        let proof = client.prove(&pk, stdin).compressed().run()?;
        let duration = start.elapsed();
        println!("证明生成完成，耗时: {:?}", duration);
        proof
    } else if let Some(system) = &args.system {
        // 根据指定的证明系统生成证明
        let start = Instant::now();
        let proof = match system.as_str() {
            "plonk" => {
                client.prove(&pk, stdin).plonk().run()?
            },
            _ => {
                eprintln!("Error: Unsupported proof system: {}", system);
                std::process::exit(1);
            }
        };
        let duration = start.elapsed();
        println!("{}证明生成完成，耗时: {:?}", system, duration);
        proof
    } else {
        // 默认生成core proof
        let start = Instant::now();
        let proof = client.prove(&pk, stdin).core().run()?;
        let duration = start.elapsed();
        println!("证明生成完成，耗时: {:?}", duration);
        proof
    };

    // 注意：证明生成的时间已经在各个分支中分别测量并输出了
    
    // 验证证明
    println!("验证证明...");
    let start = Instant::now();
    client.verify(&proof, &vk)?;
    let duration = start.elapsed();
    println!("证明验证通过，耗时: {:?}", duration);
    
    // 解析并显示公共值
    let public_values: PublicValuesStruct = PublicValuesStruct::abi_decode(proof.public_values.as_slice())?;
    println!("验证结果: 所有哈希值验证有效 = {}", public_values.allValid);
    
    // 保存证明到文件
    println!("保存证明到文件: {}", args.output);
    let mut file = File::create(&args.output)?;
    file.write_all(&proof.bytes())?;
    println!("证明文件保存成功");
    
    Ok(())
}