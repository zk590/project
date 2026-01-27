use alloy_sol_types::SolType;
use clap::Parser;
use rsa_lib::PublicValuesStruct;
use zkm_sdk::{ProverClient, ZKMStdin, include_elf, HashableKey};
use hex;
use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write, Error as IoError, ErrorKind};
use std::path::Path;
use std::time::Instant;
use dotenv::dotenv;

/// The ELF (executable and linkable format) file for the zkMIPS zkVM.
pub const RSA_ELF: &[u8] = include_elf!("rsa");

// 包含2048位RSA密钥的DER格式数据
const RSA_2048_PUB_DER: &[u8] = include_bytes!("../rsa2048-pub.der");

// 定义单个签名结果数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct SignatureResult {
    message: String,
    signature_hex: String,
}

// 定义多个签名结果的集合数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct SignatureResults {
    results: Vec<SignatureResult>,
}

// 定义用于序列化证明和公共值的数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct ProofData {
    proof: Vec<u8>,
    public_values: Vec<u8>,
    vk_bytes: String,
}

// 从文件读取并使用rkyv反序列化
fn read_and_deserialize(file_path: &str) -> Result<SignatureResults, IoError> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(IoError::new(ErrorKind::NotFound, "文件不存在"));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    // 使用rkyv反序列化
    let deserialized = rkyv::from_bytes(&bytes)
        .map_err(|_| IoError::new(ErrorKind::Other, "反序列化失败"))?;
    
    Ok(deserialized)
}

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
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
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    // Setup the prover client.
    let client = ProverClient::new();

    // 从文件中反序列化批量签名结果数据
    let input_path = args.input.as_deref().unwrap_or("/opt/project/1-Sender/rsa/rsa_hash.bin");
    let signature_results = read_and_deserialize(input_path).expect("无法从文件中反序列化数据");
    
    println!("从文件中加载的数据:");
    println!("- 总共有 {} 条记录", signature_results.results.len());
    
    // 打印前3条记录作为示例
    let display_count = signature_results.results.len().min(3);
    for (index, result) in signature_results.results.iter().take(display_count).enumerate() {
        println!("示例记录 #{}:", index + 1);
        println!("  消息: {}", result.message);
        println!("  签名: {}", result.signature_hex);
    }

    // 创建输入流
    let mut stdin = ZKMStdin::new();
    
    // 先写入结果列表的长度
    stdin.write(&(signature_results.results.len() as u32));
    
    // 使用包含的公钥DER数据
    let public_key_der = RSA_2048_PUB_DER;
    
    // 逐个写入每个签名结果
    for result in &signature_results.results {
        let message = result.message.as_bytes();
        let signature = hex::decode(&result.signature_hex).expect("无效的hex签名值");
        
        // 先写入消息长度和内容
        stdin.write(&(message.len() as u32));
        for byte in message {
            stdin.write(&byte);
        }
        
        // 先写入签名长度和内容
        stdin.write(&(signature.len() as u32));
        for byte in signature {
            stdin.write(&byte);
        }
        
        // 先写入公钥长度和内容
        stdin.write(&(public_key_der.len() as u32));
        for byte in public_key_der {
            stdin.write(&byte);
        }
    }

    // Setup the program for proving.
    let (pk, vk) = client.setup(RSA_ELF);

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
        let (output, report) = client.execute(RSA_ELF, stdin).run()?;
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
        let proof = client.prove(&pk, stdin).core().run()?;
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

    // 验证证明
    println!("验证证明...");
    let start = Instant::now();
    client.verify(&proof, &vk)?;
    let duration = start.elapsed();
    println!("证明验证通过，耗时: {:?}", duration);
    
    // 解析并显示公共值
    let public_values: PublicValuesStruct = PublicValuesStruct::abi_decode(proof.public_values.as_slice())?;
    println!("验证结果: 所有签名验证有效 = {}", public_values.allValid);
    
    // 保存证明到文件
    println!("保存证明到文件: {}", args.output);
    let mut file = File::create(&args.output)?;
    file.write_all(&proof.bytes())?;
    println!("证明文件保存成功");
    
    Ok(())
}