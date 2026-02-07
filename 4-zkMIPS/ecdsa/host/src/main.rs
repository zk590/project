use clap::Parser;
use dotenv::dotenv;
use ecdsa_lib::{PublicValuesStruct, read_and_deserialize};
use common::constants::ECDSA_BATCH_DATA_FILE;
use hex;
use alloy_sol_types::SolType;
use std::fs::File;
use std::io::Write;
use std::time::Instant;
use zkm_sdk::{include_elf, ZKMStdin, ProverClient, HashableKey};

// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("ecdsa");




/// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(about = "ECDSA zkVM Prover")]
struct Args {
    /// 仅执行程序，不生成证明
    #[arg(long)]
    execute: bool,
    
    /// 生成核心证明
    #[arg(long)]
    core: bool,
    
    /// 生成压缩证明
    #[arg(long)]
    compressed: bool,
    
    /// 指定证明系统类型
    #[arg(long)]
    system: Option<String>,
    
    /// 输入文件路径
    #[arg(long)]
    input: Option<String>,
    
    /// 输出证明文件路径
    #[arg(long, default_value = "proof.bin")]
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
    // 使用constants.rs中定义的ECDSA_BATCH_DATA_FILE
    // 从文件读取输入数据
    let ecdsa_results = read_and_deserialize(ECDSA_BATCH_DATA_FILE).expect("无法从文件中反序列化数据");
    
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

    
    // 检查参数是否合法
    let mut specified_count = 0;
    if args.execute { specified_count += 1; }
    if args.core { specified_count += 1; }
    if args.compressed { specified_count += 1; }
    if args.system.is_some() { specified_count += 1; }
    
    if specified_count != 1 {
        eprintln!("Error: You must specify exactly one of --execute, --core, --compress, or --system");
        std::process::exit(1);
    }

    if args.execute {
        // Execute the program
        let start_time = Instant::now();
        let (output, report) = client.execute(ELF, stdin).run().unwrap();
        let elapsed = start_time.elapsed();
        println!("Program executed successfully. Execution time: {:?}", elapsed);

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        println!("Verification result: All signatures valid = {}", decoded.allValid);

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(ELF);

        // Generate the proof
        let proof = if args.core || args.compressed {
            // 生成compressed proof
            let start_time = Instant::now();
            let proof = client.prove(&pk, stdin).compressed().run().expect("failed to generate Compressed proof");
            let duration = start_time.elapsed();
            println!("generated compressed proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
            proof
        } else if let Some(system) = &args.system {
            // 根据指定的系统类型生成proof
            let start_time = Instant::now();
            let proof = match system.as_str() {
                "plonk" => {
                    client.prove(&pk, stdin).plonk().run().expect("failed to generate Plonk proof")
                },
                _ => {
                    eprintln!("Error: Unsupported proof system: {}", system);
                    std::process::exit(1);
                }
            };
            let duration = start_time.elapsed();
            println!("generated {} proof in {}.{:03} seconds", system, duration.as_secs(), duration.subsec_millis());
            proof
        } else {
            // 默认生成compressed proof
            let start_time = Instant::now();
            let proof = client.prove(&pk, stdin).compressed().run().expect("failed to generate default proof");
            let duration = start_time.elapsed();
            println!("generated compressed proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
            proof
        };
        println!("Successfully generated proof!");

        // Verify the proof.
        let start_time = Instant::now();
        client.verify(&proof, &vk).expect("failed to verify proof");
        let duration = start_time.elapsed();
        println!("verified proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
        println!("Successfully verified proof!");

        // 解析并显示公共值
        let public_values: PublicValuesStruct = PublicValuesStruct::abi_decode(proof.public_values.as_slice())?;
        println!("验证结果: 所有签名有效 = {}", public_values.allValid);
        
        // 保存证明到文件
        println!("保存证明到文件: {}", args.output);
        let mut file = File::create(&args.output)?;
        file.write_all(&proof.bytes())?;
        println!("证明文件保存成功");
        println!("vk hash: {}", vk.bytes32());
    };
    
    Ok(())
}