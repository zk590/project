use rkyv::{Archive, Deserialize, Serialize};
use clap::Parser;
use alloy_sol_types::SolType;
use zkm_sdk::{include_elf, HashableKey, ProverClient, ZKMStdin};
use std::time::Instant;

use common::constants::FIBONACCI_MUL_DATA_FILE;
use fibonacci_mul_lib::{PublicValuesStruct, SerializedProof, serialize_stark_proof, serialize_plonk_proof, read_and_deserialize};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-mul");

/// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(about = "Fibonacci Multiplication zkVM Prover")]
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
}



// 定义证明数据结构，用于rkyv序列化
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct ProofData {
    proof: Vec<u8>,
    public_values: Vec<u8>,
    vk_bytes: Vec<u8>,
}

fn main() {
    // 从文件中反序列化斐波那契结果数据
    let fibonacci_result = read_and_deserialize(FIBONACCI_MUL_DATA_FILE).expect("无法从文件中反序列化数据");

    // 提取项数n
    let n = fibonacci_result.n as u32;

    println!("从文件中加载的数据:");
    println!("- 项数n: {}", n);
    println!("- 预期结果a: {}", fibonacci_result.a);
    println!("- 预期结果b: {}", fibonacci_result.b);

    // The input stream that the program will read from using `zkm_zkvm::io::read`.
    let mut stdin = ZKMStdin::new();
    // 写入项数n
    stdin.write(&n);

    // 解析命令行参数
    let args = Args::parse();

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

    // Setup the prover client.
    let client = ProverClient::new();

    if args.execute {
        // Execute the program
        let start_time = Instant::now();
        let (output, report) = client.execute(ELF, stdin).run().unwrap();
        let elapsed = start_time.elapsed();
        println!("Program executed successfully. Execution time: {:?}", elapsed);

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        let PublicValuesStruct { n, a, b } = decoded;
        println!("Fibonacci Results:");
        println!("  n: {}", n);
        println!("  a: {}", a);
        println!("  b: {}", b);

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(ELF);

        // Generate the proof
        let proof: zkm_sdk::ZKMProofWithPublicValues = if args.core || args.compressed {
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

        // 将证明、公共值和验证密钥序列化为文件
        let SerializedProof { proof, public_values, vk_bytes } = if args.system.as_deref() == Some("plonk") {
            serialize_plonk_proof(&proof, &vk)
        } else {
            serialize_stark_proof(&proof, &vk)
        };

        let proof_data = ProofData {
            proof,
            public_values,
            vk_bytes,
        };
        
        // 使用rkyv序列化
        let bytes = rkyv::to_bytes::<_, 256>(&proof_data).expect("序列化失败");
        
        // 写入文件
        let output_file = "fibonacci_mul_proof_data.bin";
        std::fs::write(output_file, bytes).expect("写入文件失败");
        println!("证明数据已成功序列化到文件: {}", output_file);
        println!("vk hash: {}", vk.bytes32());
    }
}