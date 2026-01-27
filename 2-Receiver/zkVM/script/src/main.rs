

use clap::Parser;
use rkyv::{Archive, Deserialize, Serialize};
use sp1_sdk::{include_elf, utils, HashableKey, ProverClient, SP1Stdin, SP1ProofWithPublicValues};
use std::fs::File;
use std::io::{Read, Error as IoError, ErrorKind};
use std::path::Path;
use std::process::exit;
use std::time::Instant;

/// The ELF for the Groth16 verifier program.
const PLONK_ELF: &[u8] = include_elf!("zkvm-verifier-program");


fn generate_proof(algorithm: &str) -> (Vec<u8>, Vec<u8>, String) {
    // 构建文件路径
    let base_path = format!("/opt/project/4-zkVM/{}/script", algorithm);
    let proof_path = format!("{}/proof.bin", base_path);
    let public_values_path = format!("{}/public_values.bin", base_path);
    let vk_hash_path = format!("{}/vk.bin", base_path);
    
    // 从指定路径读取proof、public_values和vk_hash
    let proof_bytes = match std::fs::read(&proof_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            eprintln!("错误: 找不到proof文件 {}。请确保该算法的证明文件存在。", proof_path);
            exit(1);
        },
        Err(err) => {
            eprintln!("错误: 读取proof文件 {} 失败: {}", proof_path, err);
            exit(1);
        }
    };
    
    let public_values = match std::fs::read(&public_values_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            eprintln!("错误: 找不到public_values文件 {}。请确保该算法的证明文件存在。", public_values_path);
            exit(1);
        },
        Err(err) => {
            eprintln!("错误: 读取public_values文件 {} 失败: {}", public_values_path, err);
            exit(1);
        }
    };
    
    let vk_hash_bytes = match std::fs::read(&vk_hash_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            eprintln!("错误: 找不到vk_hash文件 {}。请确保该算法的证明文件存在。", vk_hash_path);
            exit(1);
        },
        Err(err) => {
            eprintln!("错误: 读取vk_hash文件 {} 失败: {}", vk_hash_path, err);
            exit(1);
        }
    };
    
    // 将vk_hash_bytes转换为字符串
    let vk_hash = String::from_utf8(vk_hash_bytes.clone()).expect("failed to convert vk_hash_bytes to string");
    
    println!("成功从{}目录读取以下文件:", base_path);
    println!("- proof.bin: {} bytes", proof_bytes.len());
    println!("- public_values.bin: {} bytes", public_values.len());
    println!("- vk.bin: {} bytes (content: {})
", vk_hash_bytes.len(), vk_hash);
    
    (proof_bytes, public_values, vk_hash)
}

/// CLI arguments for the verifier script
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// The algorithm name for which to verify the proof (e.g., "fibonacci_add")
    algorithm: String,
}

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Parse command line arguments
    let args = Args::parse();
    
    // Generate the proof, public values and vk_hash for the specified algorithm.
    let (proof, public_values, vk_hash) = generate_proof(&args.algorithm);

    // Write the proof, public values and vk_hash to the input stream.
    let mut stdin = SP1Stdin::new();
    stdin.write(&proof);
    stdin.write(&public_values);
    stdin.write(&vk_hash);

    // Create a `ProverClient`.
    let client = ProverClient::from_env();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let start_time = Instant::now();
    let (_, report) = client.execute(PLONK_ELF, &stdin).run().unwrap();
    let duration = start_time.elapsed();
    println!("执行时间: {:?}", duration);
    println!("executed plonk program with {} cycles", report.total_instruction_count());
    println!("{}", report);
}