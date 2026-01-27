//! A script that verifies a Plonk proof in ZKM.

use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::time::Instant;
use zkm_sdk::{include_elf, utils, ProverClient, ZKMStdin};
use clap::{Parser, ValueEnum};

/// The ELF for the Plonk verifier program.
const PLONK_ELF: &[u8] = include_elf!("plonk-verifier");

/// The ProofData structure that matches the serialized data in sha3_proof_data.bin
#[derive(Archive, Deserialize, Serialize, Debug)]
pub struct ProofData {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
    pub vk_bytes: Vec<u8>,
}

/// 支持的算法类型
#[derive(Debug, Clone, ValueEnum)]
enum Algorithm {
    Sha2,
    Sha3,
    FibonacciAdd,
}

/// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(about = "ZKM Plonk 证明验证工具")]
struct Args {
    /// 要验证的算法
    #[arg(short, long, required = true, value_enum)]
    algorithm: Algorithm,
}

fn load_proof_data(algorithm: &Algorithm) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // 根据算法类型确定证明数据文件路径
    let proof_data_path = match algorithm {
        Algorithm::Sha2 => "/opt/project/5-zkMIPS/sha2/host/sha2_proof_data.bin",
        Algorithm::Sha3 => "/opt/project/5-zkMIPS/sha3/host/sha3_proof_data.bin",
        Algorithm::FibonacciAdd => "/opt/project/5-zkMIPS/fibonacci_add/host/fibonacci_add_proof_data.bin",
    };
    
    // 反序列化证明数据文件
    let mut file = File::open(proof_data_path)
        .expect(&format!("Failed to open {}", proof_data_path));
    
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .expect(&format!("Failed to read {}", proof_data_path));
    
    // 使用 rkyv 反序列化数据
    let proof_data: ProofData = unsafe {
        rkyv::archived_root::<ProofData>(&data)
            .deserialize(&mut rkyv::Infallible)
            .expect("Failed to deserialize ProofData")
    };
    
    println!("Successfully deserialized {}", proof_data_path);
    println!("Proof length: {}", proof_data.proof.len());
    println!("Public values length: {}", proof_data.public_values.len());
    println!("Verification key bytes length: {}", proof_data.vk_bytes.len());
    
    // 返回反序列化的proof、public_values和vk_bytes
    (proof_data.proof, proof_data.public_values, proof_data.vk_bytes)
}

fn load_plonk_vk() -> Vec<u8> {
    // 读取plonk_vk.bin文件
    let plonk_vk_path = "/opt/project/2-Receiver/zkMIPS/Plonk/host/plonk_vk.bin";
    let mut file = File::open(plonk_vk_path)
        .expect(&format!("Failed to open {}", plonk_vk_path));
    
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .expect(&format!("Failed to read {}", plonk_vk_path));
    
    println!("Successfully read {}", plonk_vk_path);
    println!("Plonk VK length: {}", data.len());
    
    data
}

fn main() {
    // Parse command line arguments
    let args = Args::parse();
    
    // Setup logging.
    utils::setup_logger();

    // Load the proof data based on the specified algorithm.
    let (proof, public_values, vk_bytes) = load_proof_data(&args.algorithm);
    
    // Load the Plonk verifying key.
    let plonk_vk = load_plonk_vk();

    // Write the proof, public values, vk_bytes, and plonk_vk to the input stream.
    let mut stdin = ZKMStdin::new();
    stdin.write_vec(proof);
    stdin.write_vec(public_values);
    stdin.write_vec(vk_bytes);
    stdin.write_vec(plonk_vk);

    // Create a `ProverClient`.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let start_time = Instant::now();
    let (_, report) = client.execute(PLONK_ELF, stdin).run().unwrap();
    let duration = start_time.elapsed();
    
    println!("执行时间: {:?}", duration);
    println!("executed plonk program with {} cycles", report.total_instruction_count());
    println!("{}", report);
}