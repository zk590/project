//! A script that verifies a Stark proof in ZKM.

use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::time::Instant;
use zkm_sdk::{include_elf, utils, ProverClient, ZKMStdin};

/// The ELF for the Stark verifier program.
const STARK_ELF: &[u8] = include_elf!("plonk-verifier");

/// The ProofData structure that matches the serialized data in sha3_proof_data.bin
#[derive(Archive, Deserialize, Serialize, Debug)]
pub struct ProofData {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
    pub vk_bytes: Vec<u8>,
}

fn load_proof_data() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // 1. 反序列化 sha3_proof_data.bin 文件
    let proof_data_path = "/opt/project/5-zkMIPS/sha3/host/sha3_proof_data.bin";
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
    println!("Verification key bytes: {}", proof_data.vk_bytes.len());
    
    // 返回反序列化的proof、public_values和vk_bytes
    (proof_data.proof, proof_data.public_values, proof_data.vk_bytes)
}

fn main() {
    // Setup logging.
    utils::setup_logger();

    // Load the proof data.
    let (proof, public_values, vk_bytes) = load_proof_data();
    println!("Using vk_bytes for verification with length: {}", vk_bytes.len());

    // Write the proof, public values, and vk_bytes to the input stream.
    let mut stdin = ZKMStdin::new();
    stdin.write_vec(proof);
    stdin.write_vec(public_values);
    stdin.write_vec(vk_bytes);

    // Create a `ProverClient`.
    let client = ProverClient::new();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let start_time = Instant::now();
    let (_, report) = client.execute(STARK_ELF, stdin).run().unwrap();
    let duration = start_time.elapsed();
    
    println!("执行时间: {:?}", duration);
    println!("executed stark program with {} cycles", report.total_instruction_count());
    println!("{}", report);
}
