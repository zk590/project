use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use hex;

use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Error as IoError, ErrorKind};
use std::path::Path;
use std::time::Instant;

use common::constants::KECCAK_HASH_FILE;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("keccak-program");

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
fn read_and_deserialize(file_path: &str) -> Result<HashResults, IoError> {
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

fn main() {
    // 从文件中反序列化批量哈希结果数据
    let hash_results = read_and_deserialize(KECCAK_HASH_FILE).expect("无法从文件中反序列化数据");
    
    println!("从文件中加载的数据:");
    println!("- 总共有 {} 条记录", hash_results.results.len());
    
    // 打印前3条记录作为示例
    let display_count = hash_results.results.len().min(3);
    for (index, result) in hash_results.results.iter().take(display_count).enumerate() {
        println!("示例记录 #{}:", index + 1);
        println!("  消息: {}", result.message);
        println!("  哈希值: {}", result.hash);
    }

    // The input stream that the program will read from using `sp1_zkvm::io::read`.
    // Note that the types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();
    
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

    // Create a `ProverClient` method.
    let client = ProverClient::from_env();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());


    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let start_time = Instant::now();
    let proof = client.prove(&pk, &stdin).compressed().run().unwrap();
    let duration = start_time.elapsed();
    // Stark Compressed proof time = 718.929 seconds
    println!("Stark Compressed proof time = {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
    // println!("Compressed proof = {}",hex::encode(proof.bytes()));

    let start_time = Instant::now();
    let plonk_proof = client.prove(&pk, &stdin).compressed().plonk().run().unwrap();
    let duration = start_time.elapsed();
    println!("Plonk proof time = {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
    println!("Plonk proof = {}",hex::encode(plonk_proof.bytes()));

    // Verify proof and public values
    let start_time = Instant::now();
    client.verify(&plonk_proof, &vk).expect("verification failed");
    let duration = start_time.elapsed();
    println!("Plonk verified time = {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
}