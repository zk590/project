use hex;

use rkyv::{Archive, Deserialize, Serialize};
use sp1_sdk::{include_elf, SP1ProofWithPublicValues, ProverClient, SP1Stdin};
use std::fs::File;
use std::io::{Read, Error as IoError, ErrorKind};
use std::path::Path;
use std::time::Instant;

use common::constants::SHA3_HASH_FILE;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("sha3-program");

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
    // 移除了utils::setup_logger()调用，因为utils模块已从导入中移除

    // 从文件中反序列化哈希结果数据
    let hash_results = read_and_deserialize(SHA3_HASH_FILE).expect("无法从文件中反序列化数据");
    
    println!("从文件中加载的数据:");
    println!("- 总共 {} 条哈希结果", hash_results.results.len());
    
    // 提取第一条结果用于演示
    let hash_result = &hash_results.results[0];
    let message = hash_result.message.as_bytes(); // 转换为&[u8]类型
    let hash_value = hex::decode(&hash_result.hash).expect("无效的hex哈希值"); // Vec<u8>类型
    
    println!("- 第一条消息: {}", hash_result.message);
    println!("- 第一条哈希值: {}", hash_result.hash);

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();
    
    // 先写入哈希结果列表的长度
    stdin.write(&(hash_results.results.len() as u32));
    
    // 循环写入所有哈希结果的数据
    for result in &hash_results.results {
        let message = result.message.as_bytes();
        let hash_value = hex::decode(&result.hash).expect("无效的hex哈希值");
        
        // 先写入消息长度
        stdin.write(&(message.len() as u32));
        // 然后逐个写入消息字节
        for byte in message {
            stdin.write(&byte);
        }
        // 先写入哈希值长度
        stdin.write(&(hash_value.len() as u32));
        // 然后逐个写入哈希值字节
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
    println!("generated proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());

    // Read and verify the output.
    //

    // Verify proof and public values
    let start_time = Instant::now();
    client.verify(&proof, &vk).expect("verification failed");
    let duration = start_time.elapsed();
    println!("verified proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
}