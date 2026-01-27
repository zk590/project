use rkyv::{Archive, Deserialize, Serialize};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::fs::File;
use std::io::{Read, Error as IoError, ErrorKind};
use std::path::Path;
use std::time::Instant;
use hex;

use common::constants::SCHNORR_DATA_FILE;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("schnorr-program");

// 定义Schnorr签名结果数据结构，与application/schnorr/src/main.rs中的SchnorrResult保持一致
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct SchnorrResult {
    message: String,
    signature_hex: String,
    public_key_hex: String,
    is_valid: bool,
}

// 定义多个Schnorr签名结果的集合数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct SchnorrResults {
    results: Vec<SchnorrResult>,
}

// 从文件读取并使用rkyv反序列化
fn read_and_deserialize(file_path: &str) -> Result<SchnorrResults, IoError> {
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

    // 从文件中反序列化批量Schnorr签名结果数据
    let schnorr_results = read_and_deserialize(SCHNORR_DATA_FILE).expect("无法从文件中反序列化数据");
    
    println!("从文件中加载的数据:");
    println!("- 总共有 {} 条记录", schnorr_results.results.len());
    
    // 打印前3条记录作为示例
    let display_count = schnorr_results.results.len().min(3);
    for (index, result) in schnorr_results.results.iter().take(display_count).enumerate() {
        println!("示例记录 #{}:", index + 1);
        println!("  消息: {}", result.message);
        println!("  签名: {}", result.signature_hex);
        println!("  公钥: {}", result.public_key_hex);
        println!("  预期验证结果: {}", result.is_valid);
    }

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();
    
    // 先写入结果列表的长度
    stdin.write(&(schnorr_results.results.len() as u32));
    
    // 然后逐个写入每个Schnorr签名结果
    for result in &schnorr_results.results {
        let message = result.message.as_bytes();
        let signature_bytes = hex::decode(&result.signature_hex).expect("无效的hex签名数据");
        let public_key_bytes = hex::decode(&result.public_key_hex).expect("无效的hex公钥数据");
        
        // 先写入消息长度和内容
        stdin.write(&(message.len() as u32));
        for byte in message {
            stdin.write(&byte);
        }
        
        // 写入签名长度和内容
        stdin.write(&(signature_bytes.len() as u32));
        for byte in signature_bytes {
            stdin.write(&byte);
        }
        
        // 写入公钥长度和内容
        stdin.write(&(public_key_bytes.len() as u32));
        for byte in public_key_bytes {
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

    // // Test a round trip of proof serialization and deserialization.
    // proof.save("proof-with-pis.bin").expect("saving proof failed");
    // let deserialized_proof =
    //     SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // // Verify the deserialized proof.
    // client.verify(&deserialized_proof, &vk).expect("verification failed");

    // println!("successfully generated and verified proof for the program!")
}