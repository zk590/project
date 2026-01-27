use sp1_sdk::{ProverClient, SP1Stdin, include_elf};
use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Error as IoError, ErrorKind};
use std::path::Path;
use std::time::Instant;
use rsa::{pkcs8::DecodePublicKey, RsaPublicKey};
use common::constants::RSA_HASH_FILE;
use hex;



/// 要在zkVM内部执行的ELF二进制文件
const RSA_ELF: &[u8] = include_elf!("rsa-program"); // 包含编译好的RSA验证程序


// 包含2048位RSA密钥的DER格式数据
const RSA_2048_PUB_DER: &[u8] = include_bytes!("../rsa2048-pub.der"); // 包含公钥

// 定义单个签名结果数据结构，与application/rsa/src/main.rs中的SignatureResult保持一致
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

fn main() {
    // 从DER格式解析RSA公钥（目前未使用解析后的密钥，但保持代码结构）
    let _public_key = RsaPublicKey::from_public_key_der(RSA_2048_PUB_DER).unwrap();
    
    // 从文件中反序列化批量签名结果数据
    let signature_results = read_and_deserialize(RSA_HASH_FILE).expect("无法从文件中反序列化数据");
    
    println!("从文件中加载的数据:");
    println!("- 总共有 {} 条记录", signature_results.results.len());
    
    // 打印前3条记录作为示例
    let display_count = signature_results.results.len().min(3);
    for (index, result) in signature_results.results.iter().take(display_count).enumerate() {
        println!("示例记录 #{}:", index + 1);
        println!("  消息: {}", result.message);
        println!("  签名: {}", result.signature_hex);
    }

    // The input stream that the program will read from using `sp1_zkvm::io::read`.
    let mut stdin = SP1Stdin::new();
    
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

    // Create a `ProverClient` method.
    let client = ProverClient::from_env();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(RSA_ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());

    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(RSA_ELF);
    let start_time = Instant::now();
    let proof = client.prove(&pk, &stdin).compressed().run().unwrap();
    let duration = start_time.elapsed();
    println!("generated proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());

    // Verify proof and public values
    let start_time = Instant::now();
    client.verify(&proof, &vk).expect("verification failed");
    let duration = start_time.elapsed();
    println!("verified proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
}