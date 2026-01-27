use rkyv::{Archive, Deserialize, Serialize};
use sp1_sdk::{include_elf, SP1ProofWithPublicValues, ProverClient, SP1Stdin};
use std::fs::File;
use std::io::{Read, Error as IoError, ErrorKind};
use std::path::Path;
use std::time::Instant;

use common::constants::FIBONACCI_MUL_DATA_FILE;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci-mul-program");

// 定义斐波那契结果数据结构，与application/fibonacci_mul/src/main.rs中的FibonacciResult保持一致
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct FibonacciResult {
    n: u64,
    a: u64,
    b: u64,
}

// 从文件读取并使用rkyv反序列化
fn read_and_deserialize(file_path: &str) -> Result<FibonacciResult, IoError> {
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

    // 从文件中反序列化斐波那契结果数据
    let fibonacci_result = read_and_deserialize(FIBONACCI_MUL_DATA_FILE).expect("无法从文件中反序列化数据");
    
    // 提取项数n
    let n = fibonacci_result.n;
    
    println!("从文件中加载的数据:");
    println!("- 项数n: {}", n);
    println!("- 预期结果a: {}", fibonacci_result.a);
    println!("- 预期结果b: {}", fibonacci_result.b);

    // The input stream that the program will read from using `sp1_zkvm::io::read`. Note that the
    // types of the elements in the input stream must match the types being read in the program.
    let mut stdin = SP1Stdin::new();
    // 写入项数n
    stdin.write(&n);
    
    // Create a `ProverClient` method.
    let client = ProverClient::from_env();

    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());


    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let start_time = Instant::now();
    let mut proof = client.prove(&pk, &stdin).run().unwrap();
    let duration = start_time.elapsed();
    println!("generated proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // // Test a round trip of proof serialization and deserialization.
    // proof.save("proof-with-pis.bin").expect("saving proof failed");
    // let deserialized_proof =
    //     SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // // Verify the deserialized proof.
    // client.verify(&deserialized_proof, &vk).expect("verification failed");

    println!("successfully generated and verified proof for the fibonacci multiplication program!")
}