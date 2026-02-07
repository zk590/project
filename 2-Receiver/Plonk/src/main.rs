use coset_bls12_381::BlsScalar;
use plonk::prelude::*;
use coset_bytes::Serializable;
use rkyv::{Archive, Deserialize};
use std::env;
use std::fs::File;
use std::io::{Read, Write, Error as IoError};
use std::path::Path;
use hex;
use std::time::{Instant, Duration};
use common::constants::{VERIFIER_FILE, MERKLE_PROOF_FILE_PREFIX};

// 定义零知识证明数据结构
#[derive(Archive, Deserialize, Debug)]
#[archive(check_bytes)]
struct ZKProofData {
    data: Vec<u8>,
}

/// 从文件读取数据
fn read_file(file_path: &str) -> Result<Vec<u8>, IoError> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(IoError::new(std::io::ErrorKind::NotFound, format!("文件不存在: {}", file_path)));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    Ok(bytes)
}

/// 写入数据到文件
fn write_file(file_path: &str, data: &[u8]) -> Result<(), IoError> {
    let mut file = File::create(file_path)?;
    file.write_all(data)?;
    Ok(())
}

/// 使用rkyv从文件中加载证明数据
fn load_proof_data(file_path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 从文件读取序列化的证明数据
    let bytes = read_file(file_path)?;
    
    // 使用rkyv反序列化ZKProofData
    let proof_data = unsafe {
        rkyv::archived_root::<ZKProofData>(&bytes)
    };
    
    Ok(proof_data.data.iter().copied().collect())
}

/// 从verifier文件生成验证器并验证指定的证明文件
fn verify_merkle_proof(n: Option<usize>) -> Result<(), Box<dyn std::error::Error>> {
 
    // let start_time = Instant::now();
    // 从verifier文件读取验证器数据
    let verifier_data = read_file(VERIFIER_FILE)?;
    println!("Plonk Proof verifier = {}",hex::encode(&verifier_data));
    
    // 反序列化验证器
    let verifier = Verifier::try_from_bytes(&verifier_data)?;
    // let duration = start_time.elapsed();
    // println!("   验证器加载完成，耗时: {}.{:03} 秒", duration.as_secs(), duration.subsec_millis());
    
    // 确定要验证的证明文件数量
    let max_files_to_verify = match n {
        Some(count) => count,
        None => {
            // 默认验证所有可能存在的文件
            let mut count = 0;
            while Path::new(&format!("{}{}", MERKLE_PROOF_FILE_PREFIX, &format!("plonk_proof_{}.bin", count + 1))).exists() {
                count += 1;
            }
            count
        }
    };
    println!("共接收 {} 个Plonk证明", max_files_to_verify);
    
    let mut total_verification_time = Duration::new(0, 0);
    let mut success_count = 0;
    let mut failure_count = 0;
    
    // 循环验证每个证明文件
    for i in 0..max_files_to_verify {
        println!("\n验证第 {} 个证明文件:", i + 1);
        
        // 构建文件路径（与batch_main.rs保持一致，从1开始编号）
        let proof_file_name = MERKLE_PROOF_FILE_PREFIX.to_string() + &format!("plonk_proof_{}.bin", i + 1);
        let public_inputs_file_name = MERKLE_PROOF_FILE_PREFIX.to_string() + &format!("plonk_publicinputs_{}.bin", i + 1);
        
        
        // 检查文件是否存在
        if !Path::new(&proof_file_name).exists() || !Path::new(&public_inputs_file_name).exists() {
            println!("   文件不存在，跳过此验证");
            failure_count += 1;
            continue;
        }
        
        // 使用rkyv加载证明数据
        let proof_bytes = load_proof_data(&proof_file_name)?;
        if i==0{
            println!(" Receive Plonk Proof = {}", hex::encode(&proof_bytes));
        }
        
        // 使用rkyv加载公开输入数据
        let public_inputs_bytes = load_proof_data(&public_inputs_file_name)?;
         if i==0{
            println!(" Receive Plonk Public_inputs = {}", hex::encode(&public_inputs_bytes));
        }
        // println!("PublicInputs数据大小: {} 字节", public_inputs_bytes.len());
        
        // 反序列化Proof - 直接从zkproof.data中获取第一个值
        let proof = {
            let mut proof_array = [0u8; 1008];
            proof_array.copy_from_slice(&proof_bytes[..]);
            
            match Proof::from_bytes(&proof_array) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("   Proof反序列化错误: {:?}", e);
                    failure_count += 1;
                    continue;
                }
            }
        };
        
        // 从字节数组解析公开输入（每32字节一个BlsScalar）
        let mut public_inputs = Vec::new();
        for j in (0..public_inputs_bytes.len()).step_by(32) {
            if j + 32 <= public_inputs_bytes.len() {
                // 安全地将&[u8]转换为&[u8; 32]
                if let Ok(array_32) = public_inputs_bytes[j..j+32].try_into() {
                    if let Some(scalar) = BlsScalar::from_bytes(array_32).into_option() {
                        public_inputs.push(scalar);
                    }
                }
            }
        }   
        
        // 获取叶子节点验证结果（从第一个公开输入推断）
        let is_valid_proof = !public_inputs.is_empty() && public_inputs[0] != BlsScalar::zero();
        
        let verify_start_time = Instant::now();
        
        // 验证证明
        let verification_result = verifier.verify(&proof, &public_inputs);
        let verify_duration = verify_start_time.elapsed();
        total_verification_time += verify_duration;
        
        match verification_result {
            Ok(_) => {
                println!("   PLonk 证明验证成功！耗时: {}.{:03} 秒", 
                         verify_duration.as_secs(), verify_duration.subsec_millis());
                
                // // 输出验证结果详细信息
                // println!("   验证结果详情:");
                // println!("   ├── 叶子节点验证结果: {}", is_valid_proof);
                // println!("   ├── 证明验证状态: 成功");
                // println!("   └── 验证器来源: {}", VERIFIER_FILE);
                
                success_count += 1;
            },
            Err(e) => {
                println!("   证明验证失败: {:?}", e);
                failure_count += 1;
            }
        }
    }
    
    // 输出总体验证结果
    println!("\n===== 验证总结 =====");
    println!("总验证文件数: {}", max_files_to_verify);
    println!("成功验证数: {}", success_count);
    println!("失败验证数: {}", failure_count);
    println!("总验证时间: {}.{:03} 秒", 
             total_verification_time.as_secs(), total_verification_time.subsec_millis());
    
    // 将总体验证结果保存到文件
    let overall_result = if failure_count == 0 && success_count > 0 { 1 } else { 0 };
    let result_data = [overall_result];
    write_file("verification_result.bin", &result_data)?;
    println!("总体验证结果已保存到 verification_result.bin");
    
    Ok(())
}

fn main() {
    println!("=== 执行 Plonk证明 程序 ===");
    println!("-----------------------------");
    
    // 获取命令行参数
    let args: Vec<String> = env::args().collect();
    
    if args.len() > 1 {
        // 如果提供了参数n，则验证指定的n个证明文件
        if let Ok(n) = args[1].parse::<usize>() {
            match verify_merkle_proof(Some(n)) {
                Ok(_) => println!("\n验证程序执行成功!"),
                Err(e) => {
                    println!("\n验证程序执行失败: {:?}", e);
                    std::process::exit(1);
                }
            }
        } else {
            println!("错误：参数必须是有效的数字");
            println!("用法：cargo run -- [n]");
            println!("  其中n是要验证的叶子节点数量（可选）");
            std::process::exit(1);
        }
    } else {
        // 如果没有提供参数，默认验证所有证明文件
        match verify_merkle_proof(None) {
            Ok(_) => println!("\n验证程序执行成功!"),
            Err(e) => {
                println!("\n验证程序执行失败: {:?}", e);
                std::process::exit(1);
            }
        }
    }
}