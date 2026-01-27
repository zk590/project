use dusk_bls12_381::BlsScalar;
use dusk_plonk::prelude::*;
use dusk_bytes::Serializable;
use rkyv::{Archive, Deserialize};
use hex;
use std::fs::File;
use std::io::{Read, Write, Error as IoError, ErrorKind};
use std::path::Path;
use std::result::Result;

// 定义零知识证明数据结构（与main.rs中的定义保持一致）
#[derive(Archive, Deserialize, rkyv::Serialize, Debug)]
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
    
    // 由于ArchivedVec没有clone方法，我们手动创建一个新的Vec
    Ok(proof_data.data.iter().copied().collect())
}

/// 验证Merkle证明
fn verify_merkle_proof(
    verifier_file_path: &str,
    proof_file_path: &str,
    public_inputs_file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 加载验证器
    let verifier_bytes = read_file(verifier_file_path)?;
    let verifier = Verifier::try_from_bytes(&verifier_bytes)?;
    
    // 加载证明数据
    let proof_bytes = load_proof_data(proof_file_path)?;
    
    // 检查证明数据是否为空或长度不足
    if proof_bytes.is_empty() {
        return Err(Box::new(IoError::new(ErrorKind::InvalidData, "证明数据为空")));
    }
    
    if proof_bytes.len() < 1008 {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            format!("证明数据长度不足: {}字节，需要1008字节", proof_bytes.len()),
        )));
    }
    
    // 反序列化Proof
    let mut proof_array = [0u8; 1008];
    proof_array.copy_from_slice(&proof_bytes[..]);
    let proof = match Proof::from_bytes(&proof_array) {
        Ok(p) => p,
        Err(e) => {
            return Err(Box::new(IoError::new(
                ErrorKind::InvalidData,
                format!("{:?}", e),
            )));
        },
    };
    println!("the proof is {}",hex::encode(proof.to_bytes()));
    // 加载并解析公开输入
    let public_inputs_bytes = load_proof_data(public_inputs_file_path)?;
    let mut public_inputs = Vec::new();
    
    for j in (0..public_inputs_bytes.len()).step_by(32) {
        if j + 32 <= public_inputs_bytes.len() {
            if let Ok(array_32) = public_inputs_bytes[j..j+32].try_into() {
                if let Some(scalar) = BlsScalar::from_bytes(array_32).into_option() {
                    public_inputs.push(scalar);
                }
            }
        }
    }
    
    // 验证证明
    verifier.verify(&proof, &public_inputs[..])?;
    
    Ok(())
}

/// 测试1: 输入错误的证明文件路径，返回错误
/// 该测试验证当尝试读取不存在的文件时，系统能够正确地返回文件不存在的错误
#[test]
fn test_invalid_proof_file_path() {
    // 测试不存在的文件路径
    let invalid_file_path = "non_existent_proof_file.bin";
    
    // 打印输入的错误路径，用于调试和日志记录
    println!("尝试访问不存在的文件路径: {}", invalid_file_path);
    
    // 调用read_file函数，应该返回文件不存在的错误
    let result = read_file(invalid_file_path);
    
    // 断言结果是错误，并且是文件不存在的错误
    assert!(result.is_err());
    if let Err(e) = result {
        // 输出返回的错误信息
        println!("read_file返回的错误: {:?}", e);
        assert_eq!(e.kind(), ErrorKind::NotFound);
        assert!(e.to_string().contains("文件不存在"));
    }
    
    // 测试load_proof_data函数，也应该返回错误
    let result = load_proof_data(invalid_file_path);
    // 输出load_proof_data返回的错误信息
    if let Err(e) = &result {
        println!("load_proof_data返回的错误: {:?}", e);
    }
    assert!(result.is_err());
}

/// 测试2: 验证损坏的证明文件（直接使用plonk_proof_error.bin和public_values.bin）
#[test]
fn test_corrupted_proof_file() {
    // 定义要使用的文件路径
    let corrupted_proof_path = "plonk_proof_error.bin";
    let verifier_path = "verifier.bin";
    let public_values_path = "plonk_publicinputs.bin";
    
    println!("开始测试损坏的证明文件验证...");
    println!("使用损坏的证明文件路径: {}", corrupted_proof_path);
    println!("使用正确的验证器文件路径: {}", verifier_path);
    println!("使用正确的公开值文件路径: {}", public_values_path);
    
    // // 反序列化损坏的证明文件
    match load_proof_data(corrupted_proof_path) {
        Ok(corrupted_proof_bytes) => {
            println!("损坏的Plonk证明数据 = {}", hex::encode(corrupted_proof_bytes));
        },
        Err(e) => {
            println!("警告: 反序列化损坏的证明文件时出错: {}", e);
        }
    }
    
    // 反序列化公开值文件
    match load_proof_data(public_values_path) {
        Ok(public_values_bytes) => {
            println!("正确的public_inputs数据 = {}", hex::encode(public_values_bytes));
        },
        Err(e) => {
            println!("警告: 反序列化公开值文件时出错: {}", e);
        }
    }
    
    // 反序列化验证器文件
    println!("尝试反序列化验证器文件...");
    match read_file(verifier_path) {
        Ok(verifier_bytes) => {
            println!("正确的verifier数据 = {}", hex::encode(verifier_bytes));
            // // 尝试解析验证器
            // match Verifier::try_from_bytes(&verifier_bytes) {
            //     Ok(_) => println!("成功反序列化验证器"),
            //     Err(e) => println!("警告: 反序列化验证器时出错: {}", e)
            // }
        },
        Err(e) => {
            println!("警告: 读取验证器文件时出错: {}", e);
        }
    }
    
    // 使用验证器验证损坏的证明文件和公开值
    println!("使用验证器验证损坏的证明文件和公开值...");
    let result = verify_merkle_proof(verifier_path, corrupted_proof_path, public_values_path);
    
    // 直接展示result内容
    println!("验证结果: {:?}", result);
    

}