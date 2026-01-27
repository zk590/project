use dusk_plonk::prelude::*;
use dusk_bytes::Serializable;
use rkyv::{Archive, Deserialize};
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

/// 读取plonk_proof.bin，修改内容中一个字符，写入到plonk_proof_error.bin
fn modify_proof_file(input_path: &str, output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 打印操作信息
    println!("开始修改证明文件...");
    println!("输入文件路径: {}", input_path);
    println!("输出文件路径: {}", output_path);
    
    // 确保输入文件存在
    if !Path::new(input_path).exists() {
        return Err(Box::new(IoError::new(
            ErrorKind::NotFound,
            format!("输入文件不存在: {}", input_path)
        )));
    }
    
    // 读取原始证明文件
    let original_proof_bytes = load_proof_data(input_path)?;
    println!("成功加载原始证明文件，数据长度: {}字节", original_proof_bytes.len());
    
    // 检查数据是否为空
    if original_proof_bytes.is_empty() {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            "证明数据为空"
        )));
    }
    
    // 修改证明文件中的一个字符
    let mut modified_proof_bytes = original_proof_bytes.clone();
    
    // 选择修改位置
    let modify_position = if modified_proof_bytes.len() > 10 {
        50 // 当数据足够长时，修改第50个字节
    } else {
        0 // 当数据较短时，修改第一个字节
    };
    
    // 确保修改位置在有效范围内
    if modify_position < modified_proof_bytes.len() {
        let original_byte = modified_proof_bytes[modify_position];
        
        // 修改字节值（如果是0则改为1，否则改为0）
        modified_proof_bytes[modify_position] = if original_byte == 0 {
            1
        } else {
            0
        };
        
        println!("已修改证明文件的第{}个字节: 原始值={}, 新值={}", 
                 modify_position, original_byte, modified_proof_bytes[modify_position]);
    } else {
        return Err(Box::new(IoError::new(
            ErrorKind::InvalidData,
            format!("修改位置超出数据范围: {}, 数据长度: {}", 
                   modify_position, modified_proof_bytes.len())
        )));
    }
    // 创建ZKProofData结构体并序列化
    let proof_data = ZKProofData { data: modified_proof_bytes };
    
    let mut error_file = File::create(&output_path)?;
    // 使用rkyv序列化
    let serialized_data = rkyv::to_bytes::<_, 1024>(&proof_data)?;
    println!("成功序列化修改后的证明数据");
    error_file.write_all(&serialized_data)?;
    // 写入输出文件
    // write_file(output_path, &serialized_data)?;
    println!("成功写入修改后的证明数据到输出文件");
    
    Ok(())
}

/// 测试函数：读取plonk_proof_1.bin，修改内容中一个字符，写入到plonk_proof_error.bin
#[test]
fn test_modify_proof_file() {
    // 定义文件路径
    let input_path = "plonk_proof_1.bin";
    let output_path = "plonk_proof_error.bin";
    
    // 执行修改操作
    let result = modify_proof_file(input_path, output_path);
    
    // 检查结果
    match result {
        Ok(_) => {
            println!("测试成功: 证明文件修改并写入完成");
            // 验证输出文件是否存在
            assert!(Path::new(output_path).exists(), "输出文件不存在");
        },
        Err(e) => {
            println!("测试失败: {}", e);
            panic!("测试失败: {}", e);
        }
    }
}

// 主函数，便于直接运行该文件进行测试
fn main() {
    let input_path = "plonk_proof_1.bin";
    let output_path = "plonk_proof_error.bin";
    
    if let Err(e) = modify_proof_file(input_path, output_path) {
        eprintln!("错误: {}", e);
        std::process::exit(1);
    }
}