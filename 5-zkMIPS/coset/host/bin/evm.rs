use clap::Parser;
use dotenv::dotenv;
use std::fs::File;
use std::io::{Read, Write};
use coset_bls12_381::BlsScalar;
use plonk::prelude::{Verifier, Proof};
use coset_bytes::{Serializable, DeserializableSlice};
use zkm_sdk::{ProverClient, ZKMStdin};

// 定义使用rkyv序列化的数据结构
use rkyv::{Archive, Serialize, Deserialize};

#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct ZKProofData {
    data: Vec<u8>,
}

/// 命令行参数结构体
#[derive(Parser, Debug)]
struct Args {
    /// 输出证明文件路径
    #[arg(short, long, default_value = "proof.bin")]
    output: String,
    
    /// 输出公共值文件路径
    #[arg(short, long, default_value = "public_values.bin")]
    public_values: String,
    
    /// 输出证明数据文件路径
    #[arg(short, long, default_value = "proof_data.bin")]
    proof_data: String,
}

/// 从文件读取数据
fn read_file(file_path: &str) -> Result<Vec<u8>, std::io::Error> {
    // 检查文件是否存在
    if !std::path::Path::new(file_path).exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("文件不存在: {}", file_path)));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    Ok(bytes)
}

/// 从文件中加载零知识证明数据
fn load_zk_proof_data(proof_path: &str, public_inputs_path: &str) -> Result<(Vec<BlsScalar>, Vec<u8>, Proof), Box<dyn std::error::Error>> {
    // 从文件读取序列化的证明数据
    let proof_file_bytes = read_file(proof_path)?;
    println!("证明文件总大小: {} 字节", proof_file_bytes.len());
    
    // 使用与3-Plonk相同的反序列化方法
    let proof_data = unsafe {
        rkyv::archived_root::<ZKProofData>(&proof_file_bytes)
    };
    
    let proof_bytes: Vec<u8> = proof_data.data.iter().copied().collect();
    println!("Proof数据大小: {} 字节", proof_bytes.len());
    
    // 反序列化Proof
    let proof = Proof::from_slice(&proof_data.data).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("反序列化证明失败: {:?}", e))
    })?;
    
    // 从文件读取序列化的公开输入数据
    let public_inputs_file_bytes = read_file(public_inputs_path)?;
    println!("公共输入文件总大小: {} 字节", public_inputs_file_bytes.len());
    
    // 使用与3-Plonk相同的反序列化方法
    let public_inputs_data = unsafe {
        rkyv::archived_root::<ZKProofData>(&public_inputs_file_bytes)
    };
    
    let public_inputs_bytes: Vec<u8> = public_inputs_data.data.iter().copied().collect();
    println!("公共输入数据大小: {} 字节", public_inputs_bytes.len());
    
    // 解析公开输入
    let mut public_inputs = Vec::new();
    let scalar_size = 32; // BlsScalar的大小
    let num_scalars = public_inputs_data.data.len() / scalar_size;
    
    for i in 0..num_scalars {
        let start = i * scalar_size;
        let end = start + scalar_size;
        let scalar_bytes = &public_inputs_data.data[start..end];
        
        // 转换为[u8; 32]类型
        let mut fixed_bytes = [0u8; 32];
        if scalar_bytes.len() == 32 {
            fixed_bytes.copy_from_slice(scalar_bytes);
        } else {
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "公开输入数据长度不正确")));
        }
        
        let scalar = match BlsScalar::from_bytes(&fixed_bytes).into_option() {
            Some(s) => s,
            None => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "解析公开输入失败"))),
        };
        
        public_inputs.push(scalar);
        println!("成功解析公共输入 {}: {:?}", i, scalar);
    }
    println!("最终公共输入数量: {}", public_inputs.len());
    
    println!("   ├── plonk证明数据加载完成");
    
    // 返回公共输入、proof_bytes（用于传递给program）和proof（用于本地验证）
    Ok((public_inputs, proof_bytes, proof))
}

/// 从文件中加载验证者参数
fn load_verifier_params(path: &str) -> Result<Verifier, std::io::Error> {
    
    // 从文件读取验证器数据
    let verifier_bytes = read_file(path)?;
    
    // 反序列化验证器
    let verifier = Verifier::try_from_bytes(&verifier_bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("反序列化验证者参数失败: {:?}", e)))?;
    
    println!("   ├── 验证者参数加载完成");
    println!("   ├── 验证者参数大小: {} 字节", verifier_bytes.len());
    
    Ok(verifier)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let args = Args::parse();
    
    // 初始化证明客户端
    let client = ProverClient::new();
    let mut stdin_instance = ZKMStdin::new(); 

    // 从环境变量获取文件路径
    let proof_file = std::env::var("PLONK_PROOF_FILE").unwrap_or("plonk_proof.bin".to_string());
    let public_inputs_file = std::env::var("PLONK_PUBLICINPUTS_FILE").unwrap_or("plonk_publicinputs.bin".to_string());
    let verifier_file = std::env::var("VERIFIER_FILE").unwrap_or("verifier.bin".to_string());
    
    println!("使用的证明文件: {}", proof_file);
    println!("使用的公共输入文件: {}", public_inputs_file);
    
    // 加载零知识证明数据
    let (public_inputs, proof_bytes, _coset_proof) = load_zk_proof_data(&proof_file, &public_inputs_file)?;
    
    // 传递公共输入（根哈希）
    if let Some(input) = public_inputs.first() {
        // BlsScalar是32字节的
        let input_bytes = <BlsScalar as Serializable<32>>::to_bytes(input);
        stdin_instance.write(&input_bytes);
        println!("已传递公共输入 0: {:?}", input);
    } else {
        // 如果没有公共输入，使用默认值
        let zero_scalar = BlsScalar::zero();
        let zero_bytes = <BlsScalar as Serializable<32>>::to_bytes(&zero_scalar);
        stdin_instance.write(&zero_bytes);
        println!("没有公共输入，使用默认值");
    }
    
    // 将proof_bytes写入（使用Vec<u8>）
    stdin_instance.write(&proof_bytes);
    println!("已传递proof数据，大小: {} 字节", proof_bytes.len());

    // 加载验证者参数
    let verifier = load_verifier_params(&verifier_file)?;
    
    // 将验证者参数转换为字节数组并写入
    let verifier_bytes = verifier.to_bytes();
    stdin_instance.write(&verifier_bytes);
    println!("已传递验证者参数，大小: {} 字节", verifier_bytes.len());
    
    // 生成EVM证明
    println!("生成EVM证明...");
    let proof = client.evm_prove_with_stdin(stdin_instance)?;
    
    // 保存证明
    println!("保存证明到文件: {}", args.output);
    let mut file = File::create(&args.output)?;
    file.write_all(&proof.proof)?;
    
    // 保存公共值
    println!("保存公共值到文件: {}", args.public_values);
    let mut file = File::create(&args.public_values)?;
    file.write_all(&proof.public_values)?;
    
    // 保存证明数据
    println!("保存证明数据到文件: {}", args.proof_data);
    let mut file = File::create(&args.proof_data)?;
    file.write_all(&proof.proof_data)?;
    
    println!("EVM证明生成完成");
    Ok(())
}