
use clap::Parser;
use std::fs::File;
use std::io::Read;
use std::io::{Error, ErrorKind};
use rkyv::{Archive, Deserialize, Serialize};

use sp1_sdk::{ProverClient, include_elf, SP1Stdin};
use dotenv;
use sp1_sdk::HashableKey;
use coset_bls12_381::BlsScalar;
use plonk::prelude::{Verifier, Proof};
use coset_bytes::{Serializable, DeserializableSlice};
use common::constants::{VERIFIER_FILE, PLONK_PROOF_FILE, PLONK_PUBLICINPUTS_FILE};

// 定义使用rkyv序列化的数据结构，与3-Plonk保持一致
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct ZKProofData {
    data: Vec<u8>,
}

/// 用于Succinct RISC-V零知识虚拟机的ELF文件
pub const COSET_ELF: &[u8] = include_elf!("coset-program");

/// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool, // 执行模式标志
    #[arg(long)]
    prove: bool, // 证明模式标志
    #[arg(long, required = false, default_value = "merkle_data.json")]
    data_file: String, // 本地数据文件路径
    #[arg(long, required = false)]
    input: Option<String>, // 可选的输入十六进制字符串
}

/// 从文件读取数据
fn read_file(file_path: &str) -> Result<Vec<u8>, Error> {
    // 检查文件是否存在
    if !std::path::Path::new(file_path).exists() {
        return Err(Error::new(ErrorKind::NotFound, format!("文件不存在: {}", file_path)));
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
    
    // 反序列化Proof，与3-Plonk保持一致
    let proof = Proof::from_slice(&proof_data.data).map_err(|e| {
        Error::new(ErrorKind::Other, format!("反序列化证明失败: {:?}", e))
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
    
    // 解析公开输入，与3-Plonk保持一致
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
            return Err(Box::new(Error::new(ErrorKind::Other, "公开输入数据长度不正确")));
        }
        
        let scalar = match BlsScalar::from_bytes(&fixed_bytes).into_option() {
            Some(s) => s,
            None => return Err(Box::new(Error::new(ErrorKind::Other, "解析公开输入失败"))),
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
        .map_err(|e| Error::new(ErrorKind::Other, format!("反序列化验证者参数失败: {:?}", e)))?;
    
    println!("   ├── 验证者参数加载完成");
    println!("   ├── 验证者参数大小: {} 字节", verifier_bytes.len());
    
    Ok(verifier)
}

fn main() {
    // 设置日志记录器
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // 解析命令行参数
    let args = Args::parse();
    // 设置证明客户端
    let client = ProverClient::from_env();
    let mut stdin_instance = SP1Stdin::new(); 

    println!("使用的证明文件: {}", PLONK_PROOF_FILE);
    println!("使用的公共输入文件: {}", PLONK_PUBLICINPUTS_FILE);
    
    // 加载零知识证明数据
    let (public_inputs, proof_bytes, _coset_proof) = load_zk_proof_data(PLONK_PROOF_FILE, PLONK_PUBLICINPUTS_FILE).expect("加载零知识证明数据失败");
    
    // 传递公共输入（根哈希）
    if let Some(input) = public_inputs.first() {
        // BlsScalar是32字节的，所以N=32
        let input_bytes = <BlsScalar as Serializable<32>>::to_bytes(input);
        stdin_instance.write::<[u8; 32]>(&input_bytes);
        println!("已传递公共输入 0: {:?}", input);
    } else {
        // 如果没有公共输入，使用默认值
        let zero_scalar = BlsScalar::zero();
        let zero_bytes = <BlsScalar as Serializable<32>>::to_bytes(&zero_scalar);
        stdin_instance.write::<[u8; 32]>(&zero_bytes);
        println!("没有公共输入，使用默认值");
    }
    
    // 将proof_bytes写入（使用Vec<u8>）
    stdin_instance.write::<Vec<u8>>(&proof_bytes);
    println!("已传递proof数据，大小: {} 字节", proof_bytes.len());

    // 加载验证者参数
    let verifier = load_verifier_params(VERIFIER_FILE).expect("加载验证者参数失败");
    
    // 将验证者参数转换为字节数组并写入
    let verifier_bytes = verifier.to_bytes();
    stdin_instance.write::<Vec<u8>>(&verifier_bytes);
    println!("已传递验证者参数，大小: {} 字节", verifier_bytes.len());
    // 根据命令行参数决定执行模式
    if args.execute {
       
        // 设置程序用于证明
        let (_output, _report) = client.execute(COSET_ELF, &stdin_instance).run().unwrap();
        // 打印公共值
        // println!("公共值: {:?}", output);
    // 完成第一类证明（coset-merkle）,完成三类compress 证明 ，最终生成聚合证明，合约校验/在外部使用Rust校验
    } else {
        // 证明模式：生成SP1的Groth16证明，关联proof1的验证结果
        println!("===== 生成SP1证明 =====");

        // 设置程序用于证明
        let (pk, vk) = client.setup(COSET_ELF);
        
        // 生成零知识证明 - 使用Groth16
        println!("生成Groth16证明...");
        let proof = client
            .prove(&pk, &stdin_instance)
            .compressed()
            // .groth16()
            .run()
            .expect("生成证明失败");
        
        println!("成功生成Groth16证明!");
        
        // 验证零知识证明，数据购买方要调用这个算法校验zk
        client.verify(&proof, &vk).expect("验证证明失败");
        println!("成功验证Groth16证明!");
        
        // 打印验证密钥和公共值
        println!("验证密钥哈希: 0x{}", vk.bytes32().to_string());
        println!("公共值哈希: 0x{}", hex::encode(proof.public_values.as_slice()));
    }
}