use clap::Parser;
use std::fs::File;
use std::io::{Write, Read};
use std::io::{Error, ErrorKind};
use std::path::Path;
use std::time::Instant;
use rkyv::{Archive, Deserialize, Serialize};

use coset_bls12_381::BlsScalar;
use plonk::prelude::{Verifier, Proof};
use coset_bytes::{Serializable, DeserializableSlice};
use zkm_sdk::{ProverClient, ZKMStdin, include_elf};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("coset");

// 定义使用rkyv序列化的数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct ZKProofData {
    data: Vec<u8>,
}

// 定义命令行参数结构
#[derive(Parser, Debug)]
#[command(author, version, about = "coset证明生成工具", long_about = None)]
struct Args {
    /// 仅执行程序，不生成证明
    #[clap(long)]
    execute: bool,
    
    /// 生成core proof
    #[clap(long)]
    core: bool,
    
    /// 生成compressed proof
    #[clap(long)]
    compressed: bool,
    
    /// 证明系统类型，如plonk
    #[arg(long)]
    system: Option<String>,
    
    /// plonk证明文件路径
    #[arg(long, default_value = "plonk_proof.bin", help = "plonk证明文件路径")]
    proof_file: String,
    
    /// plonk公共输入文件路径
    #[arg(long, default_value = "plonk_publicinputs.bin", help = "plonk公共输入文件路径")]
    public_inputs_file: String,
    
    /// 验证者参数文件路径
    #[arg(long, default_value = "verifier.bin", help = "验证者参数文件路径")]
    verifier_file: String,
    
    /// 输出证明文件路径
    #[clap(short, long, default_value = "proof.bin")]
    output: String,
}

// 从文件读取数据
fn read_file(file_path: &str) -> Result<Vec<u8>, Error> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(Error::new(ErrorKind::NotFound, format!("文件不存在: {}", file_path)));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    Ok(bytes)
}

// 从文件中加载零知识证明数据
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

// 从文件中加载验证者参数
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 设置日志记录器
    dotenv::dotenv().ok();

    // 解析命令行参数
    let args = Args::parse();
    
    // 初始化证明客户端
    let client = ProverClient::new();
    let mut stdin_instance = ZKMStdin::new(); 

    // 使用命令行参数或默认值
    let proof_file = args.proof_file;
    let public_inputs_file = args.public_inputs_file;
    let verifier_file = args.verifier_file;
    
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
    
    // Setup the program for proving.
    let (pk, vk) = client.setup(ELF);

    // 检查参数是否合法
    let mut specified_count = 0;
    if args.execute { specified_count += 1; }
    if args.core { specified_count += 1; }
    if args.compressed { specified_count += 1; }
    if args.system.is_some() { specified_count += 1; }
    
    if specified_count != 1 {
        eprintln!("Error: You must specify exactly one of --execute, --core, --compressed, or --system");
        std::process::exit(1);
    }

    // 确定执行模式
    match args.execute {
        true => {
            // 仅执行程序，不生成证明
            let start = Instant::now();
            let (_output, report) = client.execute(ELF, stdin_instance).run()?;
            let duration = start.elapsed();
            println!("程序执行成功。执行周期数: {}", report.total_instruction_count());
            println!("程序执行耗时: {:?}", duration);
            return Ok(());
        },
        false if args.core => {
            // 生成core proof
            let start = Instant::now();
            let proof = client.prove(&pk, stdin_instance).core().run()?;
            let duration = start.elapsed();
            println!("Core证明生成完成，耗时: {:?}", duration);
            
            // 验证证明
            println!("验证证明...");
            let start_verify = Instant::now();
            client.verify(&proof, &vk)?;
            let duration_verify = start_verify.elapsed();
            println!("证明验证通过，耗时: {:?}", duration_verify);
            
            // 保存证明到文件
            println!("保存证明到文件: {}", args.output);
            let mut file = File::create(&args.output)?;
            file.write_all(&proof.bytes())?;
            println!("证明文件保存成功");
        },
        false if args.compressed => {
            // 生成compressed proof
            let start = Instant::now();
            let proof = client.prove(&pk, stdin_instance).compressed().run()?;
            let duration = start.elapsed();
            println!("Compressed证明生成完成，耗时: {:?}", duration);
            
            // 验证证明
            println!("验证证明...");
            let start_verify = Instant::now();
            client.verify(&proof, &vk)?;
            let duration_verify = start_verify.elapsed();
            println!("证明验证通过，耗时: {:?}", duration_verify);
            
            // 保存证明到文件
            println!("保存证明到文件: {}", args.output);
            let mut file = File::create(&args.output)?;
            file.write_all(&proof.bytes())?;
            println!("证明文件保存成功");
        },
        false if args.system.is_some() => {
            // 根据指定的证明系统生成证明
            let system = args.system.unwrap();
            let start = Instant::now();
            let proof = match system.as_str() {
                "plonk" => {
                    client.prove(&pk, stdin_instance).plonk().run()?
                },
                _ => {
                    eprintln!("Error: Unsupported proof system: {}", system);
                    std::process::exit(1);
                }
            };
            let duration = start.elapsed();
            println!("{}证明生成完成，耗时: {:?}", system, duration);
            
            // 验证证明
            println!("验证证明...");
            let start_verify = Instant::now();
            client.verify(&proof, &vk)?;
            let duration_verify = start_verify.elapsed();
            println!("证明验证通过，耗时: {:?}", duration_verify);
            
            // 保存证明到文件
            println!("保存证明到文件: {}", args.output);
            let mut file = File::create(&args.output)?;
            file.write_all(&proof.bytes())?;
            println!("证明文件保存成功");
        },
        _ => {
            // 默认生成core proof
            let start = Instant::now();
            let proof = client.prove(&pk, stdin_instance).core().run()?;
            let duration = start.elapsed();
            println!("Core证明生成完成，耗时: {:?}", duration);
            
            // 验证证明
            println!("验证证明...");
            let start_verify = Instant::now();
            client.verify(&proof, &vk)?;
            let duration_verify = start_verify.elapsed();
            println!("证明验证通过，耗时: {:?}", duration_verify);
            
            // 保存证明到文件
            println!("保存证明到文件: {}", args.output);
            let mut file = File::create(&args.output)?;
            file.write_all(&proof.bytes())?;
            println!("证明文件保存成功");
        }
    }
    
    Ok(())
}