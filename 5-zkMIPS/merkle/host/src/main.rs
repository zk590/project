use alloy_sol_types::SolType;
use clap::Parser;
use merkle_lib::PublicValuesStruct;
use zkm_sdk::{ProverClient, ZKMStdin, include_elf};
use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write, Error as IoError, ErrorKind};
use std::path::Path;
use std::time::Instant;


/// The ELF (executable and linkable format) file for the zkMIPS zkVM.
pub const MERKLE_ELF: &[u8] = include_elf!("merkle");

// 定义单个叶子节点信息的数据结构
#[derive(Archive, Serialize, Deserialize, Debug, Clone)]
#[archive(check_bytes)]
struct LeafInfo {
    position: u64,
    leaf_hash: [u8; 32],
    proof_bytes: Vec<u8>, // 节点路径
}

// 定义包含多个叶子节点信息的数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct MultipleLeavesData {
    root_hash: [u8; 32],
    leaves_info: Vec<LeafInfo>,
}

// 定义用于序列化证明和公共值的数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct ProofData {
    proof: Vec<u8>,
    public_values: Vec<u8>,
    vk_bytes: String,
}

/// 使用rkyv从文件中加载Merkle树的证明数据（支持多个叶子节点）
fn load_multiple_proof_data(file_path: &str) -> Result<MultipleLeavesData, IoError> {
    if !Path::new(file_path).exists() {
        return Err(IoError::new(ErrorKind::NotFound, "文件不存在"));
    }

    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    // 使用rkyv反序列化
    let data = unsafe { rkyv::archived_root::<MultipleLeavesData>(&bytes) };

    println!("使用rkyv成功加载Merkle证明数据");
    println!(" ├── 总共有 {} 个叶子节点证明", data.leaves_info.len());
    println!(" ├── 序列化数据大小: {} 字节", bytes.len());

    // 转换为非归档类型
    let result = MultipleLeavesData {
        root_hash: data.root_hash,
        leaves_info: data
            .leaves_info
            .iter()
            .map(|leaf| LeafInfo {
                position: leaf.position,
                leaf_hash: leaf.leaf_hash,
                proof_bytes: leaf.proof_bytes.to_vec(),
            })
            .collect(),
    };

    Ok(result)
}

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
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
    
    /// 输入文件路径
    #[clap(short, long)]
    input: Option<String>,
    
    /// 输出证明文件路径
    #[clap(short, long, default_value = "proof.bin")]
    output: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    // Setup the prover client.
    let client = ProverClient::new();

    // 从文件中加载证明数据
    let input_path = args
        .input
        .as_deref()
        .unwrap_or("/opt/project/1-Sender/merkle/merkle_some_data.bin");
    let data = load_multiple_proof_data(input_path).expect("无法加载证明数据");

    println!("1. 成功加载证明数据");
    println!("├── 根节点哈希: {:?}", data.root_hash);
    println!("└── 总共有 {} 个叶子节点证明", data.leaves_info.len());

    // 准备传递给program的输入
    let mut stdin = ZKMStdin::new();

    // 写入叶子节点数量
    let num_leaves = data.leaves_info.len() as u64;
    stdin.write(&num_leaves);

    // 写入根节点哈希
    stdin.write(&data.root_hash);

    // 为每个叶子节点写入数据
    for (i, leaf_info) in data.leaves_info.iter().enumerate() {
        println!("\n处理叶子节点 {}:", i + 1);
        println!("├── 位置: {}", leaf_info.position);
        println!("└── 哈希: {:?}", leaf_info.leaf_hash);

        // 写入叶子节点位置
        stdin.write(&leaf_info.position);

        // 写入叶子节点哈希
        stdin.write(&leaf_info.leaf_hash);

        // 写入证明数据长度
        let proof_len = leaf_info.proof_bytes.len() as u32;
        stdin.write(&proof_len);

        // 写入证明数据
        for byte in &leaf_info.proof_bytes {
            stdin.write(byte);
        }
    }

    // Setup the program for proving.
    let (pk, vk) = client.setup(MERKLE_ELF);

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
    let proof = if args.execute {
        // 仅执行程序，不生成证明
        let start = Instant::now();
        let (output, report) = client.execute(MERKLE_ELF, stdin).run()?;
        let duration = start.elapsed();
        println!("程序执行成功。执行周期数: {}", report.total_instruction_count());
        println!("程序执行耗时: {:?}", duration);
         // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        let PublicValuesStruct { all_valid } = decoded;
        println!("All tests passed: {}", all_valid);
        return Ok(());
    } else if args.core {
        // 生成core proof
        let start = Instant::now();
        let proof = client.prove(&pk, stdin).core().run()?;
        let duration = start.elapsed();
        println!("证明生成完成，耗时: {:?}", duration);
        proof
    } else if args.compressed {
        // 生成compressed proof
        let start = Instant::now();
        let proof = client.prove(&pk, stdin).compressed().run()?;
        let duration = start.elapsed();
        println!("证明生成完成，耗时: {:?}", duration);
        proof
    } else if let Some(system) = &args.system {
        // 根据指定的证明系统生成证明
        let start = Instant::now();
        let proof = match system.as_str() {
            "plonk" => {
                client.prove(&pk, stdin).plonk().run()?
            },
            _ => {
                eprintln!("Error: Unsupported proof system: {}", system);
                std::process::exit(1);
            }
        };
        let duration = start.elapsed();
        println!("{}证明生成完成，耗时: {:?}", system, duration);
        proof
    } else {
        // 默认生成core proof
        let start = Instant::now();
        let proof = client.prove(&pk, stdin).core().run()?;
        let duration = start.elapsed();
        println!("证明生成完成，耗时: {:?}", duration);
        proof
    };

    // 验证证明
    println!("验证证明...");
    let start = Instant::now();
    client.verify(&proof, &vk)?;
    let duration = start.elapsed();
    println!("证明验证通过，耗时: {:?}", duration);
    
    // 解析并显示公共值
    let public_values: PublicValuesStruct = PublicValuesStruct::abi_decode(proof.public_values.as_slice())?;
    println!("验证结果: 所有叶子节点验证有效 = {}", public_values.all_valid);
    
    // 保存证明到文件
    println!("保存证明到文件: {}", args.output);
    let mut file = File::create(&args.output)?;
    file.write_all(&proof.bytes())?;
    println!("证明文件保存成功");
    
    Ok(())
}