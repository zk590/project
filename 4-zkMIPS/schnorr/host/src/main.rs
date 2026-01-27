use alloy_sol_types::SolType;
use clap::Parser;
use schnorr_lib::PublicValuesStruct;
use zkm_sdk::{ProverClient, ZKMStdin, include_elf, HashableKey};
use hex;
use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Error as IoError, ErrorKind};
use std::path::Path;
use std::time::Instant;

// 定义单个Schnorr签名结果数据结构
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

// 定义用于序列化证明和公共值的数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct ProofData {
    proof: Vec<u8>,
    public_values: Vec<u8>,
    vk_bytes: String,
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

/// The ELF (executable and linkable format) file for the zkMIPS zkVM.
pub const SCHNORR_ELF: &[u8] = include_elf!("schnorr");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    core: bool,

    #[arg(long)]
    compressed: bool,

    #[arg(long)]
    system: Option<String>, // 证明系统类型，如plonk

    #[arg(long)]
    file_path: Option<String>, // 批量签名结果文件路径
}

fn main() {
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    // 检查参数是否合法
    let mut specified_count = 0;
    if args.execute { specified_count += 1; }
    if args.core { specified_count += 1; }
    if args.compressed { specified_count += 1; }
    if args.system.is_some() { specified_count += 1; }
    
    if specified_count != 1 {
        eprintln!("Error: You must specify exactly one of --execute, --core, --compress, or --system");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    // 从文件中反序列化批量Schnorr签名结果数据
    let file_path = args.file_path.as_deref().unwrap_or("/opt/project/1-Sender/schnorr/schnorr_data.bin");
    let schnorr_results = read_and_deserialize(file_path).expect("无法从文件中反序列化数据");
    
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

    // The input stream that the program will read from using `zkm_zkvm::io::read`.
    // Note that the types of the elements in the input stream must match the types being read in the program.
    let mut stdin = ZKMStdin::new();
    
    // 先写入结果列表的长度
    stdin.write(&(schnorr_results.results.len() as u32));
    
    // 然后逐个写入每个签名结果
    for result in &schnorr_results.results {
        let message = result.message.as_bytes();
        let signature_bytes = hex::decode(&result.signature_hex).expect("无效的hex签名数据");
        let public_key_bytes = hex::decode(&result.public_key_hex).expect("无效的hex公钥数据");
        
        // 写入消息长度和消息内容
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

    if args.execute {
        // Execute the program
        let start_time = Instant::now();
        let (output, report) = client.execute(SCHNORR_ELF, stdin).run().unwrap();
        let elapsed = start_time.elapsed();
        println!("Program executed successfully. Execution time: {:?}", elapsed);

        // Read the output.
        let decoded = PublicValuesStruct::abi_decode(output.as_slice()).unwrap();
        let PublicValuesStruct { all_valid } = decoded;
        println!("All tests passed: {}", all_valid);

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else {
        // Setup the program for proving.
        let (pk, vk) = client.setup(SCHNORR_ELF);

        // Generate the proof
        let proof: zkm_sdk::ZKMProofWithPublicValues = if args.core || args.compressed {
            // 生成compressed proof
            let start_time = Instant::now();
            let proof = client.prove(&pk, stdin).compressed().run().expect("failed to generate Compressed proof");
            let duration = start_time.elapsed();
            println!("generated compressed proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
            proof
        } else if let Some(system) = &args.system {
            // 根据指定的系统类型生成proof
            let start_time = Instant::now();
            let proof = match system.as_str() {
                "plonk" => {
                    client.prove(&pk, stdin).plonk().run().expect("failed to generate Plonk proof")
                },
                _ => {
                    eprintln!("Error: Unsupported proof system: {}", system);
                    std::process::exit(1);
                }
            };
            let duration = start_time.elapsed();
            println!("generated {} proof in {}.{:03} seconds", system, duration.as_secs(), duration.subsec_millis());
            proof
        } else {
            // 默认生成compressed proof
            let start_time = Instant::now();
            let proof = client.prove(&pk, stdin).compressed().run().expect("failed to generate default proof");
            let duration = start_time.elapsed();
            println!("generated compressed proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
            proof
        };
        println!("Successfully generated proof!");

        // Verify the proof.
        let start_time = Instant::now();
        client.verify(&proof, &vk).expect("failed to verify proof");
        let duration = start_time.elapsed();
        println!("verified proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
        println!("Successfully verified proof!");
        
        // 将证明、公共值和验证密钥序列化为文件
        let proof_data = ProofData {
            proof: proof.bytes().to_vec(),
            public_values: proof.public_values.to_vec(),
            vk_bytes: vk.bytes32(),
        };
        
        // 使用rkyv序列化
        let bytes = rkyv::to_bytes::<_, 256>(&proof_data).expect("序列化失败");
        
        // 写入文件
        let output_file = "schnorr_proof_data.bin";
        std::fs::write(output_file, bytes).expect("写入文件失败");
        println!("证明数据已成功序列化到文件: {}", output_file);
    }
}
