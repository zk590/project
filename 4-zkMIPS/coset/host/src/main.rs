use clap::Parser;
use std::fs::File;
use std::io::Write;
use std::time::Instant;
use common::constants::{PLONK_PROOF_FILE, PLONK_PUBLICINPUTS_FILE, VERIFIER_FILE};
use zkm_sdk::{ProverClient, ZKMStdin, include_elf};
use coset_bytes::Serializable;

// 引入coset-lib库
use coset_lib::{load_zk_proof_data, load_verifier_params};

// 直接导入需要的类型
use coset_bls12_381::BlsScalar;

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("coset");



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



fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 设置日志记录器
    dotenv::dotenv().ok();

    // 解析命令行参数
    let args = Args::parse();
    
    // 初始化证明客户端
    let client = ProverClient::new();
    let mut stdin_instance = ZKMStdin::new(); 

    // 使用constants.rs中定义的常量
    let proof_file = PLONK_PROOF_FILE;
    let public_inputs_file = PLONK_PUBLICINPUTS_FILE;
    let verifier_file = VERIFIER_FILE;
    
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

    if args.execute {
        // Execute the program
        let start_time = Instant::now();
        let (_output, report) = client.execute(ELF, stdin_instance).run()?;
        let elapsed = start_time.elapsed();
        println!("Program executed successfully. Execution time: {:?}", elapsed);
        println!("Number of cycles: {}", report.total_instruction_count());
        return Ok(());
    } else {
        // Generate the proof
        let proof = if args.core || args.compressed {
            // 生成compressed proof
            let start_time = Instant::now();
            let proof = client.prove(&pk, stdin_instance).compressed().run()?;
            let duration = start_time.elapsed();
            println!("generated compressed proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
            proof
        } else if let Some(system) = &args.system {
            // 根据指定的系统类型生成proof
            let start_time = Instant::now();
            let proof = match system.as_str() {
                "plonk" => {
                    client.prove(&pk, stdin_instance).plonk().run()?
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
            let proof = client.prove(&pk, stdin_instance).compressed().run()?;
            let duration = start_time.elapsed();
            println!("generated compressed proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
            proof
        };
        println!("Successfully generated proof!");

        // Verify the proof.
        let start_time = Instant::now();
        client.verify(&proof, &vk)?;
        let duration = start_time.elapsed();
        println!("verified proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
        println!("Successfully verified proof!");

        // 保存证明到文件
        println!("保存证明到文件: {}", args.output);
        let mut file = File::create(&args.output)?;
        file.write_all(&proof.bytes())?;
        println!("证明文件保存成功");
    }
    
    Ok(())
}