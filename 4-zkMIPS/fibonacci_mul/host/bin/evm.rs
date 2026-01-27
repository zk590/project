use clap::Parser;
use dotenv::dotenv;
use std::time::Instant;
use zkm_sdk::{include_elf, ProverClient, ZkmProofWithPublicValues, ZkmStdin};
use fibonacci_mul_lib::{PublicValuesStruct, DEFAULT_N};

/// EVM证明生成工具的命令行参数
#[derive(Parser)]
#[command(version, about = "EVM证明生成工具")]
struct Args {
    #[arg(long, help = "指定n值")]
    n: Option<u64>,
    #[arg(long, default_value = "evm-proof.bin", help = "指定EVM证明输出文件")]
    evm_proof: String,
    #[arg(long, default_value = "public-values.bin", help = "指定公共值输出文件")]
    public_values: String,
    #[arg(long, default_value = "proof-data.bin", help = "指定证明数据输出文件")]
    proof_data: String,
}

fn main() {
    dotenv().ok();
    let args = Args::parse();

    // 获取n值，默认使用DEFAULT_N
    let n = args.n.unwrap_or(DEFAULT_N);
    println!("使用n值: {}", n);

    // 初始化证明客户端
    let client = ProverClient::from_env();

    // 包含编译好的ELF文件
    let elf = include_elf!("fibonacci-mul");

    // 创建输入流
    let mut stdin = ZkmStdin::new();
    stdin.write(n);

    // 生成EVM证明
    let start_time = Instant::now();
    let proof = client.prove_evm(elf, &stdin).run().unwrap();
    let duration = start_time.elapsed();
    println!("生成EVM证明耗时: {}.{:03} 秒", duration.as_secs(), duration.subsec_millis());

    // 保存证明、公共值和证明数据
    proof.save(&args.evm_proof).expect("保存EVM证明失败");
    std::fs::write(&args.public_values, &proof.public_values).expect("保存公共值失败");
    std::fs::write(&args.proof_data, &proof.proof_data).expect("保存证明数据失败");
    println!("EVM证明已保存到文件: {}", args.evm_proof);
    println!("公共值已保存到文件: {}", args.public_values);
    println!("证明数据已保存到文件: {}", args.proof_data);

    // 解析并显示公共值
    let public_values = PublicValuesStruct::abi_decode(&proof.public_values, true).unwrap();
    println!("公共值:");
    println!("  n: {}", public_values.n);
    println!("  a: {}", public_values.a);
    println!("  b: {}", public_values.b);

    println!("EVM证明生成完成!");
}