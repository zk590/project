//! 一个简单的示例，展示如何使用zkm-sdk聚合多个程序的证明。

// 添加时间记录相关导入
use std::time::Instant;

use aggregation_lib::{PublicValuesStruct, DEFAULT_VKEY, DEFAULT_PUBLIC_VALUE};
use clap::Parser;
use dotenv;
use hex;
use zkm_sdk::{ProverClient, ZKMStdin};

/// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 要聚合的证明数量
    #[arg(short, long, default_value_t = 2)]
    count: u32,
    
    /// 证明模式，可选值: execute, core, compressed
    #[arg(short, long, default_value = "execute")]
    mode: String,
    
    /// 输出证明文件路径
    #[arg(short, long, default_value = "proof.bin")]
    output: String,
    
    /// 输出公共值文件路径
    #[arg(short, long, default_value = "public_values.bin")]
    public_values: String,
    
    /// 输出验证密钥文件路径
    #[arg(short, long, default_value = "vk.bin")]
    vk: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();
    
    // 解析命令行参数
    let args = Args::parse();
    println!("要聚合的证明数量: {}", args.count);
    println!("证明模式: {}", args.mode);
    
    // 初始化证明客户端
    let client = ProverClient::new();
    
    // 创建输入流
    let mut stdin = ZKMStdin::new();
    
    // 准备验证密钥和公共值
    let vkeys = vec![DEFAULT_VKEY; args.count as usize];
    let public_values = vec![DEFAULT_PUBLIC_VALUE.to_vec(); args.count as usize];
    
    // 写入验证密钥和公共值
    println!("准备输入数据...");
    stdin.write(&vkeys);
    stdin.write(&public_values);
    
    // 记录证明生成开始时间
    let start_time = Instant::now();
    
    // 根据不同模式生成证明
    let proof = match args.mode.as_str() {
        "execute" => {
            println!("执行模式 - 生成证明...");
            client.execute_with_stdin(stdin)?
        },
        "core" => {
            println!("核心模式 - 生成证明...");
            client.core_prove_with_stdin(stdin)?
        },
        "compressed" => {
            println!("压缩模式 - 生成证明...");
            client.compressed_prove_with_stdin(stdin)?
        },
        _ => {
            panic!("不支持的证明模式: {}", args.mode);
        },
    };
    
    // 记录证明生成结束时间
    let end_time = Instant::now();
    println!("证明生成耗时: {:?}", end_time.duration_since(start_time));
    
    // 验证证明
    println!("验证证明...");
    let verify_start_time = Instant::now();
    proof.verify()?;
    let verify_end_time = Instant::now();
    println!("证明验证耗时: {:?}", verify_end_time.duration_since(verify_start_time));
    
    // 解析公共值
    let public_values = proof.public_values::<PublicValuesStruct>()?;
    println!("聚合证明的默克尔根: 0x{}", hex::encode(public_values.merkleRoot.0));
    
    // 保存证明
    println!("保存证明到文件: {}", args.output);
    std::fs::write(&args.output, &proof.proof)?;
    
    // 保存公共值
    println!("保存公共值到文件: {}", args.public_values);
    std::fs::write(&args.public_values, &proof.public_values)?;
    
    // 保存验证密钥
    println!("保存验证密钥到文件: {}", args.vk);
    let vkey = client.get_vkey()?;
    std::fs::write(&args.vk, &vkey)?;
    
    println!("聚合证明生成和验证完成!");
    Ok(())
}