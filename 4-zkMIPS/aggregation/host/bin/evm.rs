use clap::Parser;
use dotenv::dotenv;
use aggregation_lib::{PublicValuesStruct, DEFAULT_VKEY, DEFAULT_PUBLIC_VALUE};
use hex;
use std::fs::File;
use std::io::{Read, Write};
use zkm_sdk::{ZKMStdin, ProverClient};

#[derive(Parser)]
struct Args {
    /// 要聚合的证明数量
    #[arg(short, long, default_value_t = 2)]
    count: u32,
    
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let args = Args::parse();
    
    // 初始化证明器客户端
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
    
    // 生成EVM证明
    println!("生成EVM证明...");
    let proof = client.evm_prove_with_stdin(stdin)?;
    
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
    
    // 解析并显示公共值
    let public_values = proof.public_values()?;
    let public_values: PublicValuesStruct = public_values;
    println!("聚合证明的默克尔根: 0x{}", hex::encode(public_values.merkleRoot.0));
    
    Ok(())
}