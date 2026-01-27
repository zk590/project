use clap::Parser;
use dotenv::dotenv;
use ecdsa_lib::{PublicValuesStruct, DEFAULT_MESSAGE, DEFAULT_PUBLIC_KEY, DEFAULT_SIGNATURE};
use hex;
use std::fs::File;
use std::io::{Read, Write};
use zkm_sdk::{ZKMStdin, ProverClient};

#[derive(Parser)]
struct Args {
    /// 输入文件路径
    #[clap(short, long)]
    input: Option<String>,
    
    /// 输出证明文件路径
    #[clap(short, long, default_value = "proof.bin")]
    output: String,
    
    /// 输出公共值文件路径
    #[clap(short, long, default_value = "public_values.bin")]
    public_values: String,
    
    /// 输出证明数据文件路径
    #[clap(short, long, default_value = "proof_data.bin")]
    proof_data: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let args = Args::parse();
    
    // 初始化证明器客户端
    let client = ProverClient::new();
    
    // 创建输入流
    let mut stdin = ZKMStdin::new();
    
    // 处理输入数据
    if let Some(input_path) = args.input {
        // 从文件读取输入数据
        let mut file = File::open(input_path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        
        // 解析输入内容（假设是JSON格式）
        // 这里简化处理，实际应该解析JSON
        println!("从文件读取输入数据: {}", content);
        
        // TODO: 根据输入内容构建stdin
        // 这部分需要根据实际的输入格式进行调整
    } else {
        // 使用默认测试数据
        println!("使用默认测试数据");
        println!("- 消息: {}", String::from_utf8_lossy(DEFAULT_MESSAGE));
        println!("- 公钥: {}", DEFAULT_PUBLIC_KEY);
        println!("- 签名: {}", DEFAULT_SIGNATURE);
        
        // 写入结果列表的长度（1条）
        stdin.write(&1u32);
        
        // 写入消息
        let message = DEFAULT_MESSAGE;
        stdin.write(&(message.len() as u32));
        for byte in message {
            stdin.write(&byte);
        }
        
        // 写入签名
        let signature_bytes = hex::decode(DEFAULT_SIGNATURE).expect("无效的hex签名数据");
        stdin.write(&(signature_bytes.len() as u32));
        for byte in signature_bytes {
            stdin.write(&byte);
        }
        
        // 写入公钥
        let public_key_bytes = hex::decode(DEFAULT_PUBLIC_KEY).expect("无效的hex公钥数据");
        stdin.write(&(public_key_bytes.len() as u32));
        for byte in public_key_bytes {
            stdin.write(&byte);
        }
    }
    
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
    let public_values: PublicValuesStruct = proof.public_values()?;
    println!("验证结果: 所有签名有效 = {}", public_values.allValid);
    
    Ok(())
}