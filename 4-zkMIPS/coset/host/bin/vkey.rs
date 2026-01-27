use clap::Parser;
use dotenv::dotenv;
use std::fs::File;
use std::io::Write;
use zkm_sdk::ProverClient;

#[derive(Parser)]
struct Args {
    /// 输出验证密钥文件路径
    #[clap(short, long, default_value = "vkey.json")]
    output: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let args = Args::parse();
    
    // 初始化证明器客户端
    let client = ProverClient::new();
    
    // 获取验证密钥
    let vkey = client.get_vkey_json()?;
    
    // 保存验证密钥到文件
    println!("保存验证密钥到文件: {}", args.output);
    let mut file = File::create(&args.output)?;
    file.write_all(vkey.as_bytes())?;
    
    println!("验证密钥生成完成");
    Ok(())
}