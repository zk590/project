use clap::Parser;
use dotenv::dotenv;
use std::fs::File;
use std::io::Write;
use zkm_sdk::{include_elf, ProverClient};

/// 验证密钥生成工具的命令行参数
#[derive(Parser)]
#[command(version, about = "验证密钥生成工具")]
struct Args {
    #[arg(long, default_value = "vkey.json", help = "指定验证密钥输出文件")]
    vkey: String,
}

fn main() {
    dotenv().ok();
    let args = Args::parse();

    // 初始化证明客户端
    let client = ProverClient::from_env();

    // 包含编译好的ELF文件
    let elf = include_elf!("fibonacci-mul");

    // 获取验证密钥
    let vkey = client.get_vkey(elf).unwrap();

    // 保存验证密钥到JSON文件
    let vkey_json = serde_json::to_string_pretty(&vkey).expect("序列化验证密钥失败");
    let mut file = File::create(&args.vkey).expect("创建验证密钥文件失败");
    file.write_all(vkey_json.as_bytes()).expect("写入验证密钥文件失败");

    println!("验证密钥已保存到文件: {}", args.vkey);
}