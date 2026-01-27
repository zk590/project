//! 使用SP1 SDK生成可在EVM兼容链上验证的零知识证明的端到端示例

use clap::{Parser, ValueEnum};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, ProverClient, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey, HashableKey};
use std::path::PathBuf;

/// 用于Succinct RISC-V零知识虚拟机的ELF文件
pub const POSEIDON_MERKLE_ELF: &[u8] = include_elf!("coset-program");

/// EVM命令的参数结构体
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct EVMArgs {
    #[arg(long, required = false)]
    input: Option<String>, // 可选的输入值，十六进制格式
    #[arg(long, value_enum, default_value = "groth16")]
    system: ProofSystem, // 证明系统类型
}

/// 表示可用的证明系统的枚举
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Plonk, // Plonk证明系统
    Groth16, // Groth16证明系统
}

/// 可用于在Solidity中测试SP1 zkVM证明验证的测试装置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SP1Sha256ProofFixture {
    input: String, // 输入的十六进制字符串表示
    output: String, // 输出的十六进制字符串表示
    vkey: String, // 验证密钥的字符串表示
    public_values: String, // 公共值的十六进制字符串表示
    proof: String, // 证明的十六进制字符串表示
}

fn main() {
    // 设置日志记录器
    sp1_sdk::utils::setup_logger();

    // 解析命令行参数
    let args = EVMArgs::parse();

    // 设置证明客户端
    let client = ProverClient::from_env();

    // 设置程序
    let (pk, vk) = client.setup(POSEIDON_MERKLE_ELF);

    // 解析输入或生成随机输入
    let input = match args.input {
        Some(hex_str) => hex::decode(&hex_str).expect("无效的十六进制字符串"),
        None => {
            let mut rng = rand::thread_rng();
            let mut random_bytes = vec![0u8; 32];
            rng.fill(&mut random_bytes[..]);
            random_bytes
        },
    };

    // 确保输入长度为32字节，这与program/main.rs中的处理保持一致
    let mut input_32 = [0u8; 32];
    input_32.copy_from_slice(&input[..32]);

    // 设置标准输入
    let mut stdin = SP1Stdin::new();
    stdin.write(&input_32);

    // 打印当前使用的输入值和证明系统
    println!("输入: 0x{}", hex::encode(&input_32));
    println!("证明系统: {:?}", args.system);

    // 根据选择的证明系统生成零知识证明
    let proof = match args.system {
        ProofSystem::Plonk => client.prove(&pk, &stdin).plonk().run(),
        ProofSystem::Groth16 => client.prove(&pk, &stdin).groth16().run(),
    }
    .expect("生成证明失败");

    // 创建并保存证明测试装置
    create_proof_fixture(&proof, &vk, args.system, &input_32);
}

/// 为给定的证明创建测试装置
fn create_proof_fixture(
    proof: &SP1ProofWithPublicValues, // 包含公共值的证明
    vk: &SP1VerifyingKey, // 验证密钥
    system: ProofSystem, // 证明系统类型
    input_32: &[u8; 32], // 输入数据
) {
    // 公共值已经是我们需要的格式，直接使用
    let bytes = proof.public_values.as_slice();

    // 我们不需要反序列化公共值，因为program/main.rs中已经直接返回了结果
    // 创建测试装置
    let fixture = SP1Sha256ProofFixture {
        input: format!("0x{}", hex::encode(&input_32)), // 输入的十六进制字符串
        output: "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(), // 输出占位符
        vkey: vk.bytes32().to_string(), // 验证密钥的字符串表示
        public_values: format!("0x{}", hex::encode(bytes)), // 公共值的十六进制字符串
        proof: format!("0x{}", hex::encode(proof.bytes())), // 证明的十六进制字符串
    };

    // 打印验证密钥
    println!("验证密钥: {}", fixture.vkey);

    // 打印公共值
    println!("公共值: {}", fixture.public_values);

    // 打印证明
    println!("证明字节: {}", fixture.proof);

    // 保存测试装置到文件
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../contracts/src/fixtures");
    std::fs::create_dir_all(&fixture_path).expect("创建测试装置路径失败");
    std::fs::write(
        fixture_path.join(format!("{:?}-fixture.json", system).to_lowercase()),
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .expect("写入测试装置失败");
}