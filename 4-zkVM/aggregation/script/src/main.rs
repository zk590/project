//! 一个简单的示例，展示如何使用SP1聚合多个程序的证明。

// 添加时间记录相关导入
use std::time::Instant;

use clap::Parser; 
use hex; 
use sp1_sdk::{include_elf, HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin, SP1VerifyingKey}; 
use aggregation_script::AggregationError;

// 导入算法处理器
mod algorithms;
use algorithms::algorithm_trait::AlgorithmHandler;
use algorithms::fibonacci::{FibonacciHandler, FibonacciResult};
use algorithms::fibonacci_mul::{FibonacciMulHandler, FibonacciMulResult};
use algorithms::sha2::{SHA2Handler, HashResult as SHA2HashResult, HashResults};
use algorithms::signature::{RSAHandler, ECDSAHandler, SchnorrHandler, SignatureResult, EcdsaResult, SchnorrResult};
use algorithms::coset::ZKProofData;
use algorithms::coset::CosetHandler;
use algorithms::utils::read_and_deserialize;
// use dusk_plonk::prelude::{BlsScalar, Proof, Verifier};
use coset_bytes::Serializable;
// use std::fs::File;

/// 聚合输入结构体，用于封装证明和验证密钥
pub struct AggregationInput {
    pub proof: SP1ProofWithPublicValues, // 带有公共值的SP1证明
    pub vk: SP1VerifyingKey,             // SP1验证密钥
}

impl AggregationInput {
    /// 创建新的聚合输入
    pub fn new(proof: SP1ProofWithPublicValues, vk: SP1VerifyingKey) -> Self {
        Self {
            proof,
            vk,
        }
    }
}

// 导入数据文件路径常量
use common::constants::{FIBONACCI_DATA_FILE, FIBONACCI_MUL_DATA_FILE, SHA2_HASH_FILE, KECCAK_HASH_FILE, SHA3_HASH_FILE, RSA_HASH_FILE, ECDSA_DATA_FILE, SCHNORR_DATA_FILE, VERIFIER_FILE, PLONK_PROOF_FILE, PLONK_PUBLICINPUTS_FILE/*, HASH_FILE*/};

/// 命令行参数结构体
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 要聚合的算法列表，可选值: fibonacci, fibonacci_mul
    #[arg(short, long, use_value_delimiter = true, num_args = 1.., default_values = ["fibonacci"])]
    algorithms: Vec<String>,
}

// 定义各个算法的ELF常量
//const HASH_ELF: &[u8] = include_elf!("hash-program");
const RSA_ELF: &[u8] = include_elf!("rsa-program");
const ECDSA_ELF: &[u8] = include_elf!("ecdsa-program");
const SCHNORR_ELF: &[u8] = include_elf!("schnorr-program");
const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-add-program");
const FIBONACCI_MUL_ELF: &[u8] = include_elf!("fibonacci-mul-program");
const SHA2_ELF: &[u8] = include_elf!("sha2-program");
const KECCAK_ELF: &[u8] = include_elf!("keccak-program");
const SHA3_ELF: &[u8] = include_elf!("sha3-program");
const COSET_ELF: &[u8] = include_elf!("coset-program");
const AGGREGATION_ELF: &[u8] = include_elf!("aggregation-program");

fn main() -> Result<(), AggregationError> {
    // 设置日志系统
    sp1_sdk::utils::setup_logger();

    // 解析命令行参数
    let args = Args::parse();
    println!("要聚合的算法: {:?}", args.algorithms);

    // 初始化证明客户端
    let client = ProverClient::from_env();
        
    // 收集所有要聚合的输入
    let mut inputs: Vec<AggregationInput> = Vec::new();

    // 根据命令行参数动态生成相应算法的证明
    for algorithm in &args.algorithms {
        match algorithm.as_str() {
            "fibonacci" => {
                // 直接从文件中读取数据并反序列成FibonacciResult
                match read_and_deserialize::<FibonacciResult>(FIBONACCI_DATA_FILE) {
                    Ok(fibonacci_result) => {
                        // 打印FibonacciResult内容
                        println!("fibonacci_result: {{ n: {}, a: {}, b: {} }}", 
                                fibonacci_result.n, fibonacci_result.a, fibonacci_result.b);
                        
                        // client.setup返回直接是元组，不是Result
                        let (pk, vk) = client.setup(FIBONACCI_ELF);
                        
                        // 准备SP1Stdin，只写入n值
                        let mut stdin = SP1Stdin::new();
                        stdin.write(&fibonacci_result.n);
                          
                        // 记录证明生成开始时间
                        let start_time = Instant::now();
                          
                        // 生成默认格式的证明
                        match client.prove(&pk, &stdin).compressed().run() {
                            Ok(proof) => {
                                let input = AggregationInput::new(proof, vk);
                                inputs.push(input);
                            },
                            Err(err) => {
                                println!("生成斐波那契证明失败: {}", err);
                            }
                        }
                        
                        // 计算并打印证明生成耗时
                        let elapsed = start_time.elapsed();
                        println!("斐波那契证明生成耗时: {:.2?}", elapsed);
                    },
                    Err(err) => {
                        println!("读取斐波那契数据失败: {}", err);
                    }
                }
            },
            "fibonacci_mul" => {
                // 直接从文件中读取数据并反序列成FibonacciMulResult
                match read_and_deserialize::<FibonacciMulResult>(FIBONACCI_MUL_DATA_FILE) {
                    Ok(fibonacci_mul_result) => {
                        // 打印FibonacciMulResult内容
                        println!("fibonacci_mul_result: {{ n: {}, a: {}, b: {} }}", 
                                fibonacci_mul_result.n, fibonacci_mul_result.a, fibonacci_mul_result.b);
                        
                        // client.setup返回直接是元组，不是Result
                        let (pk, vk) = client.setup(FIBONACCI_MUL_ELF);
                        
                        // 准备SP1Stdin，只写入n值
                        let mut stdin = SP1Stdin::new();
                        stdin.write(&fibonacci_mul_result.n);
                          
                        // 记录证明生成开始时间
                        let start_time = Instant::now();
                          
                        // 生成默认格式的证明
                        match client.prove(&pk, &stdin).compressed().run() {
                            Ok(proof) => {
                                let input = AggregationInput::new(proof, vk);
                                inputs.push(input);
                            },
                            Err(err) => {
                                println!("生成乘法斐波那契证明失败: {}", err);
                            }
                        }
                        
                        // 计算并打印证明生成耗时
                        let elapsed = start_time.elapsed();
                        println!("乘法斐波那契证明生成耗时: {:.2?}", elapsed);
                    },
                    Err(err) => {
                        println!("读取乘法斐波那契数据失败: {}", err);
                    }
                }
            },
            "sha2" => {
                // 直接从文件中读取数据并反序列成HashResults
                match read_and_deserialize::<HashResults>(SHA2_HASH_FILE) {
                    Ok(hash_results) => {
                        // 打印HashResults内容
                        println!("共读取到 {} 条SHA2哈希记录", hash_results.results.len());
                        for (i, result) in hash_results.results.iter().enumerate() {
                            println!("记录 {}: {{ message: '{}', hash: {} }}", 
                                    i + 1, result.message, result.hash);
                        }
                        
                        // client.setup返回直接是元组，不是Result
                        let (pk, vk) = client.setup(SHA2_ELF);
                        
                        // 准备SP1Stdin，按照sha2程序期望的格式写入多条数据
                        let mut stdin = SP1Stdin::new();
                        
                        // 1. 写入结果列表长度
                        stdin.write(&(hash_results.results.len() as u32));
                        
                        // 2. 循环写入每条记录
                        for result in &hash_results.results {
                            // 写入消息长度
                            let message_bytes = result.message.as_bytes();
                            stdin.write(&(message_bytes.len() as u32));
                            
                            // 写入消息内容
                            for byte in message_bytes {
                                stdin.write(&byte);
                            }
                            
                            // 写入哈希值长度（注意：result.hash是十六进制字符串，需要先解码）
                            let hash_bytes = match hex::decode(&result.hash) {
                                Ok(bytes) => bytes,
                                Err(err) => {
                                    println!("解码哈希值失败: {}，跳过该记录", err);
                                    continue;
                                }
                            };
                            stdin.write(&(hash_bytes.len() as u32));
                            
                            // 写入哈希值内容
                            for byte in hash_bytes {
                                stdin.write(&byte);
                            }
                        }
                            
                        // 记录证明生成开始时间
                        let start_time = Instant::now();
                        
                        // 生成默认格式的证明
                        match client.prove(&pk, &stdin).compressed().run() {
                            Ok(proof) => {
                                let input = AggregationInput::new(proof, vk);
                                inputs.push(input);
                            },
                            Err(err) => {
                                println!("生成SHA2证明失败: {}", err);
                            }
                        }
                        
                        // 计算并打印证明生成耗时
                        let elapsed = start_time.elapsed();
                        println!("SHA2证明生成耗时: {:.2?}", elapsed);
                    },
                    Err(err) => {
                        println!("读取SHA2数据失败: {}", err);
                    }
                }
            },
            "keccak" => {
                // 直接从文件中读取数据并反序列成HashResults
                match read_and_deserialize::<aggregation_script::algorithms::keccak::HashResults>(KECCAK_HASH_FILE) {
                    Ok(hash_results) => {
                        // 打印HashResults内容
                        println!("共读取到 {} 条Keccak哈希记录", hash_results.results.len());
                        for (i, result) in hash_results.results.iter().enumerate() {
                            println!("记录 {}: {{ message: '{}', hash: {} }}", 
                                    i + 1, result.message, result.hash);
                        }
                        
                        // client.setup返回直接是元组，不是Result
                        let (pk, vk) = client.setup(KECCAK_ELF);
                        
                        // 准备SP1Stdin，按照keccak程序期望的格式写入多条数据
                        let mut stdin = SP1Stdin::new();
                        
                        // 1. 写入结果列表长度
                        stdin.write(&(hash_results.results.len() as u32));
                        
                        // 2. 循环写入每条记录
                        for result in &hash_results.results {
                            // 写入消息长度
                            let message_bytes = result.message.as_bytes();
                            stdin.write(&(message_bytes.len() as u32));
                            
                            // 写入消息内容
                            for byte in message_bytes {
                                stdin.write(&byte);
                            }
                            
                            // 写入哈希值长度（注意：result.hash是十六进制字符串，需要先解码）
                            let hash_bytes = match hex::decode(&result.hash) {
                                Ok(bytes) => bytes,
                                Err(err) => {
                                    println!("解码哈希值失败: {}，跳过该记录", err);
                                    continue;
                                }
                            };
                            stdin.write(&(hash_bytes.len() as u32));
                            
                            // 写入哈希值内容
                            for byte in hash_bytes {
                                stdin.write(&byte);
                            }
                        }
                            
                        // 记录证明生成开始时间
                        let start_time = Instant::now();
                        
                        // 生成默认格式的证明
                        match client.prove(&pk, &stdin).compressed().run() {
                            Ok(proof) => {
                                let input = AggregationInput::new(proof, vk);
                                inputs.push(input);
                            },
                            Err(err) => {
                                println!("生成Keccak证明失败: {}", err);
                            }
                        }
                        
                        // 计算并打印证明生成耗时
                        let elapsed = start_time.elapsed();
                        println!("Keccak证明生成耗时: {:.2?}", elapsed);
                    },
                    Err(err) => {
                        println!("读取Keccak数据失败: {}", err);
                    }
                }
            },
            "sha3" => {
                // 直接从文件中读取数据并反序列成HashResults
                match read_and_deserialize::<aggregation_script::algorithms::sha3::HashResults>(SHA3_HASH_FILE) {
                    Ok(hash_results) => {
                        // 打印HashResults内容
                        println!("共读取到 {} 条SHA3哈希记录", hash_results.results.len());
                        for (i, result) in hash_results.results.iter().enumerate() {
                            println!("记录 {}: {{ message: '{}', hash: {} }}", 
                                    i + 1, result.message, result.hash);
                        }
                        
                        // client.setup返回直接是元组，不是Result
                        let (pk, vk) = client.setup(SHA3_ELF);
                        
                        // 准备SP1Stdin，按照sha3程序期望的格式写入多条数据
                        let mut stdin = SP1Stdin::new();
                        
                        // 1. 写入结果列表长度
                        stdin.write(&(hash_results.results.len() as u32));
                        
                        // 2. 循环写入每条记录
                        for result in &hash_results.results {
                            // 写入消息长度
                            let message_bytes = result.message.as_bytes();
                            stdin.write(&(message_bytes.len() as u32));
                            
                            // 写入消息内容
                            for byte in message_bytes {
                                stdin.write(&byte);
                            }
                            
                            // 写入哈希值长度（注意：result.hash是十六进制字符串，需要先解码）
                            let hash_bytes = match hex::decode(&result.hash) {
                                Ok(bytes) => bytes,
                                Err(err) => {
                                    println!("解码哈希值失败: {}，跳过该记录", err);
                                    continue;
                                }
                            };
                            stdin.write(&(hash_bytes.len() as u32));
                            
                            // 写入哈希值内容
                            for byte in hash_bytes {
                                stdin.write(&byte);
                            }
                        }
                            
                        // 记录证明生成开始时间
                        let start_time = Instant::now();
                        
                        // 生成默认格式的证明
                        match client.prove(&pk, &stdin).compressed().run() {
                            Ok(proof) => {
                                let input = AggregationInput::new(proof, vk);
                                inputs.push(input);
                            },
                            Err(err) => {
                                println!("生成SHA3证明失败: {}", err);
                            }
                        }
                        
                        // 计算并打印证明生成耗时
                        let elapsed = start_time.elapsed();
                        println!("SHA3证明生成耗时: {:.2?}", elapsed);
                    },
                    Err(err) => {
                        println!("读取SHA3数据失败: {}", err);
                    }
                }
            },
            "rsa" => {
                // 使用RSAHandler来处理RSA算法相关操作
                let mut rsa_handler = RSAHandler::new(RSA_ELF, RSA_HASH_FILE);
                
                // 读取数据
                if let Err(err) = rsa_handler.read_data() {
                    println!("读取RSA数据失败: {}", err);
                    break;
                }
                
                // 获取ELF并设置客户端
                let elf = rsa_handler.get_elf();
                let (pk, vk) = client.setup(elf);
                
                // 准备SP1Stdin
                let mut stdin = SP1Stdin::new();
                
                // 获取输入数据并写入stdin
                if let Ok(input_data) = rsa_handler.get_input_data() {
                    stdin.write(&input_data);
                } else {
                    println!("获取RSA输入数据失败");
                    break;
                }
                
                // 记录证明生成开始时间
                let start_time = Instant::now();
                
                // 生成默认格式的证明
                match client.prove(&pk, &stdin).compressed().run() {
                    Ok(proof) => {
                        let input = AggregationInput::new(proof, vk);
                        inputs.push(input);
                    },
                    Err(err) => {
                        println!("生成RSA证明失败: {}", err);
                    }
                }
                
                // 计算并打印证明生成耗时
                let elapsed = start_time.elapsed();
                println!("RSA证明生成耗时: {:.2?}", elapsed);
            },
            "ecdsa" => {
                // 使用ECDSAHandler来处理ECDSA算法相关操作
                let mut ecdsa_handler = ECDSAHandler::new(ECDSA_ELF, ECDSA_DATA_FILE);
                
                // 读取数据
                if let Err(err) = ecdsa_handler.read_data() {
                    println!("读取ECDSA数据失败: {}", err);
                    break;
                }
                
                // 获取ELF并设置客户端
                let elf = ecdsa_handler.get_elf();
                let (pk, vk) = client.setup(elf);
                
                // 准备SP1Stdin
                let mut stdin = SP1Stdin::new();
                
                // 获取原始数据并写入stdin
                if let Ok(ecdsa_results) = ecdsa_handler.get_data() {
                    // 先写入结果列表的长度
                    stdin.write(&(ecdsa_results.results.len() as u32));
                    
                    // 然后逐个写入每个ECDSA结果
                    for result in &ecdsa_results.results {
                        let message = result.message.as_bytes();
                        let signature_bytes = hex::decode(&result.signature_hex).expect("无效的hex签名数据");
                        let public_key_bytes = hex::decode(&result.public_key_hex).expect("无效的hex公钥数据");
                        
                        // 先写入消息长度和内容
                        stdin.write(&(message.len() as u32));
                        for byte in message {
                            stdin.write(&byte);
                        }
                        
                        // 先写入签名长度和内容
                        stdin.write(&(signature_bytes.len() as u32));
                        for byte in signature_bytes {
                            stdin.write(&byte);
                        }
                        
                        // 先写入公钥长度和内容
                        stdin.write(&(public_key_bytes.len() as u32));
                        for byte in public_key_bytes {
                            stdin.write(&byte);
                        }
                    }
                } else {
                    println!("获取ECDSA输入数据失败");
                    break;
                }
                
                // 记录证明生成开始时间
                let start_time = Instant::now();
                
                // 生成默认格式的证明
                match client.prove(&pk, &stdin).compressed().run() {
                    Ok(proof) => {
                        let input = AggregationInput::new(proof, vk);
                        inputs.push(input);
                    },
                    Err(err) => {
                        println!("生成ECDSA证明失败: {}", err);
                    }
                }
                
                // 计算并打印证明生成耗时
                let elapsed = start_time.elapsed();
                println!("ECDSA证明生成耗时: {:.2?}", elapsed);
            },
            "schnorr" => {
                // 使用SchnorrHandler来处理Schnorr算法相关操作
                let mut schnorr_handler = SchnorrHandler::new(SCHNORR_ELF, SCHNORR_DATA_FILE);
                
                // 读取数据
                if let Err(err) = schnorr_handler.read_data() {
                    println!("读取Schnorr数据失败: {}", err);
                    break;
                }
                
                // 获取ELF并设置客户端
                let elf = schnorr_handler.get_elf();
                let (pk, vk) = client.setup(elf);
                
                // 准备SP1Stdin
                let mut stdin = SP1Stdin::new();
                
                // 获取输入数据并写入stdin
                if let Ok(input_data) = schnorr_handler.get_input_data() {
                    stdin.write(&input_data);
                } else {
                    println!("获取Schnorr输入数据失败");
                    break;
                }
                
                // 记录证明生成开始时间
                let start_time = Instant::now();
                
                // 生成默认格式的证明
                match client.prove(&pk, &stdin).compressed().run() {
                    Ok(proof) => {
                        let input = AggregationInput::new(proof, vk);
                        inputs.push(input);
                    },
                    Err(err) => {
                        println!("生成Schnorr证明失败: {}", err);
                    }
                }
                
                // 计算并打印证明生成耗时
                let elapsed = start_time.elapsed();
                println!("Schnorr证明生成耗时: {:.2?}", elapsed);
            },
            "coset" => {
                // 使用DuskHandler来处理Dusk算法相关操作
                // 初始化CosetHandler
                let mut coset_handler = CosetHandler::new(
                    COSET_ELF,
                    PLONK_PROOF_FILE,
                    PLONK_PUBLICINPUTS_FILE,
                    VERIFIER_FILE
                );
                
                // 读取数据
                if let Err(err) = coset_handler.read_data() {
                    println!("读取Coset数据失败: {}", err);
                    break;
                }
                
                // 获取ELF并设置客户端
                let elf = coset_handler.get_elf();
                let (pk, vk) = client.setup(elf);
                
                // 准备SP1Stdin
                let mut stdin = SP1Stdin::new();
                
                // 使用get_separate_inputs()方法获取分离的输入数据
                if let Ok((public_inputs, proof, verifier)) = coset_handler.get_separate_inputs() {

                    //打印public_inputs，proof,verifier
                    println!("public_inputs: {:?}", public_inputs);
                    println!("proof: {:?}", proof);
                    // 写入第一个public_input（如果有）或32字节零
                    if !public_inputs.is_empty() {
                        let first_input_bytes = public_inputs[0].to_bytes();
                        stdin.write(&first_input_bytes);
                    } else {
                        stdin.write(&[0u8; 32]);
                    }
                    
                    // 写入proof字节
                    let proof_bytes = proof.to_bytes();
                    stdin.write(&proof_bytes.to_vec());
                    
                    // 写入verifier字节
                    let verifier_bytes = verifier.to_bytes();
                    stdin.write(&verifier_bytes.to_vec());
                } else {
                    println!("获取Coset输入数据失败");
                    break;
                }
                
                // 记录证明生成开始时间
                let start_time = Instant::now();
                
                // 生成默认格式的证明
                match client.prove(&pk, &stdin).compressed().run() {
                    Ok(proof) => {
                        let input = AggregationInput::new(proof, vk);
                        inputs.push(input);
                    },
                    Err(err) => {
                        println!("生成Coset证明失败: {}", err);
                    }
                }
                
                // 计算并打印证明生成耗时
                let elapsed = start_time.elapsed();
                println!("Coset证明生成耗时: {:.2?}", elapsed);
            }
            _ => {
                println!("警告: 未知的算法 '{0}'，支持的算法: fibonacci, sha2, keccak, sha3, rsa, ecdsa, schnorr, coset", algorithm);
            }
        }
    }

    if inputs.is_empty() {
        return Err(AggregationError::NoValidInputsError);
    }

    // 聚合证明
    let (aggregation_pk, _) = client.setup(AGGREGATION_ELF); // 设置聚合程序的证明密钥
    let mut stdin = SP1Stdin::new();

    // 写入验证密钥（以哈希形式）
    let vkeys = inputs.iter().map(|input| input.vk.hash_u32()).collect::<Vec<_>>();
    stdin.write::<Vec<[u32; 8]>>(&vkeys);

    // 写入公共值
    let public_values = 
        inputs.iter().map(|input| input.proof.public_values.to_vec()).collect::<Vec<_>>();
    stdin.write::<Vec<Vec<u8>>>(&public_values);

    // 注意：这些数据实际上不会被聚合程序读取，而是会在SP1内部的递归聚合过程中由证明器见证。
    // 直接使用bytes()方法获取proof的字节表示
    for input in inputs {
        let SP1Proof::Compressed(proof) = input.proof.proof else { panic!() };
        stdin.write_proof(*proof, input.vk.vk);
    }

    // 生成聚合证明
    client.prove(&aggregation_pk, &stdin).run()
        .map_err(|e| AggregationError::Sp1Error(e.to_string()))?;
    println!("证明聚合成功!");

    Ok(())
}