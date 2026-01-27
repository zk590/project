use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use rkyv::{Archive, Deserialize, Serialize};
use coset_bls12_381::BlsScalar;
use poseidon_merkle::{Item, Opening};
use std::fs::File;
use std::io::{Read, Error as IoError, ErrorKind};
use std::path::Path;
use std::time::{Instant, Duration};
use common::constants::{MERKLE_FILE};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("merkle-program");

// 定义单个叶子节点信息的数据结构
#[derive(Archive, Serialize, Deserialize, Debug, Clone)]
#[archive(check_bytes)]
struct LeafInfo {
    position: u64,
    leaf_hash: [u8; 32],
    proof_bytes: Vec<u8>, //节点路径
}

// 定义包含多个叶子节点信息的数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct MultipleLeavesData {
    root_hash: [u8; 32],
    leaves_info: Vec<LeafInfo>,
}

// 从文件读取并使用rkyv反序列化
fn read_and_deserialize<T: Archive>(file_path: &str) -> Result<Vec<u8>, IoError> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(IoError::new(ErrorKind::NotFound, "文件不存在"));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    Ok(bytes)
}

/// 使用rkyv从文件中加载Merkle树的证明数据（支持多个叶子节点）
fn load_multiple_proof_data(file_path: &str) -> Result<MultipleLeavesData, IoError> {
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    // 使用rkyv反序列化
    let data = unsafe { rkyv::archived_root::<MultipleLeavesData>(&bytes) };
    
    println!("使用rkyv成功加载Merkle证明数据");
    println!(" ├── 总共有 {} 个叶子节点证明", data.leaves_info.len());
    println!(" ├── 序列化数据大小: {} 字节", bytes.len());
    
    // 转换为非归档类型
    let result = MultipleLeavesData {
        root_hash: data.root_hash,
        leaves_info: data.leaves_info
            .iter()
            .map(|leaf| LeafInfo {
                position: leaf.position,
                leaf_hash: leaf.leaf_hash,
                proof_bytes: leaf.proof_bytes.to_vec(),
            })
            .collect(),
    };
    
    Ok(result)
}

fn main() {
    // 从文件中加载证明数据（使用MERKLE_SOME_FILE支持多个叶子节点）
    let data = load_multiple_proof_data(common::constants::MERKLE_SOME_FILE)
        .expect("无法加载证明数据");
    
    println!("1. 成功加载证明数据");
    println!("├── 根节点哈希: {:?}", data.root_hash);
    println!("└── 总共有 {} 个叶子节点证明", data.leaves_info.len());
    
    // 准备传递给program的输入
    let mut stdin = SP1Stdin::new();
    
    // 写入叶子节点数量
    let num_leaves = data.leaves_info.len() as u64;
    stdin.write(&num_leaves);
    
    // 写入根节点哈希
    stdin.write(&data.root_hash);
    
    // 为每个叶子节点写入数据
    for (i, leaf_info) in data.leaves_info.iter().enumerate() {
        println!("\n处理叶子节点 {}:", i+1);
        println!("├── 位置: {}", leaf_info.position);
        println!("└── 哈希: {:?}", leaf_info.leaf_hash);
        
        // 写入叶子节点位置
        stdin.write(&leaf_info.position);
        
        // 写入叶子节点哈希
        stdin.write(&leaf_info.leaf_hash);
        
        // 写入证明数据长度
        let proof_len = leaf_info.proof_bytes.len() as u32;
        stdin.write(&proof_len);
        
        // 写入证明数据
        for byte in &leaf_info.proof_bytes {
            stdin.write(byte);
        }
    }
    

    
    // Create a `ProverClient` method.
    let client = ProverClient::from_env();
    
    // Execute the program using the `ProverClient.execute` method, without generating a proof.
    let (_, report) = client.execute(ELF, &stdin).run().unwrap();
    println!("executed program with {} cycles", report.total_instruction_count());
    
    // Generate the proof for the given program and input.
    let (pk, vk) = client.setup(ELF);
    let start_time = Instant::now();
    let proof = client.prove(&pk, &stdin).compressed().run().unwrap();
    let duration = start_time.elapsed();
    println!("generated proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
    
    // Verify proof and public values
    let start_time = Instant::now();
    client.verify(&proof, &vk).expect("verification failed");
    let duration = start_time.elapsed();
    println!("verified proof in {}.{:03} seconds", duration.as_secs(), duration.subsec_millis());
}