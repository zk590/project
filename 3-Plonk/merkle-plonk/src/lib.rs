// 使用rkyv进行序列化和反序列化
use bincode;
use coset_bls12_381::BlsScalar;
use coset_bytes::Serializable;
use plonk::prelude::*;
use poseidon_merkle::zk::opening_gadget;
use poseidon_merkle::{Item, Opening, Tree};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::{Error as IoError, ErrorKind};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

// 仅保留树高作为编译期常量；文件路径与容量改为运行期可配置。
use common::constants::TREE_HEIGHT;

// 定义数据类型别名
type PoseidonItem = Item<()>;

/// 批量证明服务配置：用于外部集成时注入文件路径与电路参数。
#[derive(Debug, Clone)]
pub struct BatchProofConfig {
    pub merkle_input_file: PathBuf,
    pub circuit_cache_file: PathBuf,
    pub verifier_file: PathBuf,
    pub output_dir: PathBuf,
    pub proof_file_prefix: String,
    pub public_inputs_file_prefix: String,
    pub capacity: usize,
}

impl Default for BatchProofConfig {
    fn default() -> Self {
        Self {
            merkle_input_file: PathBuf::from(
                common::constants::MERKLE_SOME_FILE,
            ),
            circuit_cache_file: PathBuf::from("circuit_prove.bin"),
            verifier_file: PathBuf::from(common::constants::VERIFIER_FILE),
            output_dir: PathBuf::from("."),
            proof_file_prefix: "plonk_proof_".to_string(),
            public_inputs_file_prefix: "plonk_publicinputs_".to_string(),
            capacity: common::constants::CAPACITY,
        }
    }
}

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

// 定义零知识证明数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct ZKProofData {
    data: Vec<u8>,
}

// 存储带容量信息的证明器数据
#[derive(
    Archive, Serialize, Deserialize, Debug, serde::Serialize, serde::Deserialize,
)]
#[archive(check_bytes)]
struct ProverWithCapacity {
    capacity: usize,
    prover: Vec<u8>,
}

// 用于零知识证明的Merkle树路径电路,
// 该电路证明"我知道一个在特定位置的叶子节点，
// 使得它在具有给定根节点的Merkle树中"
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct OpeningCircuit {
    pub opening: Opening<(), { TREE_HEIGHT }>,
    pub leaf: Item<()>,
}

impl Default for OpeningCircuit {
    fn default() -> Self {
        let empty = Item::<()> {
            hash: BlsScalar::zero(),
            data: (),
        };
        let mut tree = Tree::new();
        tree.insert(0, empty);
        let opening = tree.opening(0).expect("There is a leaf at position 0");
        Self {
            opening,
            leaf: empty,
        }
    }
}

impl OpeningCircuit {
    /// 构造单个叶子 opening 对应的电路实例。
    pub fn new(opening: Opening<(), { TREE_HEIGHT }>, leaf: Item<()>) -> Self {
        Self { opening, leaf }
    }
}

impl Circuit for OpeningCircuit {
    /// 在电路中重建 Merkle 根，并与公开输入根做一致性约束。
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let leaf = composer.append_witness(self.leaf.hash);
        let computed_root = opening_gadget(composer, &self.opening, leaf);

        let constraint = Constraint::new()
            .left(-BlsScalar::one())
            .a(computed_root)
            .public(self.opening.root().hash);
        composer.append_gate(constraint);

        Ok(())
    }
}

// 从文件读取并使用rkyv反序列化数据
fn read_file_bytes_checked(
    file_path: impl AsRef<Path>,
) -> Result<Vec<u8>, IoError> {
    let file_path = file_path.as_ref();
    // 检查文件是否存在
    if !file_path.exists() {
        return Err(IoError::new(ErrorKind::NotFound, "文件不存在"));
    }

    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    Ok(bytes)
}

/// 加载缓存电路；若缓存不存在或容量不匹配则重新编译并写回。
fn load_or_compile_opening_circuit(
    config: &BatchProofConfig,
) -> Result<(Prover, Verifier), Box<dyn std::error::Error>> {
    // 检查CIRCUIT_PROVE_FILE和VERIFIER_FILE是否存在
    if let (Ok(mut prover_file), Ok(mut verifier_file)) = (
        File::open(&config.circuit_cache_file),
        File::open(&config.verifier_file),
    ) {
        // 读取证明器数据和容量信息
        let mut prover_buffer = Vec::new();
        prover_file.read_to_end(&mut prover_buffer)?;

        if let Ok(prover_with_capacity) =
            bincode::deserialize::<ProverWithCapacity>(&prover_buffer)
        {
            // 比较容量值
            if prover_with_capacity.capacity == config.capacity {
                // 读取验证器数据
                let mut verifier_buffer = Vec::new();
                verifier_file.read_to_end(&mut verifier_buffer)?;

                let prover: Prover =
                    Prover::try_from_bytes(&prover_with_capacity.prover)?;
                let verifier: Verifier =
                    Verifier::try_from_bytes(&verifier_buffer)?;

                println!(
                    "加载缓存的 prover/verifier 成功 (容量: {})",
                    config.capacity
                );
                return Ok((prover, verifier));
            } else {
                println!(
                    "容量不匹配: 文件中的容量={}, 当前设置的容量={}",
                    prover_with_capacity.capacity, config.capacity
                );
            }
        }
    }

    // 文件不存在或容量不匹配，编译电路
    if let Some(parent) = config.circuit_cache_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = config.verifier_file.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let circuit_label = b"opening-circuit";
    let mut rng = rand::thread_rng();
    let public_parameters =
        PublicParameters::setup(1 << config.capacity, &mut rng)?;
    let (prover, verifier) =
        Compiler::compile::<OpeningCircuit>(&public_parameters, circuit_label)?;

    // 保存证明器和容量信息到circuit_prove.bin
    let prover_with_capacity = ProverWithCapacity {
        capacity: config.capacity,
        prover: prover.to_bytes(),
    };
    std::fs::write(
        &config.circuit_cache_file,
        bincode::serialize(&prover_with_capacity)?,
    )?;

    // 保存验证器到VERIFIER_FILE
    let verifier_bytes = verifier.to_bytes();
    std::fs::write(&config.verifier_file, &verifier_bytes)?;

    println!(
        "电路首次编译并缓存 prover/verifier (容量: {})",
        config.capacity
    );

    Ok((prover, verifier))
}

/// 批量校验叶子 opening，并为通过校验的条目生成并验证 PLONK 证明。
/// 对外服务入口：批量验证 Merkle opening，并生成/验证 PLONK 证明后落盘。
pub fn process_batch_proofs_with_config(
    config: &BatchProofConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n===== 批量验证叶子节点并生成零知识证明 ======");
    std::fs::create_dir_all(&config.output_dir)?;

    // 从文件中加载MultipleLeavesData
    let bytes = read_file_bytes_checked(&config.merkle_input_file)?;
    let all_leaves_data =
        unsafe { rkyv::archived_root::<MultipleLeavesData>(&bytes) };
    println!("MultipleLeavesData 加载成功");
    // 解析根哈希
    let root_hash =
        match BlsScalar::from_bytes(&all_leaves_data.root_hash).into_option() {
            Some(hash) => hash,
            None => {
                return Err(Box::new(IoError::new(
                    ErrorKind::Other,
                    "解析根哈希失败",
                )));
            }
        };
    println!("根哈希加载成功");
    let circuit_load_start = Instant::now();
    // 加载或编译电路
    let (prover, verifier) = load_or_compile_opening_circuit(config)?;
    let circuit_load_end = Instant::now();
    let circuit_load_duration =
        circuit_load_end.duration_since(circuit_load_start);
    println!("加载电路耗时: {:?}", circuit_load_duration);
    println!(
        "Plonk Proof verifier = {}",
        hex::encode(verifier.to_bytes())
    );

    println!(
        "1. 收到{} 个叶子节点数据",
        all_leaves_data.leaves_info.len()
    );
    println!(
        "Plonk Public_input.root = {}",
        hex::encode(all_leaves_data.root_hash)
    );
    // 处理所有叶子节点
    for (leaf_index, leaf_info) in
        all_leaves_data.leaves_info.iter().enumerate()
    {
        println!("\n处理叶子节点 ");
        // println!("\n处理叶子节点 {} （位置: {}）", leaf_index + 1,
        // leaf_info.position);
        if leaf_index == 0 {
            println!(
                "Plonk Public_input.leaf = {}",
                hex::encode(leaf_info.leaf_hash)
            );
        }
        // 解析叶子节点哈希
        let leaf_hash =
            match BlsScalar::from_bytes(&leaf_info.leaf_hash).into_option() {
                Some(hash) => hash,
                None => {
                    println!("  解析叶子哈希失败，跳过此节点");
                    continue;
                }
            };

        // 使用Opening::from_slice方法反序列化叶子路径
        let opening: Opening<(), { TREE_HEIGHT }> =
            match Opening::from_slice(&leaf_info.proof_bytes) {
                Ok(opening) => opening,
                Err(error) => {
                    println!("  反序列化证明失败: {:?}，跳过此节点", error);
                    continue;
                }
            };

        // 验证证明中的根哈希是否与提供的根哈希一致
        if opening.root().hash != root_hash {
            println!("  证明中的根哈希与提供的根哈希不一致，跳过此节点");
            continue;
        }

        // 创建叶子节点
        let leaf = PoseidonItem::new(leaf_hash, ());

        // 检查叶子节点是否有效（先进行常规验证）
        if !opening.verify(leaf.clone()) {
            println!("  叶子节点不在Merkle树中，跳过此节点");
            continue;
        }

        // println!(" 开始生成零知识证明");
        // 创建电路实例
        let circuit = OpeningCircuit::new(opening, leaf);
        let first_circuit_start = if leaf_index == 0 {
            Some(Instant::now())
        } else {
            None
        };
        // 生成零知识证明
        let mut rng = StdRng::seed_from_u64(0xdea1 + leaf_index as u64);
        let (proof, public_inputs) = prover.prove(&mut rng, &circuit)?;
        // println!("  生成零知识证明成功");
        if let Some(first_start) = first_circuit_start {
            println!("Plonk proof = {}", hex::encode(proof.to_bytes()));
            let first_end = Instant::now();
            let first_proof_duration = first_end.duration_since(first_start);
            println!("生成Plonk证明耗时: {:?}", first_proof_duration);
        }

        // 验证零知识证明
        verifier.verify(&proof, &public_inputs).map_err(|error| {
            IoError::new(ErrorKind::Other, format!("验证证明失败: {:?}", error))
        })?;
        println!("  验证零知识证明成功");
        // 将Proof转换为字节数组
        let proof_bytes = proof.to_bytes();

        // 将BlsScalar向量转换为字节数组的向量
        let public_inputs_flattened: Vec<u8> = public_inputs
            .iter()
            .flat_map(|scalar| scalar.to_bytes().to_vec())
            .collect();

        // 使用rkyv保存证明数据
        let proof_data = ZKProofData {
            data: proof_bytes.to_vec(),
        };

        // 为每个证明创建唯一的文件名（按照1、2、3的顺序）
        let proof_file_name =
            format!("{}{}.bin", config.proof_file_prefix, leaf_index + 1);
        let public_inputs_file_name = format!(
            "{}{}.bin",
            config.public_inputs_file_prefix,
            leaf_index + 1
        );
        let proof_file_path = config.output_dir.join(&proof_file_name);
        let public_inputs_file_path =
            config.output_dir.join(&public_inputs_file_name);

        // 序列化并保存到文件
        let mut proof_file = File::create(&proof_file_path)?;
        let proof_bytes_serialized = rkyv::to_bytes::<_, 1024>(&proof_data)?;
        proof_file.write_all(&proof_bytes_serialized)?;

        // 使用rkyv保存公开输入数据
        let public_inputs_data = ZKProofData {
            data: public_inputs_flattened,
        };

        let mut public_inputs_file = File::create(&public_inputs_file_path)?;
        let public_inputs_bytes_serialized =
            rkyv::to_bytes::<_, 1024>(&public_inputs_data)?;
        public_inputs_file.write_all(&public_inputs_bytes_serialized)?;

        println!("  成功保存证明数据");
        println!("   ├── 证明文件: {}", proof_file_path.display());
        println!("   ├── 证明数据大小: {} 字节", proof_bytes_serialized.len());
        println!("   ├── 公开输入文件: {}", public_inputs_file_path.display());
        println!(
            "   └── 公开输入数据大小: {} 字节",
            public_inputs_bytes_serialized.len()
        );
    }

    // println!("\n===== 批量处理完成 ======");

    Ok(())
}

/// 使用默认配置执行批量证明流程（兼容旧调用方）。
pub fn process_batch_proofs() -> Result<(), Box<dyn std::error::Error>> {
    process_batch_proofs_with_config(&BatchProofConfig::default())
}

/// 命令行入口包装：打印日志并调用批处理服务。
pub fn run_batch_cli() {
    println!("===== 批量验证Merkle树叶子节点并生成零知识证明 ======");

    match process_batch_proofs_with_config(&BatchProofConfig::default()) {
        Ok(()) => println!("\n Plonk 零知识证明生成完成"),
        Err(error) => {
            println!("\n错误：批量验证和零知识证明生成失败");
            println!("  ├── 详细信息: {}", error);
        }
    }
}

/// 使用外部传入配置运行 CLI 风格输出流程。
pub fn run_batch_cli_with_config(config: &BatchProofConfig) {
    println!("===== 批量验证Merkle树叶子节点并生成零知识证明 ======");

    match process_batch_proofs_with_config(config) {
        Ok(()) => println!("\n Plonk 零知识证明生成完成"),
        Err(error) => {
            println!("\n错误：批量验证和零知识证明生成失败");
            println!("  ├── 详细信息: {}", error);
        }
    }
}
