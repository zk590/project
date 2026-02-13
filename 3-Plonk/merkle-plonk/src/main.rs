// 使用rkyv进行序列化和反序列化
use bincode;
use coset_bls12_381::BlsScalar;
use coset_bytes::{DeserializableSlice, Serializable};
use plonk::prelude::*;
use poseidon_merkle::zk::opening_gadget;
use poseidon_merkle::{Item, Opening};
use rkyv::{Archive, Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind};
use std::io::{Read, Write};
use std::path::Path;

// 导入公共常量和电路定义
use common::constants::{
    CAPACITY, CIRCUIT_PROVE_FILE, MERKLE_FILE, PLONK_PROOF_FILE,
    PLONK_PUBLICINPUTS_FILE, TREE_HEIGHT, VERIFIER_FILE,
};

// 定义数据类型别名
type PoseidonItem = Item<()>;

/// 用于零知识证明的Merkle树路径电路,
// 该电路证明"我知道一个在特定位置的叶子节点，
// 使得它在具有给定根节点的Merkle树中"
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct OpeningCircuit {
    pub opening: Opening<(), { TREE_HEIGHT }>,
    pub leaf: Item<()>,
}

impl Default for OpeningCircuit {
    /// 构造用于编译/测试的默认电路实例。
    /// 该实例使用单叶节点树生成一条合法 opening，确保约束系统可被完整构建。
    /// 默认值不依赖外部文件，便于在纯代码路径下初始化 prover/verifier。
    fn default() -> Self {
        let empty = Item::<()> {
            hash: BlsScalar::zero(),
            data: (),
        };
        let mut tree = poseidon_merkle::Tree::new();
        tree.insert(0, empty);
        let opening = tree.opening(0).expect("There is a leaf at position 0");
        Self {
            opening,
            leaf: empty,
        }
    }
}

impl OpeningCircuit {
    /// 构造一条 Merkle 开证明对应的电路实例。
    pub fn new(opening: Opening<(), { TREE_HEIGHT }>, leaf: Item<()>) -> Self {
        Self { opening, leaf }
    }
}

impl Circuit for OpeningCircuit {
    /// 在约束系统中验证 `leaf` 与 `opening` 计算出的根是否匹配公开根。
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
// 定义Merkle证明数据结构，使用rkyv序列化
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct MerkleProofData {
    position: u64,
    leaf_hash: [u8; 32],
    root_hash: [u8; 32],
    proof_bytes: Vec<u8>,
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

// 定义零知识证明数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
struct ZKProofData {
    data: Vec<u8>,
}

/// 将 32 字节哈希解析为 `BlsScalar`。
#[inline]
fn parse_scalar_from_hash(
    hash_bytes: &[u8; 32],
    context: &str,
) -> Result<BlsScalar, IoError> {
    BlsScalar::from_bytes(hash_bytes)
        .into_option()
        .ok_or_else(|| {
            IoError::new(ErrorKind::Other, format!("{}失败", context))
        })
}

/// 使用 rkyv 将字节载荷包装为 `ZKProofData` 并写入文件。
#[inline]
fn write_archived_data_file(
    output_path: &str,
    payload: Vec<u8>,
) -> Result<usize, IoError> {
    let archived_payload = ZKProofData { data: payload };
    let serialized = rkyv::to_bytes::<_, 1024>(&archived_payload)
        .map_err(|e| IoError::new(ErrorKind::Other, e.to_string()))?;
    let mut output_file = File::create(output_path)?;
    output_file.write_all(&serialized)?;
    Ok(serialized.len())
}

/// 将扁平化字节数组按 32 字节切片恢复为公开输入标量向量。
#[inline]
fn parse_public_inputs(
    public_inputs_data: &[u8],
) -> Result<Vec<BlsScalar>, IoError> {
    let scalar_size = 32usize;
    if public_inputs_data.len() % scalar_size != 0 {
        return Err(IoError::new(ErrorKind::Other, "公开输入数据长度不正确"));
    }

    let mut public_inputs =
        Vec::with_capacity(public_inputs_data.len() / scalar_size);
    for scalar_chunk in public_inputs_data.chunks(scalar_size) {
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(scalar_chunk);
        let scalar = parse_scalar_from_hash(&scalar_bytes, "解析公开输入")?;
        public_inputs.push(scalar);
    }

    Ok(public_inputs)
}

/// 从指定文件路径读取全部字节并做存在性检查。
/// 该函数将文件访问错误统一映射为 `IoError`，便于上层链式传播。
/// 返回值仅负责字节加载，不承担具体结构化反序列化职责。
fn read_file_bytes_checked(file_path: &str) -> Result<Vec<u8>, IoError> {
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

/// 使用rkyv从文件中加载Merkle树的证明数据
/// 该函数会解析叶子哈希、根哈希与 opening 路径，并执行根一致性预检查。
/// 若任一环节失败会立即返回错误，避免后续证明流程建立在损坏输入之上。
/// 成功时返回“位置 + 叶子 + 根 + opening”的完整验证上下文。
fn load_merkle_opening_from_file()
-> Result<(u64, BlsScalar, BlsScalar, Opening<(), { TREE_HEIGHT }>), IoError> {
    // 使用rkyv反序列化MerkleProofData
    let bytes = read_file_bytes_checked(MERKLE_FILE)?;

    // 使用rkyv反序列化
    let proof_data = unsafe { rkyv::archived_root::<MerkleProofData>(&bytes) };

    // 提取数据
    let position = proof_data.position;

    // 解析叶子节点哈希
    let leaf_hash =
        parse_scalar_from_hash(&proof_data.leaf_hash, "解析叶子哈希")?;

    // 解析根哈希
    let root_hash =
        parse_scalar_from_hash(&proof_data.root_hash, "解析根哈希")?;

    // 使用Opening::from_slice方法反序列化证明
    let opening: Opening<(), { TREE_HEIGHT }> =
        match Opening::from_slice(&proof_data.proof_bytes) {
            Ok(opening) => opening,
            Err(error) => {
                return Err(IoError::new(
                    ErrorKind::Other,
                    format!("反序列化证明失败: {:?}", error),
                ));
            }
        };

    // 验证证明中的根哈希是否与提供的根哈希一致
    if opening.root().hash != root_hash {
        return Err(IoError::new(
            ErrorKind::Other,
            "证明中的根哈希与提供的根哈希不一致",
        ));
    }

    println!("使用rkyv成功加载Merkle证明数据");
    println!(" ├── 序列化数据大小: {} 字节", proof_data.proof_bytes.len());

    Ok((position, leaf_hash, root_hash, opening))
}

/// 加载或编译 prover/verifier
/// 该函数优先从缓存文件恢复 prover/verifier，并校验容量参数是否匹配。
/// 当缓存缺失或不一致时，会重新编译电路并回写缓存，保证运行稳定性。
/// 返回的对象可直接用于后续 `prove` 与 `verify` 流程，避免重复初始化开销。
fn load_or_compile_opening_circuit()
-> Result<(Prover, Verifier), Box<dyn std::error::Error>> {
    // 检查CIRCUIT_PROVE_FILE和VERIFIER_FILE是否存在
    if let (Ok(mut prover_file), Ok(mut verifier_file)) =
        (File::open(CIRCUIT_PROVE_FILE), File::open(VERIFIER_FILE))
    {
        // 读取证明器数据和容量信息
        let mut prover_buffer = Vec::new();
        prover_file.read_to_end(&mut prover_buffer)?;

        if let Ok(prover_with_capacity) =
            bincode::deserialize::<ProverWithCapacity>(&prover_buffer)
        {
            // 比较容量值
            if prover_with_capacity.capacity == CAPACITY {
                // 读取验证器数据
                let mut verifier_buffer = Vec::new();
                verifier_file.read_to_end(&mut verifier_buffer)?;

                let prover: Prover =
                    Prover::try_from_bytes(&prover_with_capacity.prover)?;
                let verifier: Verifier =
                    Verifier::try_from_bytes(&verifier_buffer)?;

                println!(
                    "加载缓存的 prover/verifier 成功 (容量: {})",
                    CAPACITY
                );
                return Ok((prover, verifier));
            } else {
                println!(
                    "容量不匹配: 文件中的容量={}, 当前设置的容量={}",
                    prover_with_capacity.capacity, CAPACITY
                );
            }
        }
    }

    // 文件不存在或容量不匹配，编译电路
    let circuit_label = b"opening-circuit";
    let mut rng = rand::thread_rng();
    let public_parameters = PublicParameters::setup(1 << CAPACITY, &mut rng)?;
    let (prover, verifier) =
        Compiler::compile::<OpeningCircuit>(&public_parameters, circuit_label)?;

    // 保存证明器和容量信息到CIRCUIT_PROVE_FILE
    let prover_with_capacity = ProverWithCapacity {
        capacity: CAPACITY,
        prover: prover.to_bytes(),
    };
    fs::write(
        CIRCUIT_PROVE_FILE,
        bincode::serialize(&prover_with_capacity)?,
    )?;

    // 保存验证器到VERIFIER_FILE
    let verifier_bytes = verifier.to_bytes();
    fs::write(VERIFIER_FILE, &verifier_bytes)?;

    println!("电路首次编译并缓存 prover/verifier (容量: {})", CAPACITY);

    Ok((prover, verifier))
}

/// 读取 Merkle opening 并生成单条 PLONK 证明，随后落盘证明与公开输入。
fn generate_and_store_zk_proof() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n===== 生成零知识证明 ======");

    // 从文件中加载证明数据
    let (_leaf_position, leaf_hash, _root_hash, opening) =
        load_merkle_opening_from_file()?;
    println!("1. 加载证明数据成功");
    println!("   - 叶子节点哈希: {:?}", leaf_hash);

    // 创建叶子节点
    let leaf = PoseidonItem::new(leaf_hash, ());

    // 检查叶子节点是否有效（先进行常规验证）
    if !opening.verify(leaf.clone()) {
        return Err("叶子节点不在Merkle树中，无法生成零知识证明".into());
    }
    println!("2. 常规验证通过，可以生成零知识证明");

    let (prover, _cached_verifier) = load_or_compile_opening_circuit()?;

    // 创建电路实例
    let circuit = OpeningCircuit::new(opening, leaf);

    // 生成零知识证明
    let (proof, public_inputs) =
        prover.prove(&mut rand::thread_rng(), &circuit)?;
    println!("3. 生成零知识证明成功");

    // 将Proof转换为字节数组
    let proof_bytes = proof.to_bytes();

    // 将BlsScalar向量转换为字节数组的向量
    let public_inputs_flattened: Vec<u8> = public_inputs
        .iter()
        .flat_map(|scalar| scalar.to_bytes().to_vec())
        .collect();

    let proof_bytes_serialized_len =
        write_archived_data_file(PLONK_PROOF_FILE, proof_bytes.to_vec())?;
    let public_inputs_bytes_serialized_len = write_archived_data_file(
        PLONK_PUBLICINPUTS_FILE,
        public_inputs_flattened,
    )?;

    println!("4. 使用rkyv成功保存证明数据");
    println!(" ├── 证明数据大小: {} 字节", proof_bytes_serialized_len);
    println!(
        " └── 公开输入数据大小: {} 字节",
        public_inputs_bytes_serialized_len
    );

    Ok(())
}

/// 验证零知识证明
/// 该函数会读取证明、公开输入与验证器，并执行 PLONK 证明校验。
/// 校验通过后还会复用 opening 对叶子成员关系再做一次业务一致性验证。
/// 这种“双重验证”可同时覆盖电路正确性与输入数据绑定正确性。
pub fn verify_proof() -> Result<(), IoError> {
    // 加载证明数据
    let (_leaf_position, leaf_hash, _root_hash, opening) =
        load_merkle_opening_from_file()?;

    // 加载验证器
    let verifier_bytes = std::fs::read(VERIFIER_FILE)?;
    let verifier: Verifier = Verifier::try_from_bytes(&verifier_bytes)
        .map_err(|e| {
            IoError::new(
                ErrorKind::Other,
                format!("反序列化验证器失败: {:?}", e),
            )
        })?;

    // 使用rkyv读取证明数据
    let bytes = read_file_bytes_checked(PLONK_PROOF_FILE)?;
    let proof_data = unsafe { rkyv::archived_root::<ZKProofData>(&bytes) };
    let proof = Proof::from_slice(&proof_data.data).map_err(|e| {
        IoError::new(ErrorKind::Other, format!("反序列化证明失败: {:?}", e))
    })?;

    // 使用rkyv读取公开输入数据
    let public_inputs_bytes = read_file_bytes_checked(PLONK_PUBLICINPUTS_FILE)?;
    let public_inputs_data =
        unsafe { rkyv::archived_root::<ZKProofData>(&public_inputs_bytes) };

    let public_inputs = parse_public_inputs(&public_inputs_data.data)?;

    // 验证零知识证明
    verifier.verify(&proof, &public_inputs).map_err(|e| {
        IoError::new(ErrorKind::Other, format!("验证证明失败: {:?}", e))
    })?;

    // 验证成功
    println!("零知识证明验证成功");

    // 创建叶子节点并验证Merkle树证明
    let leaf = PoseidonItem::new(leaf_hash, ());
    let is_valid = opening.verify(leaf);

    if is_valid {
        println!("Merkle树证明验证成功");
    } else {
        println!("Merkle树证明验证失败");
        return Err(IoError::new(ErrorKind::Other, "Merkle树证明验证失败"));
    }

    Ok(())
}

/// CLI 入口：先生成证明，再执行一次验证。
fn main() {
    println!("===== 验证基于Poseidon Hash的Merkle树叶子节点 ======");
    // 从文件中加载证明数据
    match load_merkle_opening_from_file() {
        Ok((position, leaf_hash, root_hash, opening)) => {
            println!("1. 成功加载证明数据");
            println!("├── 叶子节点位置: {}", position);
            println!("├── 叶子节点哈希: {:?}", leaf_hash);
            println!("└── 根节点哈希: {:?}", root_hash);

            // 验证证明中的根哈希是否与加载的根哈希一致（额外安全检查）
            if opening.root().hash == root_hash {
                println!("2. 根哈希一致性检查通过");
            } else {
                println!(
                    "2. 根哈希一致性检查失败！证明中的根哈希与加载的根哈希不一致"
                );
                return;
            }

            // 创建叶子节点
            let leaf = PoseidonItem::new(leaf_hash, ());

            // 验证叶子节点是否在Merkle树中
            println!("3. 开始验证叶子节点是否在Merkle树中...");
            let is_valid = opening.verify(leaf);

            if is_valid {
                println!(
                    "4. 验证成功！叶子节点确实在具有给定根节点的Merkle树中"
                );
            } else {
                println!("4. 验证失败！叶子节点不在Merkle树中或证明无效");
            }
        }
        Err(error) => {
            println!(" 错误：无法加载证明数据");
            println!("  ├── 详细信息: {}", error);
        }
    }
    println!("===== merkle验证流程完成 ======");
    println!("===== 生成plonk证明 ======");

    match generate_and_store_zk_proof() {
        Ok(()) => {
            println!("零知识证明已成功生成并保存到{}", PLONK_PROOF_FILE);
            println!("===== 验证plonk证明 ======");

            match verify_proof() {
                Ok(()) => println!("零知识证明验证成功"),
                Err(e) => {
                    println!("错误：无法验证零知识证明");
                    println!("  ├── 详细信息: {}", e);
                }
            }
        }
        Err(error) => {
            println!("错误：无法生成零知识证明");
            println!("  ├── 详细信息: {}", error);
        }
    }
}
