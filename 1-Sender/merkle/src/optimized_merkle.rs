use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use rand::prelude::SliceRandom;
use coset_bls12_381::BlsScalar;
use coset_poseidon::{Domain, Hash};
use poseidon_merkle::{Item as PoseidonItem, Opening, Tree as PoseidonTree};

use rkyv::{Archive, Serialize, Deserialize};
use common::constants::{TREE_HEIGHT, MERKLE_FILE, MERKLE_SOME_FILE, MERKLE_TREE_STATE_FILE};

use std::env;
use std::fs::File;
use std::io::{Write, Read};
use std::path::Path;
use std::time::Instant;
use std::sync::Mutex;

use lazy_static::lazy_static;

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

// 使用rkyv将MultipleLeavesData序列化并写入文件
fn serialize_multiple_leaves_to_file(data: &MultipleLeavesData, file_path: &str) -> Result<(), std::io::Error> {
    // 使用rkyv序列化结果
    let bytes = rkyv::to_bytes::<_, 256>(data)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "序列化失败"))?;
    
    // 打开或创建文件
    let mut file = File::create(file_path)?;
    
    // 写入序列化后的字节
    file.write_all(&bytes)?;    
    // println!("序列化字节大小: {} 字节", bytes.len());
    
    Ok(())
}

/// 从文件读取并使用rkyv反序列化MultipleLeavesData
fn read_and_deserialize_multiple_leaves(file_path: &str) -> Result<MultipleLeavesData, std::io::Error> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "文件不存在"));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    // 使用rkyv反序列化
    let deserialized = rkyv::from_bytes(&bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "反序列化失败"))?;
    
    Ok(deserialized)
}

// 创建全局的Merkle树实例
lazy_static! {
    static ref GLOBAL_MERKLE_TREE: Mutex<PoseidonTree::<(), { TREE_HEIGHT }>> = {
        // 尝试从文件加载已保存的树状态，如果失败则创建新树
        let tree = match load_tree_state() {
            Ok(loaded_tree) => {
                println!("成功从文件加载Merkle树状态");
                loaded_tree
            },
            Err(e) => {
                println!("无法加载Merkle树状态，创建新树: {}", e);
                PoseidonTree::<(), { TREE_HEIGHT }>::new()
            }
        };
        Mutex::new(tree)
    };
}

///// 获取全局Merkle树的访问函数
fn get_global_merkle_tree() -> &'static Mutex<PoseidonTree::<(), { TREE_HEIGHT }>> {
    &GLOBAL_MERKLE_TREE
}

/// 从文件加载Merkle树状态
fn load_tree_state() -> Result<PoseidonTree::<(), { TREE_HEIGHT }>, std::io::Error> {
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;
    use rkyv::Deserialize;
    
    let file_path = MERKLE_TREE_STATE_FILE;
    
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "树状态文件不存在"));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    // 使用rkyv反序列化树状态
    let tree = rkyv::from_bytes::<PoseidonTree::<(), { TREE_HEIGHT }>>(&bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "反序列化失败"))?;
    
    Ok(tree)
}

/// 将Merkle树状态保存到文件（接受已锁定的树引用）
fn save_tree_state(tree: &PoseidonTree<(), { TREE_HEIGHT }>) -> Result<(), std::io::Error> {
    use std::fs::File;
    use std::io::Write;
    
    let file_path = MERKLE_TREE_STATE_FILE;
    
    // 使用rkyv序列化树状态
    let bytes = rkyv::to_bytes::<_, 256>(tree)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "序列化失败"))?;
    
    // 打开或创建文件
    let mut file = File::create(file_path)?;
    
    // 写入序列化后的字节
    file.write_all(&bytes)?;
    
    println!("Merkle树状态已保存到文件: {}", file_path);
    
    Ok(())
}

/// 将Merkle树状态保存到文件（获取全局树锁）
fn save_global_tree_state() -> Result<(), std::io::Error> {
    // 获取全局树的锁
    let tree_guard = get_global_merkle_tree().lock().unwrap();
    
    // 调用接受已锁定树引用的版本
    save_tree_state(&*tree_guard)
}



/// 初始化Merkle树并插入指定数量的叶子节点（接受已锁定的树引用）
fn initialize_merkle_tree(tree: &mut PoseidonTree<(), { TREE_HEIGHT }>, num_leaves: u64) -> Vec<u64> {
    // 创建一个随机数生成器
    let mut rng = StdRng::seed_from_u64(0xdea1);
    
    // 插入数据到树中
    let mut positions = Vec::with_capacity(num_leaves as usize);
    
    for i in 0..num_leaves {
        // 生成一个随机的BlsScalar值
        let value = rng.next_u64();
        let scalar = BlsScalar::from(value);
        let hash = Hash::digest(Domain::Other, &[scalar])[0];
        // 创建一个Poseidon Merkle树的叶子节点
        let leaf = PoseidonItem::new(hash, ());
        // 插入到树中的特定位置
        tree.insert(i as u64, leaf);
        positions.push(i as u64);
    }
    
    positions
}

/// 向Merkle树中添加指定数量的新叶子节点（接受已锁定的树引用）
fn add_new_leaves(tree: &mut PoseidonTree<(), { TREE_HEIGHT }>, num_new_leaves: u64) -> Vec<u64> {
    // 创建一个随机数生成器
    let mut rng = StdRng::seed_from_u64(0xdea1);
    
    // 获取当前树中的叶子节点数量
    let current_count = tree.len();
    
    // 插入新数据到树中
    let mut positions = Vec::with_capacity(num_new_leaves as usize);
    
    for i in 0..num_new_leaves {
        // 生成一个随机的BlsScalar值
        let value = rng.next_u64();
        let scalar = BlsScalar::from(value);
        let hash = Hash::digest(Domain::Other, &[scalar])[0];
        // 创建一个Poseidon Merkle树的叶子节点
        let leaf = PoseidonItem::new(hash, ());
        // 插入到树中的下一个可用位置
        let new_position = current_count + i;
        tree.insert(new_position, leaf);
        positions.push(new_position);
    }
    
    positions
}

/// 获取指定位置的叶子节点
fn get_leaf_at_position(tree: &PoseidonTree<(), { TREE_HEIGHT }>, position: u64) -> PoseidonItem<()> {
    if let Some(opening) = tree.opening(position) {
        // 获取叶子层（最后一层）的对应位置的叶子节点
        let branch = opening.branch();
        let positions = opening.positions();
        // 使用树高-1作为branch的索引，获取叶子层的节点
        PoseidonItem::new(branch[TREE_HEIGHT-1][positions[TREE_HEIGHT-1]].hash, ())
    } else {
        panic!("无法获取位置 {} 的叶子节点", position);
    }
}

/// 为指定位置的叶子节点生成证明路径并创建LeafInfo
fn create_leaf_info(tree: &PoseidonTree<(), { TREE_HEIGHT }>, position: u64) -> LeafInfo {
    let leaf = get_leaf_at_position(tree, position);
    let opening = tree.opening(position).unwrap();
    
    // 验证证明路径
    let is_valid = opening.verify(leaf.clone());
    if is_valid {
        // println!("位置 {} 的叶子节点验证通过", position);
    } else {
        println!("位置 {} 的叶子节点验证失败", position);
    }
    
    // 准备证明路径
    const T_SIZE: usize = 32; // BlsScalar的大小是32字节
    let opening_bytes = opening.to_var_bytes::<T_SIZE>();
    
    // 创建LeafInfo实例
    LeafInfo {
        position,
        leaf_hash: leaf.hash.to_bytes(),
        proof_bytes: opening_bytes,
    }
}

/// 模拟链上Merkle树生成环境
fn simulate_chain_environment(num_leaves: u64) {
    println!("1. 使用全局Poseidon Merkle树模拟链上环境");
    
    // 获取全局树的锁
    let mut tree_guard = get_global_merkle_tree().lock().unwrap();
    
    // 检查树是否为空，如果为空则初始化
    if tree_guard.root().hash == BlsScalar::zero() {
        // 初始化全局树
        let start_time = Instant::now();
        let _positions = initialize_merkle_tree(&mut tree_guard, num_leaves);
        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        println!("2. 全局Merkle树已初始化，包含{}个叶子节点，耗时: {:?}", num_leaves, duration);
    }
    
    // 获取树的根节点哈希值并复制
    let root_hash = tree_guard.root().hash.clone();
    println!("3. Merkle树根节点哈希值: {:?}", root_hash);
     
    // 创建随机数生成器用于选择叶子节点
    let mut rng = StdRng::seed_from_u64(0xdea1);
    
    // 随机选择一个叶子节点位置
    let random_position = rng.next_u64() % num_leaves;
       
    // 获取该位置的叶子节点
    let leaf_from_chain = get_leaf_at_position(&tree_guard, random_position);
    
    // 验证证明路径
    let opening = tree_guard.opening(random_position).unwrap();
    let is_valid = opening.verify(leaf_from_chain.clone());
    if is_valid {
        println!("4. 自验证通过：节点路径有效");
    } else {
        println!("4. 自验证失败：节点路径无效");
    }
    
    // 释放锁，因为create_and_save_leaves_data会重新获取锁
    drop(tree_guard);
    
    // 使用新的create_and_save_leaves_data函数来保存单个叶子节点数据
    if let Err(e) = create_and_save_leaves_data(1, 1, MERKLE_FILE) {
        println!("错误：无法保存证明数据");
        println!(" └── 详细信息: {}", e);
    } else {
        println!("7. merkle数据已成功保存到文件");
           
    }
}

/// 创建并保存Merkle树叶子节点数据（支持单个或多个叶子节点）
fn create_and_save_leaves_data(
    num_leaves: u64, 
    selected_count: u64, 
    output_file: &str
) -> Result<(), std::io::Error> {
    // 获取全局树的锁
    let mut tree_guard = get_global_merkle_tree().lock().unwrap();
    
    println!("1. 使用全局Poseidon Merkle树（高度为{})", TREE_HEIGHT);
    
    // 检查树是否为空，如果为空则初始化，否则添加新叶子节点
    if tree_guard.root().hash == BlsScalar::zero() {
        // 初始化全局树
        let start_time = Instant::now();
        initialize_merkle_tree(&mut tree_guard, num_leaves);
        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        println!("2. 全局Merkle树已初始化，包含{}个叶子节点，耗时: {:?}", num_leaves, duration);
    } else {
        // 添加新的叶子节点
        let start_time = Instant::now();
        let new_positions = add_new_leaves(&mut tree_guard, num_leaves);
        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        println!("2. 已向全局Merkle树添加{}个新叶子节点，耗时: {:?}", num_leaves, duration);
        println!("   新叶子节点位置: {:?}", new_positions);
    }
    
    // 获取树的根节点
    let root = tree_guard.root();
    println!("3. Merkle树根节点哈希值: {:?}", root.hash);
    
    // 生成所有可能的位置
    let positions: Vec<u64> = (0..num_leaves).collect();
    
    // 确定要生成证明的叶子节点位置
    let selected_positions: Vec<u64> = if num_leaves == 1 && selected_count == 1 {
        // 单个叶子节点情况
        vec![0]
    } else {
        // 多个叶子节点情况，随机选择
        let mut rng = StdRng::seed_from_u64(0xdea1);
        if selected_count < num_leaves {
            positions.choose_multiple(&mut rng, selected_count as usize).copied().collect()
        } else {
            positions.clone()
        }
    };
    
    // 为每个选定的叶子节点生成证明
    let start_time = Instant::now();
    let leaves_info: Vec<LeafInfo> = selected_positions
        .iter()
        .map(|&position| create_leaf_info(&tree_guard, position))
        .collect();
    let end_time = Instant::now();
    let duration = end_time.duration_since(start_time);
    println!("4. 已选择 {} 个叶子节点进行证明生成,耗时: {:?}", selected_positions.len(), duration);
    
    // 创建MultipleLeavesData实例
    let leaves_data = MultipleLeavesData {
        root_hash: root.hash.to_bytes(),
        leaves_info,
    };
    
    // 使用rkyv序列化并写入文件
    serialize_multiple_leaves_to_file(&leaves_data, output_file)?;
    
    println!("5. 叶子节点数据已成功保存到 '{}'", output_file);
    
    // 保存树状态到文件
    save_tree_state(&tree_guard)?;
    
    Ok(())
}

/// 验证叶子节点的证明（支持单个叶子节点或从文件验证所有叶子节点）
fn verify_leaves(
    file_path: Option<&str>, 
    position: Option<u64>,
    leaf_hash: Option<[u8; 32]>,
    root_hash: Option<[u8; 32]>,
    proof_bytes: Option<&[u8]>
) -> Result<bool, std::io::Error> {
    // 从文件验证所有叶子节点
    if let Some(path) = file_path {
        // 读取并反序列化数据
        let data = read_and_deserialize_multiple_leaves(path)?;
        
        println!("验证文件 '{}' 中的所有叶子节点证明:", path);
        println!("总共有 {} 个叶子节点需要验证", data.leaves_info.len());
        
        let mut all_valid = true;
        
        for (i, leaf_info) in data.leaves_info.iter().enumerate() {
            let is_valid = {
                // 从bytes还原opening
                match Opening::<(), { TREE_HEIGHT }>::from_slice(&leaf_info.proof_bytes) {
                    Ok(opening) => {
                        // 创建叶子节点
                        let leaf_scalar = BlsScalar::from_bytes(&leaf_info.leaf_hash);
                        if let Some(leaf_scalar) = leaf_scalar.into_option() {
                            let leaf = PoseidonItem::new(leaf_scalar, ());
                            
                            // 验证证明
                            let is_valid = opening.verify(leaf);
                            
                            // 直接返回验证结果，因为compute_root方法不存在
                            is_valid
                        } else {
                            false
                        }
                    },
                    Err(_) => false
                }
            };
            
            if is_valid {
                println!("叶子节点 {} (位置: {}) 验证通过", i+1, leaf_info.position);
            } else {
                println!("叶子节点 {} (位置: {}) 验证失败", i+1, leaf_info.position);
                all_valid = false;
            }
        }
        
        if all_valid {
            println!("所有叶子节点证明验证通过");
        } else {
            println!("存在验证失败的叶子节点证明");
        }
        
        Ok(all_valid)
    } else if let (Some(pos), Some(l_hash), Some(_r_hash), Some(p_bytes)) = 
                 (position, leaf_hash, root_hash, proof_bytes) {
        // 验证单个叶子节点的证明
        // 从bytes还原opening
        match Opening::<(), { TREE_HEIGHT }>::from_slice(p_bytes) {
            Ok(opening) => {
                // 创建叶子节点
                let leaf_scalar = BlsScalar::from_bytes(&l_hash);
                if let Some(leaf_scalar) = leaf_scalar.into_option() {
                    let leaf = PoseidonItem::new(leaf_scalar, ());
                    
                    // 验证证明
                    let is_valid = opening.verify(leaf);
                    
                    if is_valid {
                        // println!("位置 {} 的叶子节点验证通过", pos);
                    } else {
                        println!("位置 {} 的叶子节点验证失败", pos);
                    }
                    
                    Ok(is_valid)
                } else {
                    Ok(false)
                }
            },
            Err(_) => Ok(false)
        }
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "无效的验证参数"))
    }
}

// 打印使用说明
fn print_usage() {
    println!("用法:");
    println!("  cargo run -- [参数]");
    println!("参数:");
    println!("  only      - 生成一个叶子节点并序列化到文件");
    println!("  Some <n> <leaf_num>  - 生成n个叶子节点并为leaf_num个节点生成证明并序列化到文件");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let output_file = MERKLE_SOME_FILE;
    
    // 处理命令行参数
    if args.len() >= 2 {
        match args[1].as_str() {
            "only" => {
                println!("===== 生成单个叶子节点 ======");
                if let Err(err) = create_and_save_leaves_data(1, 1, output_file) {
                    eprintln!("创建单叶子节点数据失败: {}", err);
                }
            },
            "Some" | "--Some" => {
                if args.len() >= 4 {
                    match (args[2].parse::<u64>(), args[3].parse::<u64>()) {
                        (Ok(n), Ok(leaf_num)) => {
                            println!("===== 生成 {} 个叶子节点，并为 {} 个节点生成证明 ======", n, leaf_num);
                            if let Err(err) = create_and_save_leaves_data(n, leaf_num, output_file) {
                                eprintln!("创建叶子节点数据失败: {}", err);
                            }
                        },
                        _ => {
                            eprintln!("错误: 'Some' 参数后需要提供两个有效的数字: n(叶子总节点数) 和 leaf_num(生成证明的叶子节点数)");
                            print_usage();
                        }
                    }
                } else {
                    eprintln!("错误: 'Some' 参数需要指定n和leaf_num的值");
                    print_usage();
                }
            },
            _ => {
                eprintln!("错误: 无效的参数");
                print_usage();
            }
        }
    } else {
        // 默认行为：模拟链上环境并测试多叶子节点功能
        println!("===== 模拟链上Merkle树生成 =====");
        simulate_chain_environment(4);
        
        println!("\n===== 测试多叶子节点功能 =====");
        match create_and_save_leaves_data(8, 4, output_file) {
            Ok(_) => {
                println!("\n===== 验证多叶子节点数据 =====");
                if let Err(err) = verify_leaves(Some(output_file), None, None, None, None) {
                    eprintln!("验证失败: {}", err);
                }
            },
            Err(err) => eprintln!("创建多叶子节点数据失败: {}", err)
        }
    }
}