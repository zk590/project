
#![no_main]
zkm_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use coset_bls12_381::BlsScalar;
use merkle_lib::PublicValuesStruct;
use poseidon_merkle::{Item, Opening};
use zkm_zkvm::io::{read, commit_slice};

const TREE_HEIGHT: usize = 22;

pub fn main() {
    // 从stdin读取数据
    // 读取叶子节点数量
    let num_leaves = read::<u64>();

    // 读取根节点哈希
    let root_hash_bytes = read::<[u8; 32]>();
    let root_hash = BlsScalar::from_bytes(&root_hash_bytes).unwrap();

    // 开始验证叶子节点的Merkle证明

    // 存储所有验证结果
    let mut all_valid = true;
    let mut results = Vec::with_capacity(num_leaves as usize);

    for i in 0..num_leaves {
        // 处理叶子节点

        // 读取位置
        let position = read::<u64>();

        // 读取叶子节点哈希
        let leaf_hash_bytes = read::<[u8; 32]>();
        let leaf_hash = BlsScalar::from_bytes(&leaf_hash_bytes).unwrap();

        // 读取证明数据长度
        let proof_len = read::<u32>();

        // 读取证明数据
        let proof_bytes = (0..proof_len)
            .map(|_| read::<u8>())
            .collect::<Vec<u8>>();

        // 使用Opening::from_slice反序列化证明
        const T_SIZE: usize = 32; // BlsScalar的大小是32字节
        let opening: Opening<(), { TREE_HEIGHT }> = Opening::from_slice::<T_SIZE>(&proof_bytes).unwrap();

        // 验证证明中的根哈希是否与加载的根哈希一致
        if opening.root().hash != root_hash {
            panic!("根哈希一致性检查失败！证明中的根哈希与加载的根哈希不一致");
        }

        // 创建叶子节点
        let leaf = Item {
            hash: leaf_hash,
            data: (),
        };

        // 验证叶子节点是否在Merkle树中
        let is_valid = opening.verify(leaf);

        // 记录结果
        results.push(is_valid);
        all_valid &= is_valid;

        println!("  验证结果: {}", is_valid);
        println!("  叶子节点位置: {}", position);
        println!("  叶子节点哈希: {:?}", leaf_hash);
    }

    println!("\n所有叶子节点验证完成！");
    println!("整体验证结果: {}", all_valid);
    println!("详细结果: {:?}", results);

    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { all_valid });
    commit_slice(&bytes);
}