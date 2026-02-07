//! 一个简单的程序，用于聚合多个使用zkVM证明的程序的证明。

#![no_main]
zkm_zkvm::entrypoint!(main); // 使用zkm_zkVM的入口点

use sha2::{Digest, Sha256}; // 导入SHA-256哈希函数

/// 将8个32位无符号整数转换为32字节的小端字节数组
pub fn words_to_bytes_le(words: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let word_bytes = words[i].to_le_bytes(); // 将每个单词转换为小端字节
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&word_bytes); // 复制到结果数组中
    }
    bytes
}

/// 将验证密钥和提交值编码为单个字节数组
///
/// 格式：(words_to_bytes_le(vkey) || (committed_value.len() as u32).to_be_bytes() || committed_value)
pub fn commit_proof_pair(vkey: &[u32; 8], committed_value: &Vec<u8>) -> Vec<u8> {
    let mut res = Vec::new();
    res.extend_from_slice(&words_to_bytes_le(vkey)); // 添加验证密钥的字节表示
    // 注意：我们使用大端字节序，因为Solidity中的abi.encodePacked也使用大端
    res.extend_from_slice(&(committed_value.len() as u32).to_be_bytes()); // 添加提交值的长度
    res.extend_from_slice(committed_value); // 添加提交值本身
    res
}

/// 计算默克尔树中叶子节点的哈希值
///
/// 默克尔树中的叶子节点是验证密钥和提交值的组合。
/// 叶子节点使用`commit_proof_pair`编码为字节数组，然后使用SHA-256哈希。
pub fn compute_leaf_hash(vkey: &[u32; 8], committed_value: &Vec<u8>) -> [u8; 32] {
    // 将叶子节点编码为字节数组
    let leaf = commit_proof_pair(vkey, committed_value);
    let digest = Sha256::digest(&leaf); // 计算SHA-256哈希
    let mut res = [0u8; 32];
    res.copy_from_slice(&digest); // 复制哈希结果
    res
}

/// 对已经哈希过的两个叶子节点计算哈希
///
/// 哈希计算为sha256(left || right)。
pub fn hash_pair(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left); // 添加左哈希
    hasher.update(right); // 添加右哈希
    let digest = hasher.finalize(); // 完成哈希计算
    let mut res = [0u8; 32];
    res.copy_from_slice(&digest); // 复制哈希结果
    res
}

/// 给定叶子节点，计算默克尔树的根节点哈希值
///
/// 叶子节点使用`compute_leaf_hash`进行哈希，然后将这些哈希值组合起来形成根节点。
/// 通过对哈希对进行哈希运算，直到只剩下一个哈希值，计算出根节点。
pub fn compute_merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32]; // 如果没有叶子节点，返回零哈希
    }

    // 当叶子节点数量大于1时，继续合并
    while leaves.len() > 1 {
        let mut next = Vec::new();
        for i in (0..leaves.len()).step_by(2) { // 每次处理两个相邻的叶子节点
            let left = &leaves[i];
            // 如果当前叶子节点是奇数位置的最后一个节点，则复制自身作为右节点
            let right = if i + 1 < leaves.len() { &leaves[i + 1] } else { &leaves[i] };
            next.push(hash_pair(left, right)); // 计算这对叶子节点的哈希值
        }
        leaves = next; // 更新叶子节点列表为新的哈希值列表
    }
    leaves[0] // 返回根节点哈希值
}

/// 主函数：聚合多个zkVM证明并计算默克尔树的根节点
pub fn main() {
    // 读取验证密钥
    let vkeys = zkm_zkvm::io::read::<Vec<[u32; 8]>>();

    // 读取公共值
    let public_values = zkm_zkvm::io::read::<Vec<Vec<u8>>>();

    // 验证证明
    assert_eq!(vkeys.len(), public_values.len()); // 确保验证密钥和公共值数量匹配
    for i in 0..vkeys.len() {
        let vkey = &vkeys[i];
        let public_values = &public_values[i];
        let public_values_digest = Sha256::digest(public_values); // 计算公共值的哈希
        // 使用zkm_zkVM验证库验证证明
        zkm_zkvm::lib::verify::verify_zkm_proof(vkey, &public_values_digest.into());
    }

    // 将（验证密钥，公共值）对转换为默克尔树的叶子节点
    let leaves: Vec<[u8; 32]> = vkeys
        .iter()
        .zip(public_values.iter())
        .map(|(vkey, public_value)| compute_leaf_hash(vkey, public_value)) // 计算每个叶子节点的哈希
        .collect();

    // 自底向上遍历默克尔树，计算根节点哈希值
    let merkle_root = compute_merkle_root(leaves);

    // 提交根节点哈希值
    zkm_zkvm::io::commit_slice(&merkle_root);
}