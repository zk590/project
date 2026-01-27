// 这两行是程序正确编译所必需的
#![no_main]
sp1_zkvm::entrypoint!(main);

use coset_lib::{PublicValuesStruct};
use alloy_sol_types::SolType;
use alloy_primitives::FixedBytes;
use coset_bls12_381::BlsScalar;
use plonk::prelude::*;
use coset_bytes::Serializable;

pub fn main() {
    // 从证明者读取输入数据 - 这里会读取一个32字节的公共输入（根哈希）
    let root_hash = sp1_zkvm::io::read::<[u8; 32]>();
    let proof_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let verifier_bytes = sp1_zkvm::io::read::<Vec<u8>>();

    // 从字节数组恢复Verifier
    let verifier = Verifier::try_from_bytes(&verifier_bytes).unwrap();
    
    // 确保proof_bytes的长度是Proof::SIZE的值
    println!("Proof::SIZE = {}", Proof::SIZE);
    println!("proof_bytes.len() = {}", proof_bytes.len());
    if proof_bytes.len() != Proof::SIZE {
        sp1_zkvm::io::commit_slice(b"false_length");
        return;
    }
    
    // 转换为固定大小的数组
    let mut proof_fixed_bytes = [0u8; Proof::SIZE];
    proof_fixed_bytes.copy_from_slice(&proof_bytes[..Proof::SIZE]);
    
    // 从字节数组恢复Proof
    let proof = Proof::from_bytes(&proof_fixed_bytes).unwrap();
    
    // Create public inputs from the read data
    let mut public_inputs = Vec::new();
    
    // Parse root hash
    let root_scalar_result = BlsScalar::from_bytes(&root_hash);
    if let Some(root_scalar) = root_scalar_result.into_option() {
        public_inputs.push(root_scalar);
        println!("成功解析根哈希: {:?}", root_scalar);
    } else {
        println!("根哈希不是有效的BlsScalar，使用默认值");
        public_inputs.push(BlsScalar::zero());
    }
    
    // // 打印proof和public_inputs的值
    // println!("Program - Proof: {:?}", proof);
    // println!("Program - Public Inputs: {:?}", public_inputs);
    // Use only leaf_hash as public inputs (FixedBytes requires 32 bytes)
    
    // Encode the public values of the program.
    let public_inputs_fixed = FixedBytes::from_slice(&root_hash);
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct {
        public_inputs: public_inputs_fixed,
        proof: proof_bytes,
    });

    // 验证proof并处理可能的错误
    if let Err(_) = verifier.verify(&proof, &public_inputs) {
        println!("Verification failed");
        sp1_zkvm::io::commit_slice(b"false_verify");
    } else {
        println!("Verification passed");
        sp1_zkvm::io::commit_slice(&bytes);
    }
}