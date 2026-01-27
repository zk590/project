use sp1_sdk::{include_elf, HashableKey, ProverClient};

/// 用于Succinct RISC-V零知识虚拟机的ELF文件
pub const POSEIDON_MERKLE_ELF: &[u8] = include_elf!("coset-program");

fn main() {
    let prover = ProverClient::from_env();
    let (_, vk) = prover.setup(POSEIDON_MERKLE_ELF);
    println!("{}", vk.bytes32());
}