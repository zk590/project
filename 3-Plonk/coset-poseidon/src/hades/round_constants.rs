// 模块说明：本文件实现 Poseidon 组件（src/hades/round_constants.rs）。

use coset_bls12_381::BlsScalar;

use crate::hades::{FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH};

const ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

pub const ROUND_CONSTANTS: [[BlsScalar; WIDTH]; ROUNDS] = {
    let bytes = include_bytes!("../../assets/arc.bin");

    if bytes.len() < WIDTH * ROUNDS * 32 {
        panic!("There are not enough round constants stored in 'assets/arc.bin', have a look at the HOWTO to generate enough constants.");
    }

    let mut constants = [[BlsScalar::zero(); WIDTH]; ROUNDS];

    let mut byte_offset = 0;
    let mut constant_index = 0;
    while byte_offset < WIDTH * ROUNDS * 32 {
        let limb_0 = super::read_u64_le_from_bytes(bytes, byte_offset);
        let limb_1 = super::read_u64_le_from_bytes(bytes, byte_offset + 8);
        let limb_2 = super::read_u64_le_from_bytes(bytes, byte_offset + 16);
        let limb_3 = super::read_u64_le_from_bytes(bytes, byte_offset + 24);

        constants[constant_index / WIDTH][constant_index % WIDTH] =
            BlsScalar::from_raw([limb_0, limb_1, limb_2, limb_3]);
        constant_index += 1;

        byte_offset += 32;
    }

    constants
};

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_round_constants() {
        let zero = BlsScalar::zero();
        let has_zero = ROUND_CONSTANTS.iter().flatten().any(|&x| x == zero);
        for ctant in ROUND_CONSTANTS.iter().flatten() {
            let bytes = ctant.to_bytes();
            assert!(&BlsScalar::from_bytes(&bytes).unwrap() == ctant);
        }
        assert!(!has_zero);
    }
}
