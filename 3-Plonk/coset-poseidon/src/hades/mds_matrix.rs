// 模块说明：加载 Poseidon 置换使用的 MDS 矩阵常量。

use coset_bls12_381::BlsScalar;

use crate::hades::WIDTH;

/// Poseidon 置换使用的 MDS 矩阵常量（从二进制资源加载）。
pub const MDS_MATRIX: [[BlsScalar; WIDTH]; WIDTH] = {
    let bytes = include_bytes!("../../assets/mds.bin");
    let mut matrix = [[BlsScalar::zero(); WIDTH]; WIDTH];
    let mut byte_offset = 0;
    let mut row_index = 0;

    while row_index < WIDTH {
        let mut column_index = 0;
        while column_index < WIDTH {
            let limb_0 = super::read_u64_le_from_bytes(bytes, byte_offset);
            let limb_1 = super::read_u64_le_from_bytes(bytes, byte_offset + 8);
            let limb_2 = super::read_u64_le_from_bytes(bytes, byte_offset + 16);
            let limb_3 = super::read_u64_le_from_bytes(bytes, byte_offset + 24);
            byte_offset += 32;

            matrix[row_index][column_index] =
                BlsScalar::from_raw([limb_0, limb_1, limb_2, limb_3]);
            column_index += 1;
        }
        row_index += 1;
    }

    matrix
};
