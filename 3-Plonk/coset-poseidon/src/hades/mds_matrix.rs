//

use coset_bls12_381::BlsScalar;

use crate::hades::WIDTH;

/// Poseidon 置换使用的 MDS 矩阵常量（从二进制资源加载）。
pub const MDS_MATRIX: [[BlsScalar; WIDTH]; WIDTH] = {
    let bytes = include_bytes!("../../assets/mds.bin");
    let mut mds = [[BlsScalar::zero(); WIDTH]; WIDTH];
    let mut k = 0;
    let mut i = 0;

    while i < WIDTH {
        let mut j = 0;
        while j < WIDTH {
            let a = super::read_u64_le_from_bytes(bytes, k);
            let b = super::read_u64_le_from_bytes(bytes, k + 8);
            let c = super::read_u64_le_from_bytes(bytes, k + 16);
            let d = super::read_u64_le_from_bytes(bytes, k + 24);
            k += 32;

            mds[i][j] = BlsScalar::from_raw([a, b, c, d]);
            j += 1;
        }
        i += 1;
    }

    mds
};
