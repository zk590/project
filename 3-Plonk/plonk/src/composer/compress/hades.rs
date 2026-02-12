use super::BlsScalar;
use sha2::{Digest, Sha512};

const WIDTH: usize = 5;

const ROUNDS: usize = 59 + 8;

const CONSTANTS: usize = ROUNDS * WIDTH;

/// 生成 Hades/Poseidon 轮常量表。
/// 该实现通过 `Sha512` 链式哈希扩展常量，并映射到标量域。
/// 常量表用于压缩模块的 Hades 优化路径，确保固定参数可重建。
pub fn constants() -> [BlsScalar; CONSTANTS] {
    let mut round_constants = [BlsScalar::zero(); CONSTANTS];
    let mut previous_round_constant = BlsScalar::one();
    let mut hash_state = b"poseidon-for-plonk".to_vec();

    round_constants.iter_mut().for_each(|constant_slot| {
        hash_state = Sha512::digest(hash_state.as_slice()).to_vec();

        let mut wide_hash_bytes = [0x00u8; 64];
        wide_hash_bytes.copy_from_slice(&hash_state[0..64]);

        *constant_slot = BlsScalar::from_bytes_wide(&wide_hash_bytes)
            + previous_round_constant;
        previous_round_constant = *constant_slot;
    });

    round_constants
}

/// 生成 Hades 使用的 MDS 矩阵。
/// 矩阵元素按 `1 / (x_i + y_j)` 规则构造，保证良好的扩散性质。
/// 该函数输出固定大小方阵，供优化压缩阶段复用。
pub fn mds() -> [[BlsScalar; WIDTH]; WIDTH] {
    let mut mds_matrix = [[BlsScalar::zero(); WIDTH]; WIDTH];
    let mut x_values = [BlsScalar::zero(); WIDTH];
    let mut y_values = [BlsScalar::zero(); WIDTH];

    (0..WIDTH).for_each(|column_index| {
        x_values[column_index] = BlsScalar::from(column_index as u64);
        y_values[column_index] = BlsScalar::from((column_index + WIDTH) as u64);
    });

    x_values
        .iter()
        .enumerate()
        .for_each(|(row_index, x_coordinate)| {
            y_values.iter().enumerate().for_each(
                |(column_index, y_coordinate)| {
                    mds_matrix[row_index][column_index] =
                        (*x_coordinate + *y_coordinate).invert().unwrap();
                },
            );
        });

    mds_matrix
}
