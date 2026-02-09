// 模块说明：本文件实现 PLONK 组件（src/composer/compress/hades.rs）。

//

use super::BlsScalar;
use sha2::{Digest, Sha512};

const WIDTH: usize = 5;

const ROUNDS: usize = 59 + 8;

const CONSTANTS: usize = ROUNDS * WIDTH;

pub fn constants() -> [BlsScalar; CONSTANTS] {
    let mut round_constants = [BlsScalar::zero(); CONSTANTS];
    let mut previous_constant = BlsScalar::one();
    let mut bytes = b"poseidon-for-plonk".to_vec();

    round_constants.iter_mut().for_each(|constant_slot| {
        bytes = Sha512::digest(bytes.as_slice()).to_vec();

        let mut wide_bytes = [0x00u8; 64];
        wide_bytes.copy_from_slice(&bytes[0..64]);

        *constant_slot =
            BlsScalar::from_bytes_wide(&wide_bytes) + previous_constant;
        previous_constant = *constant_slot;
    });

    round_constants
}

pub fn mds() -> [[BlsScalar; WIDTH]; WIDTH] {
    let mut matrix = [[BlsScalar::zero(); WIDTH]; WIDTH];
    let mut x_values = [BlsScalar::zero(); WIDTH];
    let mut y_values = [BlsScalar::zero(); WIDTH];

    (0..WIDTH).for_each(|i| {
        x_values[i] = BlsScalar::from(i as u64);
        y_values[i] = BlsScalar::from((i + WIDTH) as u64);
    });

    let mut row_index = 0;
    (0..WIDTH).for_each(|i| {
        (0..WIDTH).for_each(|j| {
            matrix[row_index][j] =
                (x_values[i] + y_values[j]).invert().unwrap();
        });
        row_index += 1;
    });

    matrix
}
