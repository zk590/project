// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

// Extracted from
// https://github.com/dusk-network/Poseidon252/blob/master/assets/HOWTO.md

use super::BlsScalar;
use sha2::{Digest, Sha512};

// the width of the hades permutation container
const WIDTH: usize = 5;
// the total amount of rounds (partial + full) within one hades permutation
const ROUNDS: usize = 59 + 8;
// the amount of constants needed for one hades permutation
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

    // Generate x and y values deterministically for the cauchy matrix
    // where x[i] != y[i] to allow the values to be inverted
    // and there are no duplicates in the x vector or y vector, so that the
    // determinant is always non-zero [a b]
    // [c d]
    // det(M) = (ad - bc) ; if a == b and c == d => det(M) =0
    // For an MDS matrix, every possible mxm submatrix, must have det(M) != 0
    (0..WIDTH).for_each(|i| {
        x_values[i] = BlsScalar::from(i as u64);
        y_values[i] = BlsScalar::from((i + WIDTH) as u64);
    });

    let mut row_index = 0;
    (0..WIDTH).for_each(|i| {
        (0..WIDTH).for_each(|j| {
            matrix[row_index][j] = (x_values[i] + y_values[j]).invert().unwrap();
        });
        row_index += 1;
    });

    matrix
}
