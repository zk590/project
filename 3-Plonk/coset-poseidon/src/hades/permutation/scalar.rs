//

use coset_bls12_381::BlsScalar;
use coset_safe::Safe;

use super::Hades;
use crate::hades::{MDS_MATRIX, ROUND_CONSTANTS, WIDTH};

#[derive(Default)]
pub(crate) struct ScalarPermutation();

impl ScalarPermutation {
    /// 创建标量域下的 Hades 置换实例。
    pub fn new() -> Self {
        Self()
    }
}

impl Safe<BlsScalar, WIDTH> for ScalarPermutation {
    fn permute(&mut self, state: &mut [BlsScalar; WIDTH]) {
        self.apply_permutation(state);
    }

    fn tag(&mut self, input: &[u8]) -> BlsScalar {
        BlsScalar::hash_to_scalar(input.as_ref())
    }

    fn add(&mut self, right: &BlsScalar, left: &BlsScalar) -> BlsScalar {
        right + left
    }
}

impl Hades<BlsScalar> for ScalarPermutation {
    fn add_round_constants(
        &mut self,
        round_index: usize,
        state: &mut [BlsScalar; WIDTH],
    ) {
        state
            .iter_mut()
            .enumerate()
            .for_each(|(state_index, state_value)| {
                *state_value += ROUND_CONSTANTS[round_index][state_index]
            });
    }

    fn quintic_s_box(&mut self, value: &mut BlsScalar) {
        *value = value.square().square() * *value;
    }

    fn apply_mds_matrix(
        &mut self,
        _round_index: usize,
        state: &mut [BlsScalar; WIDTH],
    ) {
        let mut mixed_state = [BlsScalar::zero(); WIDTH];

        for (column_index, state_value) in state.iter().enumerate() {
            for row_index in 0..WIDTH {
                mixed_state[row_index] +=
                    MDS_MATRIX[row_index][column_index] * state_value;
            }
        }

        state.copy_from_slice(&mixed_state);
    }
}

#[cfg(feature = "encryption")]
impl coset_safe::Encryption<BlsScalar, WIDTH> for ScalarPermutation {
    fn subtract(
        &mut self,
        minuend: &BlsScalar,
        subtrahend: &BlsScalar,
    ) -> BlsScalar {
        minuend - subtrahend
    }

    fn is_equal(&mut self, lhs: &BlsScalar, rhs: &BlsScalar) -> bool {
        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hades_det() {
        let mut x = [BlsScalar::from(17u64); WIDTH];
        let mut y = [BlsScalar::from(17u64); WIDTH];
        let mut z = [BlsScalar::from(19u64); WIDTH];

        ScalarPermutation::new().permute(&mut x);
        ScalarPermutation::new().permute(&mut y);
        ScalarPermutation::new().permute(&mut z);

        assert_eq!(x, y);
        assert_ne!(x, z);
    }
}
