


//




//!




use coset_bls12_381::BlsScalar;

use crate::hades::{FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH};

const ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;



///

///

pub const ROUND_CONSTANTS: [[BlsScalar; WIDTH]; ROUNDS] = {
    let bytes = include_bytes!("../../assets/arc.bin");



    if bytes.len() < WIDTH * ROUNDS * 32 {
        panic!("There are not enough round constants stored in 'assets/arc.bin', have a look at the HOWTO to generate enough constants.");
    }

    let mut cnst = [[BlsScalar::zero(); WIDTH]; ROUNDS];

    let mut i = 0;
    let mut j = 0;
    while i < WIDTH * ROUNDS * 32 {
        let a = super::u64_from_buffer(bytes, i);
        let b = super::u64_from_buffer(bytes, i + 8);
        let c = super::u64_from_buffer(bytes, i + 16);
        let d = super::u64_from_buffer(bytes, i + 24);

        cnst[j / WIDTH][j % WIDTH] = BlsScalar::from_raw([a, b, c, d]);
        j += 1;

        i += 32;
    }

    cnst
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
