//! Fr 的编码/解码与辅助实现（字节转换、排序与索引支持）。

use core::cmp::{Ord, Ordering, PartialOrd};
use core::convert::TryInto;
use core::ops::{Index, IndexMut};

use coset_bls12_381::BlsScalar;
use coset_bytes::{Error as BytesError, Serializable};

use super::{Fr, MODULUS, R2};
use crate::util::sbb;

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for Fr {}

impl Fr {
    /// ```
    pub fn hash_to_scalar(input: &[u8]) -> Self {
        let state = blake2b_simd::Params::new()
            .hash_length(64)
            .to_state()
            .update(input)
            .finalize();

        let bytes = state.as_bytes();

        Self::reduce_u512_words([
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[48..56]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[56..64]).unwrap()),
        ])
    }

    #[inline]
    pub fn divn(&mut self, mut n: u32) {
        if n >= 256 {
            *self = Self::from(0u64);
            return;
        }

        while n >= 64 {
            let mut carry_word = 0;
            for limb in self.0.iter_mut().rev() {
                core::mem::swap(&mut carry_word, limb);
            }
            n -= 64;
        }

        if n > 0 {
            let mut carry_bits = 0;
            for limb in self.0.iter_mut().rev() {
                let shifted_bits = *limb << (64 - n);
                *limb >>= n;
                *limb |= carry_bits;
                carry_bits = shifted_bits;
            }
        }
    }

    pub fn reduce(&self) -> Self {
        Fr::montgomery_reduce(
            self.0[0], self.0[1], self.0[2], self.0[3], 0u64, 0u64, 0u64, 0u64,
        )
    }

    pub fn is_even(&self) -> bool {
        self.0[0] % 2 == 0
    }

    pub fn mod_2_pow_k(&self, k: u8) -> u8 {
        (self.0[0] & ((1 << k) - 1)) as u8
    }

    pub fn mods_2_pow_k(&self, w: u8) -> i8 {
        assert!(w < 32u8);
        let modulus = self.mod_2_pow_k(w) as i8;
        let two_pow_w_minus_one = 1i8 << (w - 1);

        match modulus >= two_pow_w_minus_one {
            false => modulus,
            true => modulus - ((1u8 << w) as i8),
        }
    }

    pub fn compute_windowed_naf(&self, width: u8) -> [i8; 256] {
        let mut reduced_scalar = self.reduce();
        let mut naf_index = 0;
        let one = Fr::one().reduce();
        let mut naf_digits = [0i8; 256];

        while reduced_scalar >= one {
            if !reduced_scalar.is_even() {
                let naf_digit = reduced_scalar.mods_2_pow_k(width);
                naf_digits[naf_index] = naf_digit;
                reduced_scalar -= Fr::from(naf_digit);
            } else {
                naf_digits[naf_index] = 0i8;
            };

            reduced_scalar.divn(1u32);
            naf_index += 1;
        }
        naf_digits
    }
}

impl From<i8> for Fr {
    fn from(val: i8) -> Fr {
        match (val >= 0, val < 0) {
            (true, false) => Fr([val.unsigned_abs() as u64, 0u64, 0u64, 0u64]),
            (false, true) => -Fr([val.unsigned_abs() as u64, 0u64, 0u64, 0u64]),
            (_, _) => unreachable!(),
        }
    }
}

impl From<Fr> for BlsScalar {
    fn from(scalar: Fr) -> BlsScalar {
        let bls_scalar =
            <BlsScalar as Serializable<32>>::from_bytes(&scalar.to_bytes());

        assert!(
            bls_scalar.is_ok(),
            "Failed to convert a Scalar from JubJub to BLS"
        );

        bls_scalar.unwrap()
    }
}

impl Index<usize> for Fr {
    type Output = u64;
    fn index(&self, _index: usize) -> &u64 {
        &(self.0[_index])
    }
}

impl IndexMut<usize> for Fr {
    fn index_mut(&mut self, _index: usize) -> &mut u64 {
        &mut (self.0[_index])
    }
}

impl PartialOrd for Fr {
    fn partial_cmp(&self, other: &Fr) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Fr {
    fn cmp(&self, other: &Self) -> Ordering {
        let this_scalar = self;
        for i in (0..4).rev() {
            #[allow(clippy::comparison_chain)]
            if this_scalar[i] > other[i] {
                return Ordering::Greater;
            } else if this_scalar[i] < other[i] {
                return Ordering::Less;
            }
        }
        Ordering::Equal
    }
}

impl Serializable<32> for Fr {
    type Error = BytesError;

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut scalar = Fr([0, 0, 0, 0]);

        scalar.0[0] = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        scalar.0[1] = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        scalar.0[2] = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        scalar.0[3] = u64::from_le_bytes(bytes[24..32].try_into().unwrap());

        let (_, borrow) = sbb(scalar.0[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb(scalar.0[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb(scalar.0[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb(scalar.0[3], MODULUS.0[3], borrow);

        let is_some = (borrow as u8) & 1;

        if is_some == 0 {
            return Err(BytesError::InvalidData);
        }

        scalar *= &R2;

        Ok(scalar)
    }

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let canonical_scalar = Fr::montgomery_reduce(
            self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0,
        );

        let mut encoded_bytes = [0; Self::SIZE];
        encoded_bytes[0..8]
            .copy_from_slice(&canonical_scalar.0[0].to_le_bytes());
        encoded_bytes[8..16]
            .copy_from_slice(&canonical_scalar.0[1].to_le_bytes());
        encoded_bytes[16..24]
            .copy_from_slice(&canonical_scalar.0[2].to_le_bytes());
        encoded_bytes[24..32]
            .copy_from_slice(&canonical_scalar.0[3].to_le_bytes());

        encoded_bytes
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    extern crate alloc;

    use alloc::string::{String, ToString};

    use coset_bytes::Serializable;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::Fr;

    impl Serialize for Fr {
        fn serialize<S: Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let hex_encoded = hex::encode(self.to_bytes());
            serializer.serialize_str(&hex_encoded)
        }
    }

    impl<'de> Deserialize<'de> for Fr {
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            let serialized_hex = String::deserialize(deserializer)?;
            let decoded = hex::decode(serialized_hex).map_err(Error::custom)?;
            let decoded_len = decoded.len();
            let bytes: [u8; Self::SIZE] = decoded.try_into().map_err(|_| {
                Error::invalid_length(
                    decoded_len,
                    &Self::SIZE.to_string().as_str(),
                )
            })?;
            Fr::from_bytes(&bytes)
                .into_option()
                .ok_or(Error::custom("Failed to deserialize Fr: invalid Fr"))
        }
    }
}

#[test]
fn w_naf_3() {
    let scalar = Fr::from(1122334455u64);
    let window_width = 3;
    // -1 - 1*2^3 - 1*2^8 - 1*2^11 + 3*2^15 + 1*2^18 - 1*2^21 + 3*2^24 +
    // 1*2^30
    let expected_result = [
        -1i8, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0, -1, 0, 0, 0, 3, 0, 0, 1, 0, 0,
        -1, 0, 0, 3, 0, 0, 0, 0, 0, 1,
    ];

    let mut expected = [0i8; 256];
    expected[..expected_result.len()].copy_from_slice(&expected_result);

    let computed = scalar.compute_windowed_naf(window_width);

    assert_eq!(expected, computed);
}

#[test]
fn w_naf_4() {
    let scalar = Fr::from(58235u64);
    let window_width = 4;
    // -5 + 7*2^7 + 7*2^13
    let expected_result = [-5, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 7];

    let mut expected = [0i8; 256];
    expected[..expected_result.len()].copy_from_slice(&expected_result);

    let computed = scalar.compute_windowed_naf(window_width);

    assert_eq!(expected, computed);
}

#[test]
fn w_naf_2() {
    let scalar = -Fr::one();
    let window_width = 2;
    let two = Fr::from(2u64);

    let wnaf = scalar.compute_windowed_naf(window_width);

    let recomputed = wnaf.iter().enumerate().fold(Fr::zero(), |acc, (i, x)| {
        if *x > 0 {
            acc + Fr::from(*x as u64) * two.pow(&[(i as u64), 0u64, 0u64, 0u64])
        } else if *x < 0 {
            acc - Fr::from(-(*x) as u64)
                * two.pow(&[(i as u64), 0u64, 0u64, 0u64])
        } else {
            acc
        }
    });
    assert_eq!(scalar, recomputed);
}

#[cfg(all(test, feature = "alloc"))]
mod fuzz {
    use alloc::vec::Vec;

    use crate::fr::{Fr, MODULUS};
    use crate::util::sbb;

    fn is_scalar_in_range(scalar: &Fr) -> bool {
        let borrow = scalar
            .0
            .iter()
            .zip(MODULUS.0.iter())
            .fold(0, |borrow, (&s, &m)| sbb(s, m, borrow).1);

        borrow == u64::MAX
    }

    quickcheck::quickcheck! {
        fn prop_hash_to_scalar(bytes: Vec<u8>) -> bool {
            let scalar = Fr::hash_to_scalar(&bytes);

            is_scalar_in_range(&scalar)
        }
    }
}

#[cfg(feature = "zeroize")]
#[test]
fn test_zeroize() {
    use zeroize::Zeroize;

    let mut scalar = Fr::one();
    scalar.zeroize();
    assert_eq!(scalar, Fr::zero());
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use std::boxed::Box;

    use ff::Field;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;
    use crate::coset::test_utils;

    #[test]
    fn serde_fr() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = StdRng::seed_from_u64(0xdead);
        let fr = Fr::random(&mut rng);
        let ser = test_utils::assert_canonical_json(
            &fr,
            "\"052385ff7468e23e6cc710b15579e0e7a7181b6cccc658a04d5c85682ee0f405\""
        )?;
        let deser = serde_json::from_str(&ser).unwrap();
        assert_eq!(fr, deser);

        Ok(())
    }

    #[test]
    fn serde_fr_wrong_encoded() {
        let wrong_encoded = "\"wrong-encoded\"";
        let fr: Result<Fr, _> = serde_json::from_str(&wrong_encoded);
        assert!(fr.is_err());
    }

    #[test]
    fn serde_fr_too_long() {
        let length_33_enc = "\"e4ab9de40283a85d6ea0cd0120500697d8b01c71b7b4b520292252d20937000631\"";
        let fr: Result<Fr, _> = serde_json::from_str(&length_33_enc);
        assert!(fr.is_err());
    }

    #[test]
    fn serde_fr_too_short() {
        let length_31_enc =
            "\"1751c37a1dca7aa4c048fcc6177194243edc3637bae042e167e4285945e046\"";
        let fr: Result<Fr, _> = serde_json::from_str(&length_31_enc);
        assert!(fr.is_err());
    }
}
