//! JubJub 曲线点（仿射/扩展坐标）与相关运算实现。

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "serde")]
mod serde_support;

use core::ops::Mul;
use ff::Field;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

pub use coset_bls12_381::BlsScalar;
use coset_bytes::{Error as BytesError, Serializable};

use crate::{Fq, Fr, JubJubAffine, JubJubExtended, EDWARDS_D};

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for JubJubAffine {}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for JubJubExtended {}

/// 基于 JubJub 的 Diffie-Hellman：`secret * public`。
pub fn dhke(secret: &Fr, public: &JubJubExtended) -> JubJubAffine {
    public.mul(secret).into()
}

pub const GENERATOR: JubJubAffine = JubJubAffine {
    u: BlsScalar::from_raw([
        0x4df7b7ffec7beaca,
        0x2e3ebb21fd6c54ed,
        0xf1fbf02d0fd6cce6,
        0x3fd2814c43ac65a6,
    ]),
    v: BlsScalar::from_raw([
        0x0000000000000012,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ]),
};

pub const GENERATOR_EXTENDED: JubJubExtended = JubJubExtended {
    u: GENERATOR.u,
    v: GENERATOR.v,
    z: BlsScalar::one(),
    t1: GENERATOR.u,
    t2: GENERATOR.v,
};

pub const GENERATOR_NUMS: JubJubAffine = JubJubAffine {
    u: BlsScalar::from_raw([
        0x921710179df76377,
        0x931e316a39fe4541,
        0xbd9514c773fd4456,
        0x5e67b8f316f414f7,
    ]),
    v: BlsScalar::from_raw([
        0x6705b707162e3ef8,
        0x9949ba0f82a5507a,
        0x7b162dbeeb3b34fd,
        0x43d80eb3b2f3eb1b,
    ]),
};

pub const GENERATOR_NUMS_EXTENDED: JubJubExtended = JubJubExtended {
    u: GENERATOR_NUMS.u,
    v: GENERATOR_NUMS.v,
    z: BlsScalar::one(),
    t1: GENERATOR_NUMS.u,
    t2: GENERATOR_NUMS.v,
};

impl Serializable<32> for JubJubAffine {
    type Error = BytesError;

    /// 从压缩字节恢复仿射点，并进行曲线合法性检查。
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut encoded_bytes = *bytes;

        let sign = encoded_bytes[31] >> 7;

        encoded_bytes[31] &= 0b0111_1111;

        let v = <BlsScalar as Serializable<32>>::from_bytes(&encoded_bytes)?;

        let v2 = v.square();

        Option::from(
            ((v2 - BlsScalar::one())
                * ((BlsScalar::one() + EDWARDS_D * v2)
                    .invert()
                    .unwrap_or(BlsScalar::zero())))
            .sqrt()
            .and_then(|u| {
                let flip_sign = Choice::from((u.to_bytes()[0] ^ sign) & 1);
                let u = BlsScalar::conditional_select(&u, &-u, flip_sign);

                let u_is_zero = u.ct_eq(&BlsScalar::zero());
                CtOption::new(JubJubAffine { u, v }, !(u_is_zero & flip_sign))
            }),
        )
        .ok_or(BytesError::InvalidData)
    }

    /// 将仿射点压缩为 32 字节（最高位携带 u 的符号位）。
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut encoded_bytes = self.v.to_bytes();
        let u_bytes = self.u.to_bytes();

        encoded_bytes[31] |= u_bytes[0] << 7;

        encoded_bytes
    }
}

impl JubJubAffine {
    /// 检查该仿射点是否满足 JubJub 曲线方程。
    pub fn is_on_curve(&self) -> Choice {
        let u2 = self.u.square();
        let v2 = self.v.square();
        (v2 - u2 - EDWARDS_D * u2 * v2).ct_eq(&Fq::one())
    }
}

impl JubJubExtended {
    /// 将仿射点嵌入扩展坐标表示。
    pub const fn from_affine(affine: JubJubAffine) -> Self {
        Self::from_raw_unchecked(
            affine.u,
            affine.v,
            BlsScalar::one(),
            affine.u,
            affine.v,
        )
    }

    /// 直接由原始坐标构造扩展点，不执行合法性检查。
    pub const fn from_raw_unchecked(
        u: BlsScalar,
        v: BlsScalar,
        z: BlsScalar,
        t1: BlsScalar,
        t2: BlsScalar,
    ) -> Self {
        Self { u, v, z, t1, t2 }
    }

    pub const fn get_u(&self) -> BlsScalar {
        self.u
    }

    pub const fn get_v(&self) -> BlsScalar {
        self.v
    }

    pub const fn get_z(&self) -> BlsScalar {
        self.z
    }

    pub const fn get_t1(&self) -> BlsScalar {
        self.t1
    }

    pub const fn get_t2(&self) -> BlsScalar {
        self.t2
    }

    /// 返回扩展点的 `(u, v)`，用于哈希输入。
    pub fn to_hash_inputs(&self) -> [BlsScalar; 2] {
        let affine_point = JubJubAffine::from(self);
        [affine_point.u, affine_point.v]
    }

    /// 将任意字节串哈希到 JubJub 素数阶子群点。
    pub fn hash_to_point(input: &[u8]) -> Self {
        let mut counter = 0u64;
        let mut array = [0u8; 32];
        loop {
            let state = blake2b_simd::Params::new()
                .hash_length(32)
                .to_state()
                .update(input)
                .update(&counter.to_le_bytes())
                .finalize();

            array.copy_from_slice(&state.as_bytes()[..32]);

            if let Ok(point) =
                <JubJubAffine as Serializable<32>>::from_bytes(&array)
            {
                if point.is_prime_order().into() {
                    return point.into();
                }
            }
            counter += 1
        }
    }

    /// 将 `u64` 映射到素数阶子群点（可逆映射）。
    pub fn map_to_point(input: &u64) -> Self {
        let input_bytes = input.to_le_bytes();

        let mut y_coordinate = GENERATOR.get_v();

        let mut point_bytes = y_coordinate.to_bytes();

        point_bytes[..u64::SIZE].copy_from_slice(&input_bytes);
        y_coordinate = BlsScalar::from_bytes(&point_bytes).unwrap();

        let adder = BlsScalar::from(u64::MAX) + BlsScalar::one();

        for _ in 0..u64::MAX {
            if let Ok(point) =
                <JubJubAffine as Serializable<32>>::from_bytes(&point_bytes)
            {
                if point.is_prime_order().into() {
                    return point.into();
                }
            }

            //

            y_coordinate += adder;
            point_bytes = y_coordinate.to_bytes();
        }

        panic!("No point is likely to be found soon enough.");
    }

    /// 从 `map_to_point` 的结果中恢复原始 `u64`。
    pub fn unmap_from_point(self) -> u64 {
        let point_bytes: [u8; u64::SIZE] = JubJubAffine::from(self).to_bytes()
            [..u64::SIZE]
            .try_into()
            .unwrap();
        u64::from_le_bytes(point_bytes)
    }

    /// 检查扩展点是否满足 JubJub 曲线方程。
    pub fn is_on_curve(&self) -> Choice {
        let affine = JubJubAffine::from(*self);

        (((self.z != Fq::zero())
            && affine.is_on_curve().into()
            && (affine.u * affine.v * self.z == self.t1 * self.t2))
            as u8)
            .into()
    }
}

#[test]
fn test_map_to_point() {
    use rand::Rng;

    let mut rng = rand::thread_rng();

    for _ in 0..500 {
        let value: u64 = rng.gen();
        let point = JubJubExtended::map_to_point(&value);
        let unmapped_value = point.unmap_from_point();

        assert_eq!(value, unmapped_value);
    }
}

#[test]
fn test_affine_point_generator_has_order_p() {
    assert_eq!(GENERATOR.is_prime_order().unwrap_u8(), 1);
}

#[test]
fn test_extended_point_generator_has_order_p() {
    assert_eq!(GENERATOR_EXTENDED.is_prime_order().unwrap_u8(), 1);
}

#[test]
fn test_affine_point_generator_nums_has_order_p() {
    assert_eq!(GENERATOR_NUMS.is_prime_order().unwrap_u8(), 1);
}

#[test]
fn test_affine_point_generator_is_not_identity() {
    assert_ne!(
        JubJubExtended::from(GENERATOR.mul_by_cofactor()),
        JubJubExtended::identity()
    );
}

#[test]
fn test_extended_point_generator_is_not_identity() {
    assert_ne!(
        GENERATOR_EXTENDED.mul_by_cofactor(),
        JubJubExtended::identity()
    );
}

#[test]
fn test_affine_point_generator_nums_is_not_identity() {
    assert_ne!(
        JubJubExtended::from(GENERATOR_NUMS.mul_by_cofactor()),
        JubJubExtended::identity()
    );
}

#[test]
fn test_is_on_curve() {
    assert!(bool::from(JubJubAffine::identity().is_on_curve()));
    assert!(bool::from(GENERATOR.is_on_curve()));
    assert!(bool::from(GENERATOR_NUMS.is_on_curve()));
    assert!(bool::from(JubJubExtended::identity().is_on_curve()));
    assert!(bool::from(GENERATOR_EXTENDED.is_on_curve()));
    assert!(bool::from(GENERATOR_NUMS_EXTENDED.is_on_curve()));

    let mut rng = rand_core::OsRng;
    for _ in 0..1000 {
        let affine = GENERATOR * &Fr::random(&mut rng);
        assert!(bool::from(affine.is_on_curve()));

        let extended = GENERATOR_EXTENDED * &Fr::random(&mut rng);
        assert!(bool::from(extended.is_on_curve()));
    }

    let affine_invalid = JubJubAffine::from_raw_unchecked(
        BlsScalar::from(42),
        BlsScalar::from(42),
    );
    assert!(!bool::from(affine_invalid.is_on_curve()));

    let extended_invalid = JubJubExtended::from_raw_unchecked(
        BlsScalar::from(42),
        BlsScalar::from(42),
        BlsScalar::from(42),
        BlsScalar::from(21),
        BlsScalar::from(2),
    );
    assert!(!bool::from(extended_invalid.is_on_curve()));
}

#[test]
fn second_gen_nums() {
    use blake2::{Blake2b, Digest};
    let generator_bytes = GENERATOR.to_bytes();
    let mut counter = 0u64;
    let mut array = [0u8; 32];
    loop {
        let mut hasher = Blake2b::new();
        hasher.update(generator_bytes);
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        array.copy_from_slice(&digest[0..32]);
        if <JubJubAffine as Serializable<32>>::from_bytes(&array).is_ok()
            && <JubJubAffine as Serializable<32>>::from_bytes(&array)
                .unwrap()
                .is_prime_order()
                .unwrap_u8()
                == 1
        {
            assert!(
                GENERATOR_NUMS
                    == <JubJubAffine as Serializable<32>>::from_bytes(&array)
                        .unwrap()
            );
            break;
        }
        counter += 1;
    }
    assert_eq!(counter, 18);
}

#[cfg(all(test, feature = "alloc"))]
mod fuzz {
    use alloc::vec::Vec;

    use crate::ExtendedPoint;

    quickcheck::quickcheck! {
        fn prop_hash_to_point(bytes: Vec<u8>) -> bool {
            let point = ExtendedPoint::hash_to_point(&bytes);

            point.satisfies_extended_curve_equation_vartime() && point.is_prime_order().into()
        }
    }
}

#[cfg(all(test, feature = "serde"))]
pub mod test_utils {
    use std::boxed::Box;
    use std::string::String;

    use serde::Serialize;

    pub fn assert_canonical_json<T>(
        input: &T,
        expected: &str,
    ) -> Result<String, Box<dyn std::error::Error>>
    where
        T: ?Sized + Serialize,
    {
        let serialized = serde_json::to_string(input)?;
        let input_canonical: serde_json::Value = serialized.parse()?;
        let expected_canonical: serde_json::Value = expected.parse()?;
        assert_eq!(input_canonical, expected_canonical);
        Ok(serialized)
    }
}

#[cfg(feature = "zeroize")]
#[test]
fn test_zeroize() {
    use zeroize::Zeroize;

    let mut point: JubJubAffine = GENERATOR;
    point.zeroize();
    assert!(bool::from(point.is_identity()));

    let mut point: JubJubExtended = GENERATOR_EXTENDED;
    point.zeroize();
    assert!(bool::from(point.is_identity()));
}
