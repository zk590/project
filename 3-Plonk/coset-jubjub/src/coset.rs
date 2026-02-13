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

        let sign_bit = encoded_bytes[31] >> 7;

        encoded_bytes[31] &= 0b0111_1111;

        let v_coordinate =
            <BlsScalar as Serializable<32>>::from_bytes(&encoded_bytes)?;

        let v_squared = v_coordinate.square();

        Option::from(
            ((v_squared - BlsScalar::one())
                * ((BlsScalar::one() + EDWARDS_D * v_squared)
                    .invert()
                    .unwrap_or(BlsScalar::zero())))
            .sqrt()
            .and_then(|u_coordinate| {
                let flip_sign =
                    Choice::from((u_coordinate.to_bytes()[0] ^ sign_bit) & 1);
                let signed_u = BlsScalar::conditional_select(
                    &u_coordinate,
                    &-u_coordinate,
                    flip_sign,
                );

                let u_is_zero = signed_u.ct_eq(&BlsScalar::zero());
                CtOption::new(
                    JubJubAffine {
                        u: signed_u,
                        v: v_coordinate,
                    },
                    !(u_is_zero & flip_sign),
                )
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
    /// 尝试将 32 字节解码为素数阶子群点。
    /// 仅当“字节可解码”为曲线点且“点属于素数阶子群”时返回 `Some`。
    #[inline]
    fn decode_prime_order_point(bytes: &[u8; 32]) -> Option<Self> {
        if let Ok(decoded_affine_point) =
            <JubJubAffine as Serializable<32>>::from_bytes(bytes)
        {
            if decoded_affine_point.is_prime_order().into() {
                return Some(decoded_affine_point.into());
            }
        }
        None
    }

    /// 用 `u64` 低位覆盖 y 坐标字节前 8 位，构造映射搜索起点。
    #[inline]
    fn mapped_y_bytes(input: &u64) -> [u8; 32] {
        let mut point_bytes = GENERATOR.get_v().to_bytes();
        point_bytes[..u64::SIZE].copy_from_slice(&input.to_le_bytes());
        point_bytes
    }

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

    /// 读取扩展点 `u` 分量。
    /// 该访问器不做任何归一化或合法性检查。
    /// 常用于调试、序列化和中间状态观测。
    pub const fn get_u(&self) -> BlsScalar {
        self.u
    }

    /// 读取扩展点 `v` 分量。
    /// 返回值按值复制，不影响原对象内部状态。
    /// 与 `get_u` 组合可直接构造哈希输入。
    pub const fn get_v(&self) -> BlsScalar {
        self.v
    }

    /// 读取扩展点 `z` 分量。
    /// 在扩展坐标系中该值决定仿射恢复时的逆元因子。
    /// 对单位元通常取 `one()`。
    pub const fn get_z(&self) -> BlsScalar {
        self.z
    }

    /// 读取扩展点 `t1` 分量。
    /// 该分量与 `t2` 一起缓存 `u * v` 的拆分乘积。
    /// 用于降低点加法中的乘法开销。
    pub const fn get_t1(&self) -> BlsScalar {
        self.t1
    }

    /// 读取扩展点 `t2` 分量。
    /// 与 `get_t1` 配对维护扩展坐标不变量。
    /// 该访问器同样不触发任何计算。
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

            if let Some(point) = Self::decode_prime_order_point(&array) {
                return point;
            }
            counter += 1
        }
    }

    /// 将 `u64` 映射到素数阶子群点（可逆映射）。
    pub fn map_to_point(input: &u64) -> Self {
        let mut point_bytes = Self::mapped_y_bytes(input);
        let mut y_coordinate = BlsScalar::from_bytes(&point_bytes).unwrap();

        let adder = BlsScalar::from(u64::MAX) + BlsScalar::one();

        for _ in 0..u64::MAX {
            if let Some(point) = Self::decode_prime_order_point(&point_bytes) {
                return point;
            }

            // 保持低 64 位不变，仅提升高位候选，遍历同一映射桶中的其它 y 值。
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
        let input_value: u64 = rng.gen();
        let mapped_point = JubJubExtended::map_to_point(&input_value);
        let unmapped_value = mapped_point.unmap_from_point();

        assert_eq!(input_value, unmapped_value);
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
    let mut hash_counter = 0u64;
    let mut candidate_bytes = [0u8; 32];
    loop {
        let mut hasher = Blake2b::new();
        hasher.update(generator_bytes);
        hasher.update(hash_counter.to_le_bytes());
        let hash_digest = hasher.finalize();
        candidate_bytes.copy_from_slice(&hash_digest[0..32]);
        if let Ok(decoded_affine_point) =
            <JubJubAffine as Serializable<32>>::from_bytes(&candidate_bytes)
        {
            if decoded_affine_point.is_prime_order().unwrap_u8() == 1 {
                assert!(GENERATOR_NUMS == decoded_affine_point);
                break;
            }
        }
        hash_counter += 1;
    }
    assert_eq!(hash_counter, 18);
}

#[cfg(all(test, feature = "alloc"))]
mod fuzz {
    use alloc::vec::Vec;

    use crate::ExtendedPoint;

    quickcheck::quickcheck! {
        fn prop_hash_to_point(input_bytes: Vec<u8>) -> bool {
            let mapped_point = ExtendedPoint::hash_to_point(&input_bytes);

            mapped_point.satisfies_extended_curve_equation_vartime() && mapped_point.is_prime_order().into()
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
