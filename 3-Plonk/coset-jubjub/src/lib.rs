//! JubJub 椭圆曲线库入口，导出标量域、点运算与可选功能模块。

#![no_std]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![allow(missing_docs)]
#![deny(unsafe_code)]
#![allow(clippy::suspicious_arithmetic_impl)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

use bitvec::{order::Lsb0, view::AsBits};
use core::borrow::Borrow;
use core::fmt;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use ff::{BatchInverter, Field};
use group::{
    cofactor::{CofactorCurve, CofactorCurveAffine, CofactorGroup},
    prime::PrimeGroup,
    Curve, Group, GroupEncoding,
};
use rand_core::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use group::WnafGroup;

//
mod coset;
pub use coset::{
    dhke, GENERATOR, GENERATOR_EXTENDED, GENERATOR_NUMS,
    GENERATOR_NUMS_EXTENDED,
};

pub type JubJubAffine = AffinePoint;

pub type JubJubExtended = ExtendedPoint;

pub type JubJubScalar = Fr;
pub use coset_bls12_381::BlsScalar;
pub use coset_bls12_381::BlsScalar as Fq;

#[macro_use]
mod util;

mod fr;
pub use fr::Fr;

pub type Base = Fq;

pub type Scalar = Fr;

const FR_MODULUS_BYTES: [u8; 32] = [
    183, 44, 247, 214, 94, 14, 151, 208, 130, 16, 200, 204, 147, 32, 104, 166,
    0, 59, 52, 1, 1, 59, 103, 6, 169, 175, 51, 101, 234, 180, 125, 14,
];

#[derive(Clone, Copy, Debug, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct AffinePoint {
    u: Fq,
    v: Fq,
}

impl fmt::Display for AffinePoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Neg for AffinePoint {
    type Output = AffinePoint;

    #[inline]
    fn neg(self) -> AffinePoint {
        AffinePoint {
            u: -self.u,
            v: self.v,
        }
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.u.ct_eq(&other.u) & self.v.ct_eq(&other.v)
    }
}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        AffinePoint {
            u: Fq::conditional_select(&a.u, &b.u, choice),
            v: Fq::conditional_select(&a.v, &b.v, choice),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct ExtendedPoint {
    u: Fq,
    v: Fq,
    z: Fq,
    t1: Fq,
    t2: Fq,
}

impl fmt::Display for ExtendedPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ConstantTimeEq for ExtendedPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        (self.u * other.z).ct_eq(&(other.u * self.z))
            & (self.v * other.z).ct_eq(&(other.v * self.z))
    }
}

impl ConditionallySelectable for ExtendedPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ExtendedPoint {
            u: Fq::conditional_select(&a.u, &b.u, choice),
            v: Fq::conditional_select(&a.v, &b.v, choice),
            z: Fq::conditional_select(&a.z, &b.z, choice),
            t1: Fq::conditional_select(&a.t1, &b.t1, choice),
            t2: Fq::conditional_select(&a.t2, &b.t2, choice),
        }
    }
}

impl PartialEq for ExtendedPoint {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<T> Sum<T> for ExtendedPoint
where
    T: Borrow<ExtendedPoint>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

impl Neg for ExtendedPoint {
    type Output = ExtendedPoint;

    #[inline]
    fn neg(self) -> ExtendedPoint {
        ExtendedPoint {
            u: -self.u,
            v: self.v,
            z: self.z,
            t1: -self.t1,
            t2: self.t2,
        }
    }
}

impl From<AffinePoint> for ExtendedPoint {
    fn from(affine: AffinePoint) -> ExtendedPoint {
        ExtendedPoint {
            u: affine.u,
            v: affine.v,
            z: Fq::one(),
            t1: affine.u,
            t2: affine.v,
        }
    }
}

impl<'a> From<&'a ExtendedPoint> for AffinePoint {
    fn from(extended: &'a ExtendedPoint) -> AffinePoint {
        let zinv = extended.z.invert().unwrap();

        AffinePoint {
            u: extended.u * zinv,
            v: extended.v * zinv,
        }
    }
}

impl From<ExtendedPoint> for AffinePoint {
    fn from(extended: ExtendedPoint) -> AffinePoint {
        AffinePoint::from(&extended)
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct AffineNielsPoint {
    v_plus_u: Fq,
    v_minus_u: Fq,
    t2d: Fq,
}

impl AffineNielsPoint {
    pub const fn identity() -> Self {
        AffineNielsPoint {
            v_plus_u: Fq::one(),
            v_minus_u: Fq::one(),
            t2d: Fq::zero(),
        }
    }

    #[inline]
    fn multiply(&self, by: &[u8; 32]) -> ExtendedPoint {
        let zero = AffineNielsPoint::identity();

        let mut accumulated_point = ExtendedPoint::identity();

        //

        for bit in by
            .as_bits::<Lsb0>()
            .iter()
            .rev()
            .skip(4)
            .map(|bit| Choice::from(if *bit { 1 } else { 0 }))
        {
            accumulated_point = accumulated_point.double();
            accumulated_point +=
                AffineNielsPoint::conditional_select(&zero, self, bit);
        }

        accumulated_point
    }

    pub fn multiply_bits(&self, by: &[u8; 32]) -> ExtendedPoint {
        self.multiply(by)
    }
}

impl<'a, 'b> Mul<&'b Fr> for &'a AffineNielsPoint {
    type Output = ExtendedPoint;

    fn mul(self, other: &'b Fr) -> ExtendedPoint {
        self.multiply(&other.to_bytes())
    }
}

impl_binops_multiplicative_mixed!(AffineNielsPoint, Fr, ExtendedPoint);

impl ConditionallySelectable for AffineNielsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        AffineNielsPoint {
            v_plus_u: Fq::conditional_select(&a.v_plus_u, &b.v_plus_u, choice),
            v_minus_u: Fq::conditional_select(
                &a.v_minus_u,
                &b.v_minus_u,
                choice,
            ),
            t2d: Fq::conditional_select(&a.t2d, &b.t2d, choice),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct ExtendedNielsPoint {
    v_plus_u: Fq,
    v_minus_u: Fq,
    z: Fq,
    t2d: Fq,
}

impl ConditionallySelectable for ExtendedNielsPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        ExtendedNielsPoint {
            v_plus_u: Fq::conditional_select(&a.v_plus_u, &b.v_plus_u, choice),
            v_minus_u: Fq::conditional_select(
                &a.v_minus_u,
                &b.v_minus_u,
                choice,
            ),
            z: Fq::conditional_select(&a.z, &b.z, choice),
            t2d: Fq::conditional_select(&a.t2d, &b.t2d, choice),
        }
    }
}

impl ExtendedNielsPoint {
    pub const fn identity() -> Self {
        ExtendedNielsPoint {
            v_plus_u: Fq::one(),
            v_minus_u: Fq::one(),
            z: Fq::one(),
            t2d: Fq::zero(),
        }
    }

    #[inline]
    fn multiply(&self, by: &[u8; 32]) -> ExtendedPoint {
        let zero = ExtendedNielsPoint::identity();

        let mut accumulated_point = ExtendedPoint::identity();

        //

        for bit in by
            .iter()
            .rev()
            .flat_map(|byte| {
                (0..8).rev().map(move |i| Choice::from((byte >> i) & 1u8))
            })
            .skip(4)
        {
            accumulated_point = accumulated_point.double();
            accumulated_point +=
                ExtendedNielsPoint::conditional_select(&zero, self, bit);
        }

        accumulated_point
    }

    pub fn multiply_bits(&self, by: &[u8; 32]) -> ExtendedPoint {
        self.multiply(by)
    }
}

impl<'a, 'b> Mul<&'b Fr> for &'a ExtendedNielsPoint {
    type Output = ExtendedPoint;

    fn mul(self, other: &'b Fr) -> ExtendedPoint {
        self.multiply(&other.to_bytes())
    }
}

impl_binops_multiplicative_mixed!(ExtendedNielsPoint, Fr, ExtendedPoint);

pub const EDWARDS_D: Fq = Fq::from_raw([
    0x0106_5fd6_d634_3eb1,
    0x292d_7f6d_3757_9d26,
    0xf5fd_9207_e6bd_7fd4,
    0x2a93_18e7_4bfa_2b48,
]);

const EDWARDS_D2: Fq = Fq::from_raw([
    0x020c_bfad_ac68_7d62,
    0x525a_feda_6eaf_3a4c,
    0xebfb_240f_cd7a_ffa8,
    0x5526_31ce_97f4_5691,
]);

impl AffinePoint {
    /// 返回仿射坐标单位元。
    pub const fn identity() -> Self {
        AffinePoint {
            u: Fq::zero(),
            v: Fq::one(),
        }
    }

    /// 判断是否为单位元。
    pub fn is_identity(&self) -> Choice {
        ExtendedPoint::from(*self).is_identity()
    }

    /// 乘以协因子 8，将点映射到素数阶子群。
    pub fn mul_by_cofactor(&self) -> ExtendedPoint {
        ExtendedPoint::from(*self).mul_by_cofactor()
    }

    /// 判断是否为小阶点（8-扭子群）。
    pub fn is_small_order(&self) -> Choice {
        ExtendedPoint::from(*self).is_small_order()
    }

    /// 判断是否属于素数阶子群。
    pub fn is_torsion_free(&self) -> Choice {
        ExtendedPoint::from(*self).is_torsion_free()
    }

    /// 判断是否为素数阶且非单位元。
    pub fn is_prime_order(&self) -> Choice {
        let extended = ExtendedPoint::from(*self);
        extended.is_torsion_free() & (!extended.is_identity())
    }

    /// 压缩编码为 32 字节（v 坐标 + u 符号位）。
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut encoded_bytes = self.v.to_bytes();
        let u_bytes = self.u.to_bytes();

        encoded_bytes[31] |= u_bytes[0] << 7;

        encoded_bytes
    }

    /// 按 ZIP-216 规则从 32 字节反序列化点。
    pub fn from_bytes(b: [u8; 32]) -> CtOption<Self> {
        Self::decode_from_bytes_with_zip216_flag(b, 1.into())
    }

    /// 按 Pre-ZIP-216 兼容规则反序列化点。
    pub fn from_bytes_pre_zip216_compatibility(b: [u8; 32]) -> CtOption<Self> {
        Self::decode_from_bytes_with_zip216_flag(b, 0.into())
    }

    fn decode_from_bytes_with_zip216_flag(
        mut b: [u8; 32],
        zip_216_enabled: Choice,
    ) -> CtOption<Self> {
        let sign = b[31] >> 7;

        b[31] &= 0b0111_1111;

        Fq::from_bytes(&b).and_then(|v| {
            let v2 = v.square();

            ((v2 - Fq::one())
                * ((Fq::one() + EDWARDS_D * v2).invert().unwrap_or(Fq::zero())))
            .sqrt()
            .and_then(|u| {
                let flip_sign = Choice::from((u.to_bytes()[0] ^ sign) & 1);
                let u_negated = -u;
                let final_u = Fq::conditional_select(&u, &u_negated, flip_sign);

                let u_is_zero = u.ct_eq(&Fq::zero());
                CtOption::new(
                    AffinePoint { u: final_u, v },
                    !(zip_216_enabled & u_is_zero & flip_sign),
                )
            })
        })
    }

    /// 批量反序列化点，复用批量求逆降低开销。
    #[cfg(feature = "alloc")]
    pub fn batch_from_bytes(
        items: impl Iterator<Item = [u8; 32]>,
    ) -> Vec<CtOption<Self>> {
        use ff::BatchInvert;

        #[derive(Clone, Copy, Default)]
        struct Item {
            sign: u8,
            v: Fq,
            numerator: Fq,
            denominator: Fq,
        }

        impl ConditionallySelectable for Item {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Item {
                    sign: u8::conditional_select(&a.sign, &b.sign, choice),
                    v: Fq::conditional_select(&a.v, &b.v, choice),
                    numerator: Fq::conditional_select(
                        &a.numerator,
                        &b.numerator,
                        choice,
                    ),
                    denominator: Fq::conditional_select(
                        &a.denominator,
                        &b.denominator,
                        choice,
                    ),
                }
            }
        }

        let items: Vec<_> = items
            .map(|mut b| {
                let sign = b[31] >> 7;

                b[31] &= 0b0111_1111;

                Fq::from_bytes(&b).map(|v| {
                    let v2 = v.square();

                    Item {
                        v,
                        sign,
                        numerator: (v2 - Fq::one()),
                        denominator: Fq::one() + EDWARDS_D * v2,
                    }
                })
            })
            .collect();

        let mut denominators: Vec<_> = items
            .iter()
            .map(|item| item.map(|item| item.denominator).unwrap_or(Fq::zero()))
            .collect();
        denominators.iter_mut().batch_invert();

        items
            .into_iter()
            .zip(denominators.into_iter())
            .map(|(item, inv_denominator)| {
                item.and_then(
                    |Item {
                         v, sign, numerator, ..
                     }| {
                        (numerator * inv_denominator).sqrt().and_then(|u| {
                            let flip_sign =
                                Choice::from((u.to_bytes()[0] ^ sign) & 1);
                            let u_negated = -u;
                            let final_u = Fq::conditional_select(
                                &u, &u_negated, flip_sign,
                            );

                            let u_is_zero = u.ct_eq(&Fq::zero());
                            CtOption::new(
                                AffinePoint { u: final_u, v },
                                !(u_is_zero & flip_sign),
                            )
                        })
                    },
                )
            })
            .collect()
    }

    pub fn get_u(&self) -> Fq {
        self.u
    }

    pub fn get_v(&self) -> Fq {
        self.v
    }

    /// 转为扩展坐标表示。
    pub const fn to_extended(&self) -> ExtendedPoint {
        ExtendedPoint {
            u: self.u,
            v: self.v,
            z: Fq::one(),
            t1: self.u,
            t2: self.v,
        }
    }

    /// 转为 Niels 形式以加速点加法。
    pub const fn to_niels(&self) -> AffineNielsPoint {
        AffineNielsPoint {
            v_plus_u: Fq::add(&self.v, &self.u),
            v_minus_u: Fq::sub(&self.v, &self.u),
            t2d: Fq::mul(&Fq::mul(&self.u, &self.v), &EDWARDS_D2),
        }
    }

    /// 从原始坐标构造点，不做合法性检查。
    pub const fn from_raw_unchecked(u: Fq, v: Fq) -> AffinePoint {
        AffinePoint { u, v }
    }

    #[cfg(test)]
    fn satisfies_curve_equation_vartime(&self) -> bool {
        let u2 = self.u.square();
        let v2 = self.v.square();

        v2 - u2 == Fq::one() + EDWARDS_D * u2 * v2
    }
}

impl ExtendedPoint {
    /// 返回扩展坐标单位元。
    pub const fn identity() -> Self {
        ExtendedPoint {
            u: Fq::zero(),
            v: Fq::one(),
            z: Fq::one(),
            t1: Fq::zero(),
            t2: Fq::zero(),
        }
    }

    /// 判断是否为单位元。
    pub fn is_identity(&self) -> Choice {
        self.u.ct_eq(&Fq::zero()) & self.v.ct_eq(&self.z)
    }

    /// 判断是否为小阶点（位于协因子子群）。
    pub fn is_small_order(&self) -> Choice {
        self.double().double().u.ct_eq(&Fq::zero())
    }

    /// 判断是否属于素数阶子群。
    pub fn is_torsion_free(&self) -> Choice {
        self.multiply(&FR_MODULUS_BYTES).is_identity()
    }

    /// 判断是否为素数阶且非单位元。
    pub fn is_prime_order(&self) -> Choice {
        self.is_torsion_free() & (!self.is_identity())
    }

    /// 乘以协因子 8。
    pub fn mul_by_cofactor(&self) -> ExtendedPoint {
        self.double().double().double()
    }

    /// 转为扩展 Niels 形式以加速加法。
    pub fn to_niels(&self) -> ExtendedNielsPoint {
        ExtendedNielsPoint {
            v_plus_u: self.v + self.u,
            v_minus_u: self.v - self.u,
            z: self.z,
            t2d: self.t1 * self.t2 * EDWARDS_D2,
        }
    }

    /// 点倍加（extended coordinates doubling）。
    pub fn double(&self) -> ExtendedPoint {
        //

        //

        //

        //

        //

        //

        //

        //

        //

        //

        //

        //

        let u_squared = self.u.square();
        let v_squared = self.v.square();
        let zz2 = self.z.square().double();
        let uv2 = (self.u + self.v).square();
        let v_plus_u_squared = v_squared + u_squared;
        let v_minus_u_squared = v_squared - u_squared;

        CompletedPoint {
            u: uv2 - v_plus_u_squared,
            v: v_plus_u_squared,
            z: v_minus_u_squared,
            t: zz2 - v_minus_u_squared,
        }
        .into_extended()
    }

    #[inline]
    fn multiply(self, by: &[u8; 32]) -> Self {
        self.to_niels().multiply(by)
    }

    /// 批量将扩展坐标点转换为仿射坐标点。
    fn batch_normalize(
        projective_points: &[Self],
        affine_points: &mut [AffinePoint],
    ) {
        assert_eq!(projective_points.len(), affine_points.len());

        for (projective_point, affine_point) in
            projective_points.iter().zip(affine_points.iter_mut())
        {
            affine_point.u = projective_point.z;
        }

        BatchInverter::invert_with_internal_scratch(
            affine_points,
            |affine_point| &mut affine_point.u,
            |affine_point| &mut affine_point.v,
        );

        for (projective_point, affine_point) in
            projective_points.iter().zip(affine_points.iter_mut()).rev()
        {
            let z_inverse = affine_point.u;

            affine_point.u = projective_point.u * z_inverse;
            affine_point.v = projective_point.v * z_inverse;
        }
    }

    #[cfg(test)]
    fn satisfies_extended_curve_equation_vartime(&self) -> bool {
        let affine = AffinePoint::from(*self);

        self.z != Fq::zero()
            && affine.satisfies_curve_equation_vartime()
            && (affine.u * affine.v * self.z == self.t1 * self.t2)
    }
}

impl<'a, 'b> Mul<&'b Fr> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    fn mul(self, other: &'b Fr) -> ExtendedPoint {
        self.multiply(&other.to_bytes())
    }
}

impl_binops_multiplicative!(ExtendedPoint, Fr);

impl<'a, 'b> Add<&'b ExtendedNielsPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, other: &'b ExtendedNielsPoint) -> ExtendedPoint {
        //

        let v_minus_u_term = (self.v - self.u) * other.v_minus_u;
        let v_plus_u_term = (self.v + self.u) * other.v_plus_u;
        let t_term = self.t1 * self.t2 * other.t2d;
        let z_term = (self.z * other.z).double();

        CompletedPoint {
            u: v_plus_u_term - v_minus_u_term,
            v: v_plus_u_term + v_minus_u_term,
            z: z_term + t_term,
            t: z_term - t_term,
        }
        .into_extended()
    }
}

impl<'a, 'b> Sub<&'b ExtendedNielsPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, other: &'b ExtendedNielsPoint) -> ExtendedPoint {
        let v_minus_u_term = (self.v - self.u) * other.v_plus_u;
        let v_plus_u_term = (self.v + self.u) * other.v_minus_u;
        let t_term = self.t1 * self.t2 * other.t2d;
        let z_term = (self.z * other.z).double();

        CompletedPoint {
            u: v_plus_u_term - v_minus_u_term,
            v: v_plus_u_term + v_minus_u_term,
            z: z_term - t_term,
            t: z_term + t_term,
        }
        .into_extended()
    }
}

impl_binops_additive!(ExtendedPoint, ExtendedNielsPoint);

impl<'a, 'b> Add<&'b AffineNielsPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, other: &'b AffineNielsPoint) -> ExtendedPoint {
        let v_minus_u_term = (self.v - self.u) * other.v_minus_u;
        let v_plus_u_term = (self.v + self.u) * other.v_plus_u;
        let t_term = self.t1 * self.t2 * other.t2d;
        let z_term = self.z.double();

        CompletedPoint {
            u: v_plus_u_term - v_minus_u_term,
            v: v_plus_u_term + v_minus_u_term,
            z: z_term + t_term,
            t: z_term - t_term,
        }
        .into_extended()
    }
}

impl<'a, 'b> Sub<&'b AffineNielsPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, other: &'b AffineNielsPoint) -> ExtendedPoint {
        let v_minus_u_term = (self.v - self.u) * other.v_plus_u;
        let v_plus_u_term = (self.v + self.u) * other.v_minus_u;
        let t_term = self.t1 * self.t2 * other.t2d;
        let z_term = self.z.double();

        CompletedPoint {
            u: v_plus_u_term - v_minus_u_term,
            v: v_plus_u_term + v_minus_u_term,
            z: z_term - t_term,
            t: z_term + t_term,
        }
        .into_extended()
    }
}

impl_binops_additive!(ExtendedPoint, AffineNielsPoint);

impl<'a, 'b> Add<&'b ExtendedPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[inline]
    fn add(self, other: &'b ExtendedPoint) -> ExtendedPoint {
        self + other.to_niels()
    }
}

impl<'a, 'b> Sub<&'b ExtendedPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[inline]
    fn sub(self, other: &'b ExtendedPoint) -> ExtendedPoint {
        self - other.to_niels()
    }
}

impl_binops_additive!(ExtendedPoint, ExtendedPoint);

impl<'a, 'b> Add<&'b AffinePoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[inline]
    fn add(self, other: &'b AffinePoint) -> ExtendedPoint {
        self + other.to_niels()
    }
}

impl<'a, 'b> Sub<&'b AffinePoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[inline]
    fn sub(self, other: &'b AffinePoint) -> ExtendedPoint {
        self - other.to_niels()
    }
}

impl_binops_additive!(ExtendedPoint, AffinePoint);

struct CompletedPoint {
    u: Fq,
    v: Fq,
    z: Fq,
    t: Fq,
}

impl CompletedPoint {
    #[inline]
    fn into_extended(self) -> ExtendedPoint {
        ExtendedPoint {
            u: self.u * self.t,
            v: self.v * self.z,
            z: self.z * self.t,
            t1: self.u,
            t2: self.v,
        }
    }
}

impl Default for AffinePoint {
    fn default() -> AffinePoint {
        AffinePoint::identity()
    }
}

impl Default for ExtendedPoint {
    fn default() -> ExtendedPoint {
        ExtendedPoint::identity()
    }
}

/// 对扩展点切片做原地归一化，并返回仿射点迭代器。
pub fn batch_normalize(
    points: &mut [ExtendedPoint],
) -> impl Iterator<Item = AffinePoint> + '_ {
    BatchInverter::invert_with_internal_scratch(
        points,
        |point| &mut point.z,
        |point| &mut point.t1,
    );

    for point in points.iter_mut() {
        let mut normalized_point = *point;
        let z_inverse = normalized_point.z;

        normalized_point.u *= &z_inverse;
        normalized_point.v *= &z_inverse;
        normalized_point.z = Fq::one();
        normalized_point.t1 = normalized_point.u;
        normalized_point.t2 = normalized_point.v;

        *point = normalized_point;
    }

    points.iter().map(|point| AffinePoint {
        u: point.u,
        v: point.v,
    })
}

impl<'a, 'b> Mul<&'b Fr> for &'a AffinePoint {
    type Output = ExtendedPoint;

    fn mul(self, other: &'b Fr) -> ExtendedPoint {
        self.to_niels().multiply(&other.to_bytes())
    }
}

impl_binops_multiplicative_mixed!(AffinePoint, Fr, ExtendedPoint);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct SubgroupPoint(ExtendedPoint);

impl From<SubgroupPoint> for ExtendedPoint {
    fn from(val: SubgroupPoint) -> ExtendedPoint {
        val.0
    }
}

impl<'a> From<&'a SubgroupPoint> for &'a ExtendedPoint {
    fn from(val: &'a SubgroupPoint) -> &'a ExtendedPoint {
        &val.0
    }
}

impl fmt::Display for SubgroupPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ConditionallySelectable for SubgroupPoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        SubgroupPoint(ExtendedPoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl SubgroupPoint {
    /// 从原始坐标构造子群点（调用方需保证输入在子群内）。
    pub const fn from_raw_unchecked(u: Fq, v: Fq) -> Self {
        SubgroupPoint(AffinePoint::from_raw_unchecked(u, v).to_extended())
    }
}

impl<T> Sum<T> for SubgroupPoint
where
    T: Borrow<SubgroupPoint>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

impl Neg for SubgroupPoint {
    type Output = SubgroupPoint;

    #[inline]
    fn neg(self) -> SubgroupPoint {
        SubgroupPoint(-self.0)
    }
}

impl Neg for &SubgroupPoint {
    type Output = SubgroupPoint;

    #[inline]
    fn neg(self) -> SubgroupPoint {
        SubgroupPoint(-self.0)
    }
}

impl<'a, 'b> Add<&'b SubgroupPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[inline]
    fn add(self, other: &'b SubgroupPoint) -> ExtendedPoint {
        self + other.0
    }
}

impl<'a, 'b> Sub<&'b SubgroupPoint> for &'a ExtendedPoint {
    type Output = ExtendedPoint;

    #[inline]
    fn sub(self, other: &'b SubgroupPoint) -> ExtendedPoint {
        self - other.0
    }
}

impl_binops_additive!(ExtendedPoint, SubgroupPoint);

impl<'a, 'b> Add<&'b SubgroupPoint> for &'a SubgroupPoint {
    type Output = SubgroupPoint;

    #[inline]
    fn add(self, other: &'b SubgroupPoint) -> SubgroupPoint {
        SubgroupPoint(self.0 + other.0)
    }
}

impl<'a, 'b> Sub<&'b SubgroupPoint> for &'a SubgroupPoint {
    type Output = SubgroupPoint;

    #[inline]
    fn sub(self, other: &'b SubgroupPoint) -> SubgroupPoint {
        SubgroupPoint(self.0 - other.0)
    }
}

impl_binops_additive!(SubgroupPoint, SubgroupPoint);

impl<'a, 'b> Mul<&'b Fr> for &'a SubgroupPoint {
    type Output = SubgroupPoint;

    fn mul(self, other: &'b Fr) -> SubgroupPoint {
        SubgroupPoint(self.0.multiply(&other.to_bytes()))
    }
}

impl_binops_multiplicative!(SubgroupPoint, Fr);

impl Group for ExtendedPoint {
    type Scalar = Fr;

    fn random(mut rng: impl RngCore) -> Self {
        loop {
            let random_v = Fq::random(&mut rng);
            let flip_sign = rng.next_u32() % 2 != 0;

            let v_squared = random_v.square();
            let candidate_point = ((v_squared - Fq::one())
                * ((Fq::one() + EDWARDS_D * v_squared)
                    .invert()
                    .unwrap_or(Fq::zero())))
            .sqrt()
            .map(|u| AffinePoint {
                u: if flip_sign { -u } else { u },
                v: random_v,
            });

            if candidate_point.is_some().into() {
                let point_on_curve = candidate_point.unwrap().to_curve();

                if bool::from(!point_on_curve.is_identity()) {
                    return point_on_curve;
                }
            }
        }
    }

    fn identity() -> Self {
        Self::identity()
    }

    fn generator() -> Self {
        AffinePoint::generator().into()
    }

    fn is_identity(&self) -> Choice {
        self.is_identity()
    }

    fn double(&self) -> Self {
        self.double()
    }
}

impl Group for SubgroupPoint {
    type Scalar = Fr;

    fn random(mut rng: impl RngCore) -> Self {
        loop {
            let subgroup_candidate =
                ExtendedPoint::random(&mut rng).clear_cofactor();

            if bool::from(!subgroup_candidate.is_identity()) {
                return subgroup_candidate;
            }
        }
    }

    fn identity() -> Self {
        SubgroupPoint(ExtendedPoint::identity())
    }

    fn generator() -> Self {
        ExtendedPoint::generator().clear_cofactor()
    }

    fn is_identity(&self) -> Choice {
        self.0.is_identity()
    }

    fn double(&self) -> Self {
        SubgroupPoint(self.0.double())
    }
}

#[cfg(feature = "alloc")]
impl WnafGroup for ExtendedPoint {
    fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
        const RECOMMENDATIONS: [usize; 12] =
            [1, 3, 7, 20, 43, 120, 273, 563, 1630, 3128, 7933, 62569];

        let mut ret = 4;
        for r in &RECOMMENDATIONS {
            if num_scalars > *r {
                ret += 1;
            } else {
                break;
            }
        }

        ret
    }
}

impl PrimeGroup for SubgroupPoint {}

impl CofactorGroup for ExtendedPoint {
    type Subgroup = SubgroupPoint;

    fn clear_cofactor(&self) -> Self::Subgroup {
        SubgroupPoint(self.mul_by_cofactor())
    }

    fn into_subgroup(self) -> CtOption<Self::Subgroup> {
        CtOption::new(SubgroupPoint(self), self.is_torsion_free())
    }

    fn is_torsion_free(&self) -> Choice {
        self.is_torsion_free()
    }
}

impl Curve for ExtendedPoint {
    type AffineRepr = AffinePoint;

    fn batch_normalize(p: &[Self], q: &mut [Self::AffineRepr]) {
        Self::batch_normalize(p, q);
    }

    fn to_affine(&self) -> Self::AffineRepr {
        self.into()
    }
}

impl CofactorCurve for ExtendedPoint {
    type Affine = AffinePoint;
}

impl CofactorCurveAffine for AffinePoint {
    type Scalar = Fr;
    type Curve = ExtendedPoint;

    fn identity() -> Self {
        Self::identity()
    }

    fn generator() -> Self {
        AffinePoint {
            u: Fq::from_raw([
                0xe4b3_d35d_f1a7_adfe,
                0xcaf5_5d1b_29bf_81af,
                0x8b0f_03dd_d60a_8187,
                0x62ed_cbb8_bf37_87c8,
            ]),
            v: Fq::from_raw([
                0x0000_0000_0000_000b,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
                0x0000_0000_0000_0000,
            ]),
        }
    }

    fn is_identity(&self) -> Choice {
        self.is_identity()
    }

    fn to_curve(&self) -> Self::Curve {
        (*self).into()
    }
}

impl GroupEncoding for ExtendedPoint {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        AffinePoint::from_bytes(*bytes).map(Self::from)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        AffinePoint::from_bytes(*bytes).map(Self::from)
    }

    fn to_bytes(&self) -> Self::Repr {
        AffinePoint::from(self).to_bytes()
    }
}

impl GroupEncoding for SubgroupPoint {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        ExtendedPoint::from_bytes(bytes).and_then(|p| p.into_subgroup())
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        ExtendedPoint::from_bytes_unchecked(bytes).map(SubgroupPoint)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.0.to_bytes()
    }
}

impl GroupEncoding for AffinePoint {
    type Repr = [u8; 32];

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        Self::from_bytes(*bytes)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        Self::from_bytes(*bytes)
    }

    fn to_bytes(&self) -> Self::Repr {
        self.to_bytes()
    }
}

#[test]
fn test_is_on_curve_var() {
    assert!(AffinePoint::identity().satisfies_curve_equation_vartime());
}

#[test]
fn test_d_is_non_quadratic_residue() {
    assert!(bool::from(EDWARDS_D.sqrt().is_none()));
    assert!(bool::from((-EDWARDS_D).sqrt().is_none()));
    assert!(bool::from((-EDWARDS_D).invert().unwrap().sqrt().is_none()));
}

#[test]
fn test_affine_niels_point_identity() {
    assert_eq!(
        AffineNielsPoint::identity().v_plus_u,
        AffinePoint::identity().to_niels().v_plus_u
    );
    assert_eq!(
        AffineNielsPoint::identity().v_minus_u,
        AffinePoint::identity().to_niels().v_minus_u
    );
    assert_eq!(
        AffineNielsPoint::identity().t2d,
        AffinePoint::identity().to_niels().t2d
    );
}

#[test]
fn test_extended_niels_point_identity() {
    assert_eq!(
        ExtendedNielsPoint::identity().v_plus_u,
        ExtendedPoint::identity().to_niels().v_plus_u
    );
    assert_eq!(
        ExtendedNielsPoint::identity().v_minus_u,
        ExtendedPoint::identity().to_niels().v_minus_u
    );
    assert_eq!(
        ExtendedNielsPoint::identity().z,
        ExtendedPoint::identity().to_niels().z
    );
    assert_eq!(
        ExtendedNielsPoint::identity().t2d,
        ExtendedPoint::identity().to_niels().t2d
    );
}

#[test]
fn test_assoc() {
    let point = ExtendedPoint::from(AffinePoint {
        u: Fq::from_raw([
            0x81c5_71e5_d883_cfb0,
            0x049f_7a68_6f14_7029,
            0xf539_c860_bc3e_a21f,
            0x4284_715b_7ccc_8162,
        ]),
        v: Fq::from_raw([
            0xbf09_6275_684b_b8ca,
            0xc7ba_2458_90af_256d,
            0x5911_9f3e_8638_0eb0,
            0x3793_de18_2f9f_b1d2,
        ]),
    })
    .mul_by_cofactor();
    assert!(point.satisfies_extended_curve_equation_vartime());

    assert_eq!(
        (point * Fr::from(1000u64)) * Fr::from(3938u64),
        point * (Fr::from(1000u64) * Fr::from(3938u64)),
    );
}

#[test]
fn test_batch_normalize() {
    let mut point = ExtendedPoint::from(AffinePoint {
        u: Fq::from_raw([
            0x81c5_71e5_d883_cfb0,
            0x049f_7a68_6f14_7029,
            0xf539_c860_bc3e_a21f,
            0x4284_715b_7ccc_8162,
        ]),
        v: Fq::from_raw([
            0xbf09_6275_684b_b8ca,
            0xc7ba_2458_90af_256d,
            0x5911_9f3e_8638_0eb0,
            0x3793_de18_2f9f_b1d2,
        ]),
    })
    .mul_by_cofactor();

    let mut points = vec![];
    for _ in 0..10 {
        points.push(point);
        point = point.double();
    }

    for point in &points {
        assert!(point.satisfies_extended_curve_equation_vartime());
    }

    let expected: std::vec::Vec<_> = points
        .iter()
        .map(|point| AffinePoint::from(*point))
        .collect();
    let mut normalized_points_0 = vec![AffinePoint::identity(); points.len()];
    ExtendedPoint::batch_normalize(&points, &mut normalized_points_0);
    for i in 0..10 {
        assert!(expected[i] == normalized_points_0[i]);
    }
    let normalized_points_1: std::vec::Vec<_> =
        batch_normalize(&mut points).collect();
    for i in 0..10 {
        assert!(expected[i] == normalized_points_1[i]);
        assert!(points[i].satisfies_extended_curve_equation_vartime());
        assert!(AffinePoint::from(points[i]) == expected[i]);
    }
    let normalized_points_2: std::vec::Vec<_> =
        batch_normalize(&mut points).collect();
    for i in 0..10 {
        assert!(expected[i] == normalized_points_2[i]);
        assert!(points[i].satisfies_extended_curve_equation_vartime());
        assert!(AffinePoint::from(points[i]) == expected[i]);
    }
}

#[cfg(test)]
const FULL_GENERATOR: AffinePoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0xe4b3_d35d_f1a7_adfe,
        0xcaf5_5d1b_29bf_81af,
        0x8b0f_03dd_d60a_8187,
        0x62ed_cbb8_bf37_87c8,
    ]),
    Fq::from_raw([0xb, 0x0, 0x0, 0x0]),
);

#[cfg(test)]
const EIGHT_TORSION: [AffinePoint; 8] = [
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0xd92e_6a79_2720_0d43,
            0x7aa4_1ac4_3dae_8582,
            0xeaaa_e086_a166_18d1,
            0x71d4_df38_ba9e_7973,
        ]),
        Fq::from_raw([
            0xff0d_2068_eff4_96dd,
            0x9106_ee90_f384_a4a1,
            0x16a1_3035_ad4d_7266,
            0x4958_bdb2_1966_982e,
        ]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0xfffe_ffff_0000_0001,
            0x67ba_a400_89fb_5bfe,
            0xa5e8_0b39_939e_d334,
            0x73ed_a753_299d_7d47,
        ]),
        Fq::from_raw([0x0, 0x0, 0x0, 0x0]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0xd92e_6a79_2720_0d43,
            0x7aa4_1ac4_3dae_8582,
            0xeaaa_e086_a166_18d1,
            0x71d4_df38_ba9e_7973,
        ]),
        Fq::from_raw([
            0x00f2_df96_100b_6924,
            0xc2b6_b572_0c79_b75d,
            0x1c98_a7d2_5c54_659e,
            0x2a94_e9a1_1036_e51a,
        ]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([0x0, 0x0, 0x0, 0x0]),
        Fq::from_raw([
            0xffff_ffff_0000_0000,
            0x53bd_a402_fffe_5bfe,
            0x3339_d808_09a1_d805,
            0x73ed_a753_299d_7d48,
        ]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0x26d1_9585_d8df_f2be,
            0xd919_893e_c24f_d67c,
            0x488e_f781_683b_bf33,
            0x0218_c81a_6eff_03d4,
        ]),
        Fq::from_raw([
            0x00f2_df96_100b_6924,
            0xc2b6_b572_0c79_b75d,
            0x1c98_a7d2_5c54_659e,
            0x2a94_e9a1_1036_e51a,
        ]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0x0001_0000_0000_0000,
            0xec03_0002_7603_0000,
            0x8d51_ccce_7603_04d0,
            0x0,
        ]),
        Fq::from_raw([0x0, 0x0, 0x0, 0x0]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([
            0x26d1_9585_d8df_f2be,
            0xd919_893e_c24f_d67c,
            0x488e_f781_683b_bf33,
            0x0218_c81a_6eff_03d4,
        ]),
        Fq::from_raw([
            0xff0d_2068_eff4_96dd,
            0x9106_ee90_f384_a4a1,
            0x16a1_3035_ad4d_7266,
            0x4958_bdb2_1966_982e,
        ]),
    ),
    AffinePoint::from_raw_unchecked(
        Fq::from_raw([0x0, 0x0, 0x0, 0x0]),
        Fq::from_raw([0x1, 0x0, 0x0, 0x0]),
    ),
];

#[test]
fn find_eight_torsion() {
    let full_generator = ExtendedPoint::from(FULL_GENERATOR);
    assert!(!bool::from(full_generator.is_small_order()));
    let torsion_generator = full_generator.multiply(&FR_MODULUS_BYTES);
    assert!(bool::from(torsion_generator.is_small_order()));

    let mut current_point = torsion_generator;

    for (i, point) in EIGHT_TORSION.iter().enumerate() {
        let affine_point = AffinePoint::from(current_point);
        if &affine_point != point {
            panic!("{}th torsion point should be {:?}", i, affine_point);
        }

        current_point += &torsion_generator;
    }
}

#[test]
fn find_curve_generator() {
    let mut trial_bytes = [0; 32];
    for _ in 0..255 {
        let maybe_affine = AffinePoint::from_bytes(trial_bytes);
        if bool::from(maybe_affine.is_some()) {
            let affine_point = maybe_affine.unwrap();
            assert!(affine_point.satisfies_curve_equation_vartime());
            let point = ExtendedPoint::from(affine_point);
            let point = point.multiply(&FR_MODULUS_BYTES);
            assert!(bool::from(point.is_small_order()));
            let point = point.double();
            assert!(bool::from(point.is_small_order()));
            let point = point.double();
            assert!(bool::from(point.is_small_order()));
            if !bool::from(point.is_identity()) {
                let point = point.double();
                assert!(bool::from(point.is_small_order()));
                assert!(bool::from(point.is_identity()));
                assert_eq!(FULL_GENERATOR, affine_point);
                assert_eq!(AffinePoint::generator(), affine_point);
                assert!(bool::from(
                    affine_point.mul_by_cofactor().is_torsion_free()
                ));
                return;
            }
        }

        trial_bytes[0] += 1;
    }

    panic!("should have found a generator of the curve");
}

#[test]
fn test_small_order() {
    for point in EIGHT_TORSION.iter() {
        assert!(bool::from(point.is_small_order()));
    }
}

#[test]
fn test_is_identity() {
    let first_torsion_point = EIGHT_TORSION[0].mul_by_cofactor();
    let second_torsion_point = EIGHT_TORSION[1].mul_by_cofactor();

    assert_eq!(first_torsion_point.u, second_torsion_point.u);
    assert_eq!(first_torsion_point.v, first_torsion_point.z);
    assert_eq!(second_torsion_point.v, second_torsion_point.z);
    assert!(first_torsion_point.v != second_torsion_point.v);
    assert!(first_torsion_point.z != second_torsion_point.z);

    assert!(bool::from(first_torsion_point.is_identity()));
    assert!(bool::from(second_torsion_point.is_identity()));

    for point in EIGHT_TORSION.iter() {
        assert!(bool::from(point.mul_by_cofactor().is_identity()));
    }
}

#[test]
fn test_mul_consistency() {
    let left_scalar = Fr([
        0x21e6_1211_d993_4f2e,
        0xa52c_058a_693c_3e07,
        0x9ccb_77bf_b12d_6360,
        0x07df_2470_ec94_398e,
    ]);
    let right_scalar = Fr([
        0x0333_6d1c_be19_dbe0,
        0x0153_618f_6156_a536,
        0x2604_c9e1_fc3c_6b15,
        0x04ae_581c_eb02_8720,
    ]);
    let product_scalar = Fr([
        0xd7ab_f5bb_2468_3f4c,
        0x9d77_12cc_274b_7c03,
        0x9732_93db_9683_789f,
        0x0b67_7e29_380a_97a7,
    ]);
    assert_eq!(left_scalar * right_scalar, product_scalar);
    let point = ExtendedPoint::from(AffinePoint {
        u: Fq::from_raw([
            0x81c5_71e5_d883_cfb0,
            0x049f_7a68_6f14_7029,
            0xf539_c860_bc3e_a21f,
            0x4284_715b_7ccc_8162,
        ]),
        v: Fq::from_raw([
            0xbf09_6275_684b_b8ca,
            0xc7ba_2458_90af_256d,
            0x5911_9f3e_8638_0eb0,
            0x3793_de18_2f9f_b1d2,
        ]),
    })
    .mul_by_cofactor();
    assert_eq!(point * product_scalar, (point * left_scalar) * right_scalar);

    assert_eq!(
        point * product_scalar,
        (point.to_niels() * left_scalar) * right_scalar
    );
    assert_eq!(
        point.to_niels() * product_scalar,
        (point * left_scalar) * right_scalar
    );
    assert_eq!(
        point.to_niels() * product_scalar,
        (point.to_niels() * left_scalar) * right_scalar
    );

    let point_affine_niels = AffinePoint::from(point).to_niels();
    assert_eq!(
        point * product_scalar,
        (point_affine_niels * left_scalar) * right_scalar
    );
    assert_eq!(
        point_affine_niels * product_scalar,
        (point * left_scalar) * right_scalar
    );
    assert_eq!(
        point_affine_niels * product_scalar,
        (point_affine_niels * left_scalar) * right_scalar
    );
}

#[cfg(feature = "alloc")]
#[test]
fn test_serialization_consistency() {
    let generator = FULL_GENERATOR.mul_by_cofactor();
    let mut current_point = generator;

    let expected_serializations = vec![
        [
            203, 85, 12, 213, 56, 234, 12, 193, 19, 132, 128, 64, 142, 110,
            170, 185, 179, 108, 97, 63, 13, 211, 247, 120, 79, 219, 110, 234,
            131, 123, 19, 215,
        ],
        [
            113, 154, 240, 230, 224, 198, 208, 170, 104, 15, 59, 126, 151, 222,
            233, 195, 203, 195, 167, 129, 89, 121, 240, 142, 51, 166, 64, 250,
            184, 202, 154, 177,
        ],
        [
            197, 41, 93, 209, 203, 55, 164, 174, 88, 0, 90, 199, 1, 156, 149,
            141, 240, 29, 14, 82, 86, 225, 126, 129, 186, 157, 148, 162, 219,
            51, 156, 199,
        ],
        [
            182, 117, 250, 241, 81, 196, 199, 227, 151, 74, 243, 17, 221, 97,
            200, 139, 192, 83, 231, 35, 214, 14, 95, 69, 130, 201, 4, 116, 177,
            19, 179, 0,
        ],
        [
            118, 41, 29, 200, 60, 189, 119, 252, 78, 40, 230, 18, 208, 221, 38,
            214, 176, 250, 4, 10, 77, 101, 26, 216, 193, 198, 226, 84, 25, 177,
            230, 185,
        ],
        [
            226, 189, 227, 208, 112, 117, 136, 98, 72, 38, 211, 167, 254, 82,
            174, 113, 112, 166, 138, 171, 166, 113, 52, 251, 129, 197, 138, 45,
            195, 7, 61, 140,
        ],
        [
            38, 198, 156, 196, 146, 225, 55, 163, 138, 178, 157, 128, 115, 135,
            204, 215, 0, 33, 171, 20, 60, 32, 142, 209, 33, 233, 125, 146, 207,
            12, 16, 24,
        ],
        [
            17, 187, 231, 83, 165, 36, 232, 184, 140, 205, 195, 252, 166, 85,
            59, 86, 3, 226, 211, 67, 179, 29, 238, 181, 102, 142, 58, 63, 57,
            89, 174, 138,
        ],
        [
            210, 159, 80, 16, 181, 39, 221, 204, 224, 144, 145, 79, 54, 231, 8,
            140, 142, 216, 93, 190, 183, 116, 174, 63, 33, 242, 177, 118, 148,
            40, 241, 203,
        ],
        [
            0, 143, 107, 102, 149, 187, 27, 124, 18, 10, 98, 28, 113, 123, 121,
            185, 29, 152, 14, 130, 149, 28, 87, 35, 135, 135, 153, 54, 112, 53,
            54, 68,
        ],
        [
            178, 131, 85, 160, 214, 51, 208, 157, 196, 152, 247, 93, 202, 56,
            81, 239, 155, 122, 59, 188, 237, 253, 11, 169, 208, 236, 12, 4,
            163, 211, 88, 97,
        ],
        [
            246, 194, 231, 195, 159, 101, 180, 133, 80, 21, 185, 220, 195, 115,
            144, 12, 90, 150, 44, 117, 8, 156, 168, 248, 206, 41, 60, 82, 67,
            75, 57, 67,
        ],
        [
            212, 205, 171, 153, 113, 16, 194, 241, 224, 43, 177, 110, 190, 248,
            22, 201, 208, 166, 2, 83, 134, 130, 85, 129, 166, 136, 185, 191,
            163, 38, 54, 10,
        ],
        [
            8, 60, 190, 39, 153, 222, 119, 23, 142, 237, 12, 110, 146, 9, 19,
            219, 143, 64, 161, 99, 199, 77, 39, 148, 70, 213, 246, 227, 150,
            178, 237, 178,
        ],
        [
            11, 114, 217, 160, 101, 37, 100, 220, 56, 114, 42, 31, 138, 33, 84,
            157, 214, 167, 73, 233, 115, 81, 124, 134, 15, 31, 181, 60, 184,
            130, 175, 159,
        ],
        [
            141, 238, 235, 202, 241, 32, 210, 10, 127, 230, 54, 31, 146, 80,
            247, 9, 107, 124, 0, 26, 203, 16, 237, 34, 214, 147, 133, 15, 29,
            236, 37, 88,
        ],
    ];

    let batched_points =
        AffinePoint::batch_from_bytes(expected_serializations.iter().cloned());

    for (expected_serialized, batch_deserialized) in expected_serializations
        .into_iter()
        .zip(batched_points.into_iter())
    {
        assert!(current_point.satisfies_extended_curve_equation_vartime());
        let affine_point = AffinePoint::from(current_point);
        let serialized_point = affine_point.to_bytes();
        let deserialized_point =
            AffinePoint::from_bytes(serialized_point).unwrap();
        assert_eq!(affine_point, deserialized_point);
        assert_eq!(affine_point, batch_deserialized.unwrap());
        assert_eq!(expected_serialized, serialized_point);
        current_point += generator;
    }
}

#[test]
fn test_zip_216() {
    const NON_CANONICAL_ENCODINGS: [[u8; 32]; 2] = [
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        ],
        [
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe,
            0xff, 0x02, 0xa4, 0xbd, 0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8,
            0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0xf3,
        ],
    ];

    for non_canonical_encoding in &NON_CANONICAL_ENCODINGS {
        {
            let mut canonicalized_encoding = *non_canonical_encoding;

            assert!(bool::from(
                AffinePoint::from_bytes(canonicalized_encoding).is_none()
            ));

            canonicalized_encoding[31] &= 0b0111_1111;
            assert!(bool::from(
                AffinePoint::from_bytes(canonicalized_encoding).is_some()
            ));
        }

        {
            let parsed = AffinePoint::from_bytes_pre_zip216_compatibility(
                *non_canonical_encoding,
            )
            .unwrap();
            let mut encoded = parsed.to_bytes();
            assert_ne!(non_canonical_encoding, &encoded);

            encoded[31] |= 0b1000_0000;
            assert_eq!(non_canonical_encoding, &encoded);
        }
    }
}
