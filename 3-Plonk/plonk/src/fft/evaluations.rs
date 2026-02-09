// 模块说明：本文件实现 PLONK 组件（src/fft/evaluations.rs）。

//

use super::domain::EvaluationDomain;
use super::polynomial::Polynomial;
use crate::error::Error;
use alloc::vec::Vec;
use core::ops::{
    Add, AddAssign, DivAssign, Index, Mul, MulAssign, Sub, SubAssign,
};
use coset_bls12_381::BlsScalar;
use coset_bytes::{DeserializableSlice, Serializable};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct Evaluations {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) evals: Vec<BlsScalar>,

    #[doc(hidden)]
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    domain: EvaluationDomain,
}

impl Evaluations {
    pub fn to_var_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.domain.to_bytes().to_vec();
        bytes.extend(
            self.evals
                .iter()
                .flat_map(|scalar| scalar.to_bytes().to_vec()),
        );

        bytes
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Evaluations, Error> {
        let mut buffer = bytes;
        let domain = EvaluationDomain::from_reader(&mut buffer)?;
        let evals = buffer
            .chunks(BlsScalar::SIZE)
            .map(BlsScalar::from_slice)
            .collect::<Result<Vec<BlsScalar>, coset_bytes::Error>>()?;
        Ok(Evaluations::from_vec_and_domain(evals, domain))
    }

    pub(crate) const fn from_vec_and_domain(
        evals: Vec<BlsScalar>,
        domain: EvaluationDomain,
    ) -> Self {
        Self { evals, domain }
    }

    pub(crate) fn interpolate(self) -> Polynomial {
        let Self { mut evals, domain } = self;
        domain.ifft_in_place(&mut evals);
        Polynomial::from_coefficients_vec(evals)
    }
}

impl Index<usize> for Evaluations {
    type Output = BlsScalar;

    fn index(&self, index: usize) -> &BlsScalar {
        &self.evals[index]
    }
}

impl<'a, 'b> Mul<&'a Evaluations> for &'b Evaluations {
    type Output = Evaluations;

    #[inline]
    fn mul(self, other: &'a Evaluations) -> Evaluations {
        let mut result = self.clone();
        result *= other;
        result
    }
}

impl<'a> MulAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn mul_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a *= b);
    }
}

impl<'a, 'b> Add<&'a Evaluations> for &'b Evaluations {
    type Output = Evaluations;

    #[inline]
    fn add(self, other: &'a Evaluations) -> Evaluations {
        let mut result = self.clone();
        result += other;
        result
    }
}

impl<'a> AddAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn add_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a += b);
    }
}

impl<'a, 'b> Sub<&'a Evaluations> for &'b Evaluations {
    type Output = Evaluations;

    #[inline]
    fn sub(self, other: &'a Evaluations) -> Evaluations {
        let mut result = self.clone();
        result -= other;
        result
    }
}

impl<'a> SubAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn sub_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a -= b);
    }
}

impl<'a> DivAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn div_assign(&mut self, other: &'a Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(a, b)| *a *= b.invert().unwrap());
    }
}
