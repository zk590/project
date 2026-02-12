use super::{EvaluationDomain, Evaluations};
use crate::error::Error;
use crate::util;
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Deref, DerefMut, Mul, Neg, Sub, SubAssign};
use coset_bls12_381::BlsScalar;
use coset_bytes::{DeserializableSlice, Serializable};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct Polynomial {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    coeffs: Vec<BlsScalar>,
}

impl Deref for Polynomial {
    type Target = [BlsScalar];

    fn deref(&self) -> &[BlsScalar] {
        &self.coeffs
    }
}

impl DerefMut for Polynomial {
    fn deref_mut(&mut self) -> &mut [BlsScalar] {
        &mut self.coeffs
    }
}

impl IntoIterator for Polynomial {
    type Item = BlsScalar;
    type IntoIter = <Vec<BlsScalar> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.coeffs.into_iter()
    }
}

impl Polynomial {
    /// 构造零多项式。
    /// 零多项式以空系数向量表示，便于后续操作快速判零。
    /// 该表示约定在本模块内保持一致。
    pub(crate) const fn zero() -> Self {
        Self { coeffs: Vec::new() }
    }

    /// 判断当前多项式是否为零多项式。
    /// 除空向量外，也兼容“全零系数但未截断”的输入形式。
    /// 该检查被度数、加减法等逻辑复用。
    pub(crate) fn is_zero(&self) -> bool {
        self.coeffs.is_empty()
            || self.coeffs.iter().all(|coeff| coeff == &BlsScalar::zero())
    }

    /// 由系数向量构造多项式并裁剪高位零系数。
    /// 规范化步骤保证最高位非零（或为空），减少后续度数判断分支。
    /// 该函数是外部输入进入多项式表示的主要入口。
    pub(crate) fn from_coefficients_vec(coeffs: Vec<BlsScalar>) -> Self {
        let mut result = Self { coeffs };

        result.truncate_leading_zeros();

        assert!(result
            .coeffs
            .last()
            .map_or(true, |coeff| coeff != &BlsScalar::zero()));

        result
    }

    /// 返回多项式度数。
    /// 对零多项式约定返回 0，以简化上层边界处理。
    /// 计算会从高位向低位扫描第一个非零系数位置。
    pub(crate) fn degree(&self) -> usize {
        match self.is_zero() {
            true => 0,
            false => {
                let len = self.len();
                for reverse_offset in 0..len {
                    let index = len - 1 - reverse_offset;
                    if self[index] != BlsScalar::zero() {
                        return index;
                    }
                }
                0
            }
        }
    }

    /// 移除末尾连续零系数。
    /// 该规范化过程避免“语义等价但表示不同”的多项式状态。
    /// 在序列化、比较与算术操作后通常需要调用。
    fn truncate_leading_zeros(&mut self) {
        while self
            .coeffs
            .last()
            .map_or(false, |coefficient| coefficient == &BlsScalar::zero())
        {
            self.coeffs.pop();
        }
    }

    /// 在给定点上评估多项式值。
    /// 实现通过预计算幂次并逐项累加完成，保持语义直观。
    /// 对零多项式会直接返回 0。
    pub(crate) fn evaluate(&self, value: &BlsScalar) -> BlsScalar {
        if self.is_zero() {
            return BlsScalar::zero();
        }

        let power_terms = util::powers_of(value, self.len());
        let scaled_coefficients = self
            .iter()
            .zip(power_terms)
            .map(|(coefficient, power)| power * coefficient);

        let mut sum = BlsScalar::zero();
        for scaled_coefficient in scaled_coefficients {
            sum += &scaled_coefficient;
        }
        sum
    }

    /// 将多项式编码为可变长字节（截断到实际度数）。
    /// 输出仅包含 `0..=degree` 的有效系数，避免冗余尾部零值。
    /// 该格式与 `from_slice` 对应，适合轻量持久化。
    pub fn to_var_bytes(&self) -> Vec<u8> {
        let degree = self.degree();
        self.coeffs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i <= degree)
            .flat_map(|(_, item)| item.to_bytes().to_vec())
            .collect()
    }

    /// 从字节切片恢复多项式。
    /// 按标量大小分块解析系数并在末尾执行零裁剪规范化。
    /// 任意系数字节非法会返回错误。
    pub fn from_slice(bytes: &[u8]) -> Result<Polynomial, Error> {
        let coeffs = bytes
            .chunks(BlsScalar::SIZE)
            .map(BlsScalar::from_slice)
            .collect::<Result<Vec<BlsScalar>, coset_bytes::Error>>()?;

        let mut polynomial = Polynomial { coeffs };

        polynomial.truncate_leading_zeros();

        Ok(polynomial)
    }

    /// 返回内部系数迭代器。
    /// 该辅助接口用于模块内通用迭代场景，避免直接暴露底层容器。
    /// 迭代顺序为低阶到高阶系数顺序。
    fn iter(&self) -> impl Iterator<Item = &BlsScalar> {
        self.coeffs.iter()
    }
}

use core::iter::Sum;

impl Sum for Polynomial {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        let sum: Polynomial =
            iter.fold(Polynomial::zero(), |mut accumulator, polynomial| {
                accumulator = &accumulator + &polynomial;
                accumulator
            });
        sum
    }
}

impl<'a, 'b> Add<&'a Polynomial> for &'b Polynomial {
    type Output = Polynomial;

    fn add(self, other: &'a Polynomial) -> Polynomial {
        let mut result = if self.is_zero() {
            other.clone()
        } else if other.is_zero() {
            self.clone()
        } else if self.degree() >= other.degree() {
            let mut result = self.clone();
            for (result_coefficient, other_coefficient) in
                result.coeffs.iter_mut().zip(&other.coeffs)
            {
                *result_coefficient += other_coefficient
            }
            result
        } else {
            let mut result = other.clone();
            for (result_coefficient, self_coefficient) in
                result.coeffs.iter_mut().zip(&self.coeffs)
            {
                *result_coefficient += self_coefficient
            }
            result
        };

        result.truncate_leading_zeros();
        result
    }
}

impl<'a> AddAssign<&'a Polynomial> for Polynomial {
    fn add_assign(&mut self, other: &'a Polynomial) {
        if self.is_zero() {
            self.coeffs.truncate(0);
            self.coeffs.extend_from_slice(&other.coeffs);
        } else if other.is_zero() {
        } else if self.degree() >= other.degree() {
            for (self_coefficient, other_coefficient) in
                self.coeffs.iter_mut().zip(&other.coeffs)
            {
                *self_coefficient += other_coefficient
            }
        } else {
            self.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            for (self_coefficient, other_coefficient) in
                self.coeffs.iter_mut().zip(&other.coeffs)
            {
                *self_coefficient += other_coefficient
            }
        }

        self.truncate_leading_zeros();
    }
}

impl<'a> AddAssign<(BlsScalar, &'a Polynomial)> for Polynomial {
    fn add_assign(&mut self, (factor, other): (BlsScalar, &'a Polynomial)) {
        if self.is_zero() {
            self.coeffs.truncate(0);
            self.coeffs.extend_from_slice(&other.coeffs);
            self.coeffs
                .iter_mut()
                .for_each(|coefficient| *coefficient *= &factor);
        } else if other.is_zero() {
        } else if self.degree() >= other.degree() {
            for (self_coefficient, other_coefficient) in
                self.coeffs.iter_mut().zip(&other.coeffs)
            {
                *self_coefficient += &(factor * other_coefficient);
            }
        } else {
            self.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            for (self_coefficient, other_coefficient) in
                self.coeffs.iter_mut().zip(&other.coeffs)
            {
                *self_coefficient += &(factor * other_coefficient);
            }
        }

        self.truncate_leading_zeros();
    }
}

impl Neg for Polynomial {
    type Output = Polynomial;

    #[inline]
    fn neg(mut self) -> Polynomial {
        for coeff in &mut self.coeffs {
            *coeff = -*coeff;
        }
        self
    }
}

impl<'a, 'b> Sub<&'a Polynomial> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn sub(self, other: &'a Polynomial) -> Polynomial {
        let mut result = if self.is_zero() {
            let mut result = other.clone();
            for coeff in &mut result.coeffs {
                *coeff = -(*coeff);
            }
            result
        } else if other.is_zero() {
            self.clone()
        } else if self.degree() >= other.degree() {
            let mut result = self.clone();
            for (result_coefficient, other_coefficient) in
                result.coeffs.iter_mut().zip(&other.coeffs)
            {
                *result_coefficient -= other_coefficient
            }
            result
        } else {
            let mut result = self.clone();
            result.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            for (result_coefficient, other_coefficient) in
                result.coeffs.iter_mut().zip(&other.coeffs)
            {
                *result_coefficient -= other_coefficient;
            }
            result
        };

        result.truncate_leading_zeros();
        result
    }
}

impl<'a> SubAssign<&'a Polynomial> for Polynomial {
    #[inline]
    fn sub_assign(&mut self, other: &'a Polynomial) {
        if self.is_zero() {
            self.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            for (coefficient_index, coefficient) in
                other.coeffs.iter().enumerate()
            {
                self.coeffs[coefficient_index] -= coefficient;
            }
        } else if other.is_zero() {
        } else if self.degree() >= other.degree() {
            for (self_coefficient, other_coefficient) in
                self.coeffs.iter_mut().zip(&other.coeffs)
            {
                *self_coefficient -= other_coefficient
            }
        } else {
            self.coeffs.resize(other.coeffs.len(), BlsScalar::zero());
            for (self_coefficient, other_coefficient) in
                self.coeffs.iter_mut().zip(&other.coeffs)
            {
                *self_coefficient -= other_coefficient
            }
        }

        self.truncate_leading_zeros();
    }
}

impl Polynomial {
    #[allow(dead_code)]
    #[inline]
    fn leading_coefficient(&self) -> Option<&BlsScalar> {
        match self.is_zero() {
            true => None,
            false => Some(&self[self.degree()]),
        }
    }

    #[allow(dead_code)]
    #[inline]
    fn iter_with_index(&self) -> Vec<(usize, BlsScalar)> {
        self.iter().cloned().enumerate().collect()
    }

    /// 执行 Ruffini 除法，计算 `self / (x - divisor_root)` 的商多项式。
    /// 算法按高次到低次递推，时间复杂度线性于系数长度。
    /// 该函数常用于构造 KZG witness 多项式。
    pub fn ruffini(&self, divisor_root: BlsScalar) -> Polynomial {
        let mut quotient: Vec<BlsScalar> = Vec::with_capacity(self.degree());
        let mut running_term = BlsScalar::zero();

        for coefficient in self.coeffs.iter().rev() {
            let updated_coefficient = coefficient + running_term;
            quotient.push(updated_coefficient);
            running_term = divisor_root * updated_coefficient;
        }

        quotient.pop();

        quotient.reverse();
        Polynomial::from_coefficients_vec(quotient)
    }
}

impl<'a, 'b> Mul<&'a Polynomial> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn mul(self, other: &'a Polynomial) -> Polynomial {
        if self.is_zero() || other.is_zero() {
            Polynomial::zero()
        } else {
            let domain =
                EvaluationDomain::new(self.coeffs.len() + other.coeffs.len())
                    .expect("field is not smooth enough to construct domain");
            let mut self_evals = Evaluations::from_vec_and_domain(
                domain.fft(&self.coeffs),
                domain,
            );
            let other_evals = Evaluations::from_vec_and_domain(
                domain.fft(&other.coeffs),
                domain,
            );
            self_evals *= &other_evals;
            self_evals.interpolate()
        }
    }
}

impl<'a, 'b> Mul<&'a BlsScalar> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn mul(self, constant: &'a BlsScalar) -> Polynomial {
        if self.is_zero() || (constant == &BlsScalar::zero()) {
            return Polynomial::zero();
        }
        let scaled_coeffs: Vec<_> =
            self.coeffs.iter().map(|coeff| coeff * constant).collect();
        Polynomial::from_coefficients_vec(scaled_coeffs)
    }
}

impl<'a, 'b> Add<&'a BlsScalar> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn add(self, constant: &'a BlsScalar) -> Polynomial {
        if self.is_zero() {
            return Polynomial::from_coefficients_vec(vec![*constant]);
        }
        let mut shifted_polynomial = self.clone();
        if constant == &BlsScalar::zero() {
            return shifted_polynomial;
        }

        shifted_polynomial[0] += constant;
        shifted_polynomial
    }
}

impl<'a, 'b> Sub<&'a BlsScalar> for &'b Polynomial {
    type Output = Polynomial;

    #[inline]
    fn sub(self, constant: &'a BlsScalar) -> Polynomial {
        let negated_constant = -constant;
        self + &negated_constant
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use ff::Field;
    use rand::rngs::StdRng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};

    impl Polynomial {
        pub(crate) fn rand<R: RngCore + CryptoRng>(
            degree: usize,
            mut rng: &mut R,
        ) -> Self {
            let mut random_coeffs = Vec::with_capacity(degree + 1);
            for _ in 0..=degree {
                random_coeffs.push(BlsScalar::random(&mut rng));
            }
            Self::from_coefficients_vec(random_coeffs)
        }

        fn add_zero_coefficient(&mut self) {
            self.coeffs.push(BlsScalar::zero())
        }
    }

    #[test]
    fn test_ruffini() {
        let quadratic = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(4),
            BlsScalar::from(4),
            BlsScalar::one(),
        ]);

        let quotient = quadratic.ruffini(-BlsScalar::from(2));

        let expected_quotient = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(2),
            BlsScalar::one(),
        ]);
        assert_eq!(quotient, expected_quotient);
    }

    #[test]
    fn test_ruffini_zero() {
        // (1)

        let zero = Polynomial::zero();

        let quotient = zero.ruffini(-BlsScalar::from(2));
        assert_eq!(quotient, Polynomial::zero());

        // (2)

        let polynomial = Polynomial::from_coefficients_vec(vec![
            BlsScalar::zero(),
            BlsScalar::one(),
            BlsScalar::one(),
        ]);

        let quotient = polynomial.ruffini(BlsScalar::zero());

        let expected_quotient = Polynomial::from_coefficients_vec(vec![
            BlsScalar::one(),
            BlsScalar::one(),
        ]);
        assert_eq!(quotient, expected_quotient);
    }

    #[test]
    fn test_degree() {
        let mut polynomial = Polynomial::from_coefficients_vec(vec![
            BlsScalar::one(),
            BlsScalar::from(2),
        ]);
        polynomial.add_zero_coefficient();
        polynomial.add_zero_coefficient();
        polynomial.add_zero_coefficient();

        assert_eq!(polynomial.degree(), 1);
    }

    #[test]
    fn test_leading_coeff() {
        let mut polynomial = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(0),
            BlsScalar::from(1),
            BlsScalar::from(2),
        ]);
        polynomial.add_zero_coefficient();
        polynomial.add_zero_coefficient();
        assert_eq!(
            *polynomial.leading_coefficient().unwrap(),
            BlsScalar::from(2)
        );
    }

    #[test]
    fn test_serialization() {
        let mut rng = StdRng::seed_from_u64(0xfeed);
        let degree = 5;
        let mut polynomial = Polynomial::rand(degree, &mut rng);

        assert_eq!(
            polynomial,
            Polynomial::from_slice(&polynomial.to_var_bytes()[..])
                .expect("(De-)Serialization should succeed")
        );

        polynomial.add_zero_coefficient();
        assert_eq!(polynomial.coeffs[degree + 1], BlsScalar::zero());
        polynomial.add_zero_coefficient();
        assert_eq!(polynomial.coeffs[degree + 2], BlsScalar::zero());
        let mut polynomial_bytes = polynomial.to_var_bytes();
        assert_eq!(polynomial_bytes.len(), (degree + 1) * BlsScalar::SIZE,);

        for _ in 0..BlsScalar::SIZE {
            polynomial_bytes.push(0);
        }
        let deserialized_polynomial =
            Polynomial::from_slice(&polynomial_bytes[..])
                .expect("Deserialization should succeed");
        polynomial.truncate_leading_zeros();
        assert_eq!(polynomial, deserialized_polynomial);
    }

    #[test]
    fn test_add_assign() {
        let mut polynomial_a = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(21),
            BlsScalar::from(4),
            BlsScalar::zero(),
            BlsScalar::from(1),
        ]);
        let polynomial_b = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(21),
            -BlsScalar::from(4),
            BlsScalar::zero(),
            -BlsScalar::from(1),
        ]);

        polynomial_a += &polynomial_b;

        assert_eq!(
            polynomial_a.leading_coefficient(),
            Some(&BlsScalar::from(42))
        );
        assert_eq!(
            polynomial_a,
            Polynomial::from_coefficients_vec(vec![BlsScalar::from(42)])
        );
    }

    #[test]
    fn test_sub_assign() {
        let mut polynomial_a = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(21),
            BlsScalar::from(4),
            BlsScalar::zero(),
            BlsScalar::from(1),
        ]);
        let polynomial_b = Polynomial::from_coefficients_vec(vec![
            -BlsScalar::from(21),
            BlsScalar::from(4),
            BlsScalar::zero(),
            BlsScalar::from(1),
        ]);

        polynomial_a -= &polynomial_b;

        assert_eq!(
            polynomial_a.leading_coefficient(),
            Some(&BlsScalar::from(42))
        );
        assert_eq!(
            polynomial_a,
            Polynomial::from_coefficients_vec(vec![BlsScalar::from(42)])
        );
    }

    #[test]
    fn test_mul_poly() {
        let polynomial = Polynomial::from_coefficients_vec(vec![
            BlsScalar::one(),
            -BlsScalar::one(),
        ]);
        let result = &polynomial * &polynomial;

        let expected = Polynomial::from_coefficients_vec(vec![
            BlsScalar::one(),
            -BlsScalar::from(2),
            BlsScalar::one(),
        ]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_mul_scalar() {
        let polynomial = Polynomial::from_coefficients_vec(vec![
            BlsScalar::one(),
            -BlsScalar::one(),
        ]);
        let scalar = BlsScalar::from(2);
        let result = &polynomial * &scalar;

        let expected = Polynomial::from_coefficients_vec(vec![
            BlsScalar::from(2),
            -BlsScalar::from(2),
        ]);
        assert_eq!(result, expected);
    }
}
