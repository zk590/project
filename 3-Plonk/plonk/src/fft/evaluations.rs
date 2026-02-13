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
    /// 将评估表编码为可变长字节。
    /// 输出以域参数开头，后续按顺序追加每个评估点的字段字节表示。
    /// 该格式与 `from_slice` 对应，用于缓存评估结果与跨模块传递。
    pub fn to_var_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.domain.to_bytes().to_vec();
        bytes.extend(
            self.evals
                .iter()
                .flat_map(|scalar| scalar.to_bytes().to_vec()),
        );

        bytes
    }

    /// 从字节切片恢复评估表。
    /// 先解析域参数，再按标量大小分块还原评估值向量。
    /// 若任一标量解析失败则返回错误，避免使用损坏评估数据。
    pub fn from_slice(bytes: &[u8]) -> Result<Evaluations, Error> {
        let mut remaining_bytes = bytes;
        let domain = EvaluationDomain::from_reader(&mut remaining_bytes)?;
        let evals = remaining_bytes
            .chunks(BlsScalar::SIZE)
            .map(BlsScalar::from_slice)
            .collect::<Result<Vec<BlsScalar>, coset_bytes::Error>>()?;
        Ok(Evaluations::from_vec_and_domain(evals, domain))
    }

    /// 由评估值向量与域参数构造评估对象。
    /// 该构造不做额外校验，调用方需保证向量长度与域规模语义匹配。
    /// 常用于 FFT 结果封装或反序列化后的结构重建。
    pub(crate) const fn from_vec_and_domain(
        evals: Vec<BlsScalar>,
        domain: EvaluationDomain,
    ) -> Self {
        Self { evals, domain }
    }

    /// 将评估表插值回系数多项式。
    /// 本质上是对评估值执行域上的 IFFT，再封装为 `Polynomial`。
    /// 该操作会消耗 `self`，避免额外克隆评估向量。
    pub(crate) fn interpolate(self) -> Polynomial {
        let Self { mut evals, domain } = self;
        domain.ifft_in_place(&mut evals);
        Polynomial::from_coefficients_vec(evals)
    }

    /// 断言两个评估表使用同一域。
    /// 点值运算必须在相同采样域上逐点执行，否则结果无数学意义。
    #[inline]
    fn assert_same_domain(&self, other: &Evaluations) {
        assert_eq!(self.domain, other.domain, "domains are unequal");
    }

    /// 对两个评估表执行逐点就地更新。
    /// 该辅助函数统一了加/减/乘/除的公共迭代模板，减少重复代码。
    #[inline]
    fn apply_pointwise_assign<F>(&mut self, other: &Evaluations, mut op: F)
    where
        F: FnMut(&mut BlsScalar, &BlsScalar),
    {
        self.assert_same_domain(other);
        self.evals
            .iter_mut()
            .zip(&other.evals)
            .for_each(|(self_value, other_value)| op(self_value, other_value));
    }
}

impl Index<usize> for Evaluations {
    type Output = BlsScalar;

    /// 按索引读取评估值。
    /// 返回引用避免拷贝，便于在约束计算中高频访问。
    /// 越界时行为与切片一致，会触发 panic。
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
        self.apply_pointwise_assign(other, |self_value, other_value| {
            *self_value *= other_value;
        });
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
        self.apply_pointwise_assign(other, |self_value, other_value| {
            *self_value += other_value;
        });
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
        self.apply_pointwise_assign(other, |self_value, other_value| {
            *self_value -= other_value;
        });
    }
}

impl<'a> DivAssign<&'a Evaluations> for Evaluations {
    #[inline]
    fn div_assign(&mut self, other: &'a Evaluations) {
        self.apply_pointwise_assign(other, |self_value, other_value| {
            *self_value *= other_value.invert().unwrap();
        });
    }
}
