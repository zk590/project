use alloc::vec::Vec;
use coset_bls12_381::{
    BlsScalar, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
#[inline(always)]
/// 在 `rkyv` 检查流程中验证结构体字段字节合法性。
/// 该函数为字段级检查失败补充字段名上下文，便于定位归档损坏位置。
/// 仅在启用 `rkyv-impl` 时使用，属于反序列化安全辅助工具。
pub unsafe fn check_field<F, C>(
    field: *const F,
    context: &mut C,
    field_name: &'static str,
) -> Result<(), bytecheck::StructCheckError>
where
    F: bytecheck::CheckBytes<C>,
{
    F::check_bytes(field, context).map_err(|e| {
        bytecheck::StructCheckError {
            field_name,
            inner: bytecheck::ErrorBox::new(e),
        }
    })?;
    Ok(())
}

/// 计算标量的幂次序列 `[1, s, s^2, ..., s^max_degree]`。
/// 该函数是多项式评估与批量聚合中常见的基础构件。
/// 结果向量长度固定为 `max_degree + 1`，便于按索引直接取幂次。
pub(crate) fn powers_of(
    scalar: &BlsScalar,
    max_degree: usize,
) -> Vec<BlsScalar> {
    let mut powers = Vec::with_capacity(max_degree + 1);
    powers.push(BlsScalar::one());
    for power_index in 1..=max_degree {
        powers.push(powers[power_index - 1] * scalar);
    }
    powers
}

/// 生成随机 `G1` 群元素。
/// 实现为“生成元 × 随机标量”，满足子群约束并保持实现简洁。
/// 该接口主要用于参数生成阶段采样随机基点。
pub(crate) fn random_g1_point<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> G1Projective {
    G1Affine::generator() * BlsScalar::random(rng)
}

/// 生成随机 `G2` 群元素。
/// 与 `random_g1_point` 对称，使用生成元乘随机标量方式构造。
/// 常用于 KZG opening key 的 `h` 相关参数初始化。
pub(crate) fn random_g2_point<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> G2Projective {
    G2Affine::generator() * BlsScalar::random(rng)
}

/// 对单一基点执行慢速多标量乘法。
/// 该实现逐项计算 `base * scalar_i`，主要用于参数生成等离线路径。
/// 相比专用 MSM 算法更直观，但在大规模输入下性能较低。
pub(crate) fn slow_multiscalar_mul_single_base(
    scalars: &[BlsScalar],
    base: G1Projective,
) -> Vec<G1Projective> {
    scalars.iter().map(|s| base * *s).collect()
}

use core::ops::MulAssign;

/// 对标量切片执行批量求逆。
/// 算法先累计前缀乘积，再仅做一次整体求逆并回填各元素逆值，复杂度线性。
/// 输入中的零元素会被跳过并保持不变，避免无逆元导致失败。
pub fn batch_inversion(scalars: &mut [BlsScalar]) {
    let mut prefix_products = Vec::with_capacity(scalars.len());
    let mut running_product = BlsScalar::one();
    for scalar in scalars
        .iter()
        .filter(|scalar| scalar != &&BlsScalar::zero())
    {
        running_product.mul_assign(scalar);
        prefix_products.push(running_product);
    }

    running_product = running_product.invert().unwrap();

    for (scalar, prefix_product) in scalars
        .iter_mut()
        .rev()
        .filter(|scalar| scalar != &&BlsScalar::zero())
        .zip(
            prefix_products
                .into_iter()
                .rev()
                .skip(1)
                .chain(Some(BlsScalar::one())),
        )
    {
        let next_running_product = running_product * *scalar;
        *scalar = running_product * prefix_product;
        running_product = next_running_product;
    }
}
#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_batch_inversion() {
        let one = BlsScalar::from(1);
        let two = BlsScalar::from(2);
        let three = BlsScalar::from(3);
        let four = BlsScalar::from(4);
        let five = BlsScalar::from(5);

        let original_scalars = vec![one, two, three, four, five];
        let mut inverted_scalars = vec![one, two, three, four, five];

        batch_inversion(&mut inverted_scalars);
        for (scalar, scalar_inverse) in
            original_scalars.iter().zip(inverted_scalars.iter())
        {
            assert_eq!(scalar.invert().unwrap(), *scalar_inverse);
        }
    }
}
