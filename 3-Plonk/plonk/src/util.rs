// 模块说明：本文件实现 PLONK 组件（src/util.rs）。

//

use alloc::vec::Vec;
use coset_bls12_381::{
    BlsScalar, G1Affine, G1Projective, G2Affine, G2Projective,
};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
#[inline(always)]
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

pub(crate) fn powers_of(
    scalar: &BlsScalar,
    max_degree: usize,
) -> Vec<BlsScalar> {
    let mut powers = Vec::with_capacity(max_degree + 1);
    powers.push(BlsScalar::one());
    for i in 1..=max_degree {
        powers.push(powers[i - 1] * scalar);
    }
    powers
}

pub(crate) fn random_g1_point<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> G1Projective {
    G1Affine::generator() * BlsScalar::random(rng)
}

pub(crate) fn random_g2_point<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> G2Projective {
    G2Affine::generator() * BlsScalar::random(rng)
}

pub(crate) fn slow_multiscalar_mul_single_base(
    scalars: &[BlsScalar],
    base: G1Projective,
) -> Vec<G1Projective> {
    scalars.iter().map(|s| base * *s).collect()
}

use core::ops::MulAssign;

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
        for (x, x_inv) in original_scalars.iter().zip(inverted_scalars.iter()) {
            assert_eq!(x.invert().unwrap(), *x_inv);
        }
    }
}
