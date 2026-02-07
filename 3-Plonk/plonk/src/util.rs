// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

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

/// Returns a vector of BlsScalars of increasing powers of x from x^0 to x^d.
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

/// Generates a random G1 Point using an RNG seed.
pub(crate) fn random_g1_point<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> G1Projective {
    G1Affine::generator() * BlsScalar::random(rng)
}
/// Generates a random G2 point using an RNG seed.
pub(crate) fn random_g2_point<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> G2Projective {
    G2Affine::generator() * BlsScalar::random(rng)
}

/// This function is only used to generate the SRS.
/// The intention is just to compute the resulting points
/// of the operation `a*P, b*P, c*P ... (n-1)*P` into a `Vec`.
pub(crate) fn slow_multiscalar_mul_single_base(
    scalars: &[BlsScalar],
    base: G1Projective,
) -> Vec<G1Projective> {
    scalars.iter().map(|s| base * *s).collect()
}

// while we do not have batch inversion for scalars
use core::ops::MulAssign;

pub fn batch_inversion(scalars: &mut [BlsScalar]) {
    // Montgomery’s Trick and Fast Implementation of Masked AES
    // Genelle, Prouff and Quisquater
    // Section 3.2

    // First pass: compute [a, ab, abc, ...]
    let mut prefix_products = Vec::with_capacity(scalars.len());
    let mut running_product = BlsScalar::one();
    for scalar in scalars.iter().filter(|scalar| scalar != &&BlsScalar::zero()) {
        running_product.mul_assign(scalar);
        prefix_products.push(running_product);
    }

    // Invert the accumulated product.
    running_product = running_product.invert().unwrap(); // Guaranteed to be nonzero.

    // Second pass: iterate backwards to compute inverses
    for (scalar, prefix_product) in scalars
        .iter_mut()
        // Backwards
        .rev()
        // Ignore normalized elements
        .filter(|scalar| scalar != &&BlsScalar::zero())
        // Backwards, skip last element, fill in one for last term.
        .zip(
            prefix_products
                .into_iter()
                .rev()
                .skip(1)
                .chain(Some(BlsScalar::one())),
        )
    {
        // running_product := running_product * scalar; scalar := running_product * prefix_product = 1/scalar
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
