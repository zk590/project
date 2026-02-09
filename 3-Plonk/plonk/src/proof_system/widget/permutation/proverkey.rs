// 模块说明：本文件实现 PLONK
// 组件（src/proof_system/widget/permutation/proverkey.rs）。

//

use crate::composer::permutation::constants::{K1, K2, K3};
use crate::fft::{EvaluationDomain, Evaluations, Polynomial};
use coset_bls12_381::BlsScalar;

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
pub(crate) struct ProverKey {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_1: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_2: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_3: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_4: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) linear_evaluations: Evaluations,
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        a_i: &BlsScalar,
        b_i: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        z_i: &BlsScalar,
        z_i_w: &BlsScalar,
        alpha: &BlsScalar,
        l1_alpha_sq: &BlsScalar,
        beta: &BlsScalar,
        gamma: &BlsScalar,
    ) -> BlsScalar {
        let identity_term = self.compute_quotient_identity_range_check_i(
            index, a_i, b_i, c_i, d_i, z_i, alpha, beta, gamma,
        );
        let copy_term = self.compute_quotient_copy_range_check_i(
            index, a_i, b_i, c_i, d_i, z_i_w, alpha, beta, gamma,
        );
        let one_check_term =
            self.compute_quotient_term_check_one_i(z_i, l1_alpha_sq);
        identity_term + copy_term + one_check_term
    }

    fn compute_quotient_identity_range_check_i(
        &self,
        index: usize,
        a_i: &BlsScalar,
        b_i: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        z_i: &BlsScalar,
        alpha: &BlsScalar,
        beta: &BlsScalar,
        gamma: &BlsScalar,
    ) -> BlsScalar {
        let domain_point = self.linear_evaluations[index];

        (a_i + (beta * domain_point) + gamma)
            * (b_i + (beta * K1 * domain_point) + gamma)
            * (c_i + (beta * K2 * domain_point) + gamma)
            * (d_i + (beta * K3 * domain_point) + gamma)
            * z_i
            * alpha
    }

    fn compute_quotient_copy_range_check_i(
        &self,
        index: usize,
        a_i: &BlsScalar,
        b_i: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        z_i_w: &BlsScalar,
        alpha: &BlsScalar,
        beta: &BlsScalar,
        gamma: &BlsScalar,
    ) -> BlsScalar {
        let s_sigma_1_eval = self.s_sigma_1.1[index];
        let s_sigma_2_eval = self.s_sigma_2.1[index];
        let s_sigma_3_eval = self.s_sigma_3.1[index];
        let s_sigma_4_eval = self.s_sigma_4.1[index];

        let product = (a_i + (beta * s_sigma_1_eval) + gamma)
            * (b_i + (beta * s_sigma_2_eval) + gamma)
            * (c_i + (beta * s_sigma_3_eval) + gamma)
            * (d_i + (beta * s_sigma_4_eval) + gamma)
            * z_i_w
            * alpha;

        -product
    }

    fn compute_quotient_term_check_one_i(
        &self,
        z_i: &BlsScalar,
        l1_alpha_sq: &BlsScalar,
    ) -> BlsScalar {
        (z_i - BlsScalar::one()) * l1_alpha_sq
    }

    pub(crate) fn compute_linearization(
        &self,
        z_challenge: &BlsScalar,
        (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
        (a_eval, b_eval, c_eval, d_eval): (
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
        ),
        (sigma_1_eval, sigma_2_eval, sigma_3_eval): (
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
        ),
        z_eval: &BlsScalar,
        z_poly: &Polynomial,
    ) -> Polynomial {
        let identity_linearization = self
            .compute_linearizer_identity_range_check(
                (a_eval, b_eval, c_eval, d_eval),
                z_challenge,
                (alpha, beta, gamma),
                z_poly,
            );
        let copy_linearization = self.compute_linearizer_copy_range_check(
            (a_eval, b_eval, c_eval),
            z_eval,
            sigma_1_eval,
            sigma_2_eval,
            sigma_3_eval,
            (alpha, beta, gamma),
            &self.s_sigma_4.0,
        );

        let domain = EvaluationDomain::new(z_poly.degree() - 2).unwrap();
        let one_check_linearization = self.compute_linearizer_check_is_one(
            &domain,
            z_challenge,
            &alpha.square(),
            z_poly,
        );
        &(&identity_linearization + &copy_linearization)
            + &one_check_linearization
    }

    fn compute_linearizer_identity_range_check(
        &self,
        (a_eval, b_eval, c_eval, d_eval): (
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
            &BlsScalar,
        ),
        z_challenge: &BlsScalar,
        (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
        z_poly: &Polynomial,
    ) -> Polynomial {
        let beta_z = beta * z_challenge;

        let mut a_term = a_eval + beta_z;
        a_term += gamma;

        let beta_z_k1 = K1 * beta_z;
        let mut b_term = b_eval + beta_z_k1;
        b_term += gamma;

        let beta_z_k2 = K2 * beta_z;
        let mut c_term = c_eval + beta_z_k2;
        c_term += gamma;

        let beta_z_k3 = K3 * beta_z;
        let mut d_term = d_eval + beta_z_k3;
        d_term += gamma;

        let mut accumulator = a_term * b_term;
        accumulator *= c_term;
        accumulator *= d_term;
        accumulator *= alpha;

        z_poly * &accumulator
    }

    fn compute_linearizer_copy_range_check(
        &self,
        (a_eval, b_eval, c_eval): (&BlsScalar, &BlsScalar, &BlsScalar),
        z_eval: &BlsScalar,
        sigma_1_eval: &BlsScalar,
        sigma_2_eval: &BlsScalar,
        sigma_3_eval: &BlsScalar,
        (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
        s_sigma_4_poly: &Polynomial,
    ) -> Polynomial {
        let beta_sigma_1 = beta * sigma_1_eval;
        let mut a_term = a_eval + beta_sigma_1;
        a_term += gamma;

        let beta_sigma_2 = beta * sigma_2_eval;
        let mut b_term = b_eval + beta_sigma_2;
        b_term += gamma;

        let beta_sigma_3 = beta * sigma_3_eval;
        let mut c_term = c_eval + beta_sigma_3;
        c_term += gamma;

        let beta_z_eval = beta * z_eval;

        let mut accumulator = a_term * b_term * c_term;
        accumulator *= beta_z_eval;
        accumulator *= alpha;

        s_sigma_4_poly * &-accumulator
    }

    fn compute_linearizer_check_is_one(
        &self,
        domain: &EvaluationDomain,
        z_challenge: &BlsScalar,
        alpha_sq: &BlsScalar,
        z_coeffs: &Polynomial,
    ) -> Polynomial {
        let l_1_z = domain.evaluate_all_lagrange_coefficients(*z_challenge)[0];

        z_coeffs * &(l_1_z * alpha_sq)
    }
}
