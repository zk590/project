// 模块说明：本文件实现 PLONK
// 组件（src/proof_system/widget/permutation/verifierkey.rs）。

//

use crate::commitment_scheme::Commitment;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct VerifierKey {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_1: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_2: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_3: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_4: Commitment,
}

#[cfg(feature = "alloc")]
mod alloc {
    use super::*;
    use crate::composer::permutation::constants::{K1, K2, K3};
    use crate::proof_system::linearization_poly::ProofEvaluations;
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use coset_bls12_381::{BlsScalar, G1Affine};

    impl VerifierKey {
        pub(crate) fn compute_linearization_commitment(
            &self,
            scalars: &mut Vec<BlsScalar>,
            points: &mut Vec<G1Affine>,
            evaluations: &ProofEvaluations,
            z_challenge: &BlsScalar,
            u_challenge: &BlsScalar,
            (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
            l1_eval: &BlsScalar,
            z_comm: G1Affine,
        ) {
            let alpha_sq = alpha.square();

            let identity_permutation_term = {
                let beta_z = beta * z_challenge;
                let a_contribution = evaluations.a_eval + beta_z + gamma;

                let beta_k1_z = beta * K1 * z_challenge;
                let b_contribution = evaluations.b_eval + beta_k1_z + gamma;

                let beta_k2_z = beta * K2 * z_challenge;
                let c_contribution = evaluations.c_eval + beta_k2_z + gamma;

                let beta_k3_z = beta * K3 * z_challenge;
                let d_contribution =
                    (evaluations.d_eval + beta_k3_z + gamma) * alpha;

                a_contribution
                    * b_contribution
                    * c_contribution
                    * d_contribution
            };

            let lagrange_first_term = l1_eval * alpha_sq;

            scalars.push(
                identity_permutation_term + lagrange_first_term + u_challenge,
            );
            points.push(z_comm);

            let copy_permutation_term = {
                let beta_sigma_1 = beta * evaluations.s_sigma_1_eval;
                let a_contribution = evaluations.a_eval + beta_sigma_1 + gamma;

                let beta_sigma_2 = beta * evaluations.s_sigma_2_eval;
                let b_contribution = evaluations.b_eval + beta_sigma_2 + gamma;

                let beta_sigma_3 = beta * evaluations.s_sigma_3_eval;
                let c_contribution = evaluations.c_eval + beta_sigma_3 + gamma;

                let z_alpha_factor = beta * evaluations.z_eval * alpha;

                -(a_contribution
                    * b_contribution
                    * c_contribution
                    * z_alpha_factor)
            };
            scalars.push(copy_permutation_term);
            points.push(self.s_sigma_4.0);
        }
    }
}
