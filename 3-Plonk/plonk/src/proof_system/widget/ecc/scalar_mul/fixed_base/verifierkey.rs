// 模块说明：本文件实现 PLONK
// 组件（src/proof_system/widget/ecc/scalar_mul/fixed_base/verifierkey.rs）。

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
    pub(crate) q_l: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_r: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_fixed_group_add: Commitment,
}

#[cfg(feature = "alloc")]
mod alloc {
    use super::*;
    use crate::proof_system::linearization_poly::ProofEvaluations;
    use crate::proof_system::widget::ecc::scalar_mul::fixed_base::proverkey::{
        check_bit_consistency, extract_bit,
    };
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use coset_bls12_381::{BlsScalar, G1Affine};
    use coset_jubjub::EDWARDS_D;

    impl VerifierKey {
        pub(crate) fn compute_linearization_commitment(
            &self,
            ecc_separation_challenge: &BlsScalar,
            scalars: &mut Vec<BlsScalar>,
            points: &mut Vec<G1Affine>,
            evaluations: &ProofEvaluations,
        ) {
            let kappa = ecc_separation_challenge.square();
            let kappa_sq = kappa.square();
            let kappa_cu = kappa_sq * kappa;

            let x_beta_poly = evaluations.q_l_eval;
            let y_beta_eval = evaluations.q_r_eval;

            let acc_x = evaluations.a_eval;
            let acc_x_w = evaluations.a_w_eval;
            let acc_y = evaluations.b_eval;
            let acc_y_w = evaluations.b_w_eval;

            let xy_alpha = evaluations.c_eval;

            let accumulated_bit = evaluations.d_eval;
            let accumulated_bit_w = evaluations.d_w_eval;
            let bit = extract_bit(&accumulated_bit, &accumulated_bit_w);

            let bit_consistency = check_bit_consistency(bit);

            let y_alpha = (bit.square() * (y_beta_eval - BlsScalar::one()))
                + BlsScalar::one();

            let x_alpha = x_beta_poly * bit;

            let xy_consistency =
                ((bit * evaluations.q_c_eval) - xy_alpha) * kappa;

            let shifted_acc_x = acc_x_w;
            let x_consistency_lhs = shifted_acc_x
                + (shifted_acc_x * xy_alpha * acc_x * acc_y * EDWARDS_D);
            let x_consistency_rhs = (x_alpha * acc_y) + (y_alpha * acc_x);
            let x_acc_consistency =
                (x_consistency_lhs - x_consistency_rhs) * kappa_sq;

            let shifted_acc_y = acc_y_w;
            let y_consistency_lhs = shifted_acc_y
                - (shifted_acc_y * xy_alpha * acc_x * acc_y * EDWARDS_D);
            let y_consistency_rhs = (x_alpha * acc_x) + (y_alpha * acc_y);
            let y_acc_consistency =
                (y_consistency_lhs - y_consistency_rhs) * kappa_cu;

            let combined_identity = bit_consistency
                + x_acc_consistency
                + y_acc_consistency
                + xy_consistency;

            scalars.push(combined_identity * ecc_separation_challenge);
            points.push(self.q_fixed_group_add.0);
        }
    }
}
