// 模块说明：本文件实现 PLONK
// 组件（src/proof_system/widget/ecc/curve_addition/verifierkey.rs）。

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
    pub(crate) q_variable_group_add: Commitment,
}

#[cfg(feature = "alloc")]
mod alloc {
    use super::*;
    use crate::proof_system::linearization_poly::ProofEvaluations;
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use coset_bls12_381::{BlsScalar, G1Affine};
    use coset_jubjub::EDWARDS_D;

    impl VerifierKey {
        pub(crate) fn compute_linearization_commitment(
            &self,
            curve_add_separation_challenge: &BlsScalar,
            scalars: &mut Vec<BlsScalar>,
            points: &mut Vec<G1Affine>,
            evaluations: &ProofEvaluations,
        ) {
            let kappa = curve_add_separation_challenge.square();

            let point_x_left = evaluations.a_eval;
            let point_x_output = evaluations.a_w_eval;
            let point_y_left = evaluations.b_eval;
            let point_y_output = evaluations.b_w_eval;
            let point_x_right = evaluations.c_eval;
            let point_y_right = evaluations.d_eval;
            let x_left_mul_y_right = evaluations.d_w_eval;

            //

            let xy_consistency =
                point_x_left * point_y_right - x_left_mul_y_right;

            let y_left_mul_x_right = point_y_left * point_x_right;
            let y_left_mul_y_right = point_y_left * point_y_right;
            let x_left_mul_x_right = point_x_left * point_x_right;

            let x3_lhs = x_left_mul_y_right + y_left_mul_x_right;
            let x3_rhs = point_x_output
                + (point_x_output
                    * (EDWARDS_D * x_left_mul_y_right * y_left_mul_x_right));
            let x3_consistency = (x3_lhs - x3_rhs) * kappa;

            let y3_lhs = y_left_mul_y_right + x_left_mul_x_right;
            let y3_rhs = point_y_output
                - (point_y_output
                    * EDWARDS_D
                    * x_left_mul_y_right
                    * y_left_mul_x_right);
            let y3_consistency = (y3_lhs - y3_rhs) * kappa.square();

            let identity = xy_consistency + x3_consistency + y3_consistency;

            scalars.push(identity * curve_add_separation_challenge);
            points.push(self.q_variable_group_add.0);
        }
    }
}
