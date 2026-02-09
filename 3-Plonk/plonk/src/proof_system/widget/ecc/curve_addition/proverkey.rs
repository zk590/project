// 模块说明：本文件实现 PLONK
// 组件（src/proof_system/widget/ecc/curve_addition/proverkey.rs）。

//

use crate::fft::{Evaluations, Polynomial};
use crate::proof_system::linearization_poly::ProofEvaluations;
use coset_bls12_381::BlsScalar;
use coset_jubjub::EDWARDS_D;

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
    pub(crate) q_variable_group_add: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        curve_add_separation_challenge: &BlsScalar,
        a_i: &BlsScalar,
        a_i_w: &BlsScalar,
        b_i: &BlsScalar,
        b_i_w: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        d_i_w: &BlsScalar,
    ) -> BlsScalar {
        let q_variable_group_add_i = &self.q_variable_group_add.1[index];

        let kappa = curve_add_separation_challenge.square();

        let point_x_left = a_i;
        let point_x_output = a_i_w;
        let point_y_left = b_i;
        let point_y_output = b_i_w;
        let point_x_right = c_i;
        let point_y_right = d_i;
        let x_left_mul_y_right = d_i_w;

        //

        let xy_consistency = point_x_left * point_y_right - x_left_mul_y_right;

        let y_left_mul_x_right = point_y_left * point_x_right;
        let y_left_mul_y_right = point_y_left * point_y_right;
        let x_left_mul_x_right = point_x_left * point_x_right;

        let x3_lhs = x_left_mul_y_right + y_left_mul_x_right;
        let x3_rhs = point_x_output
            + (point_x_output
                * EDWARDS_D
                * x_left_mul_y_right
                * y_left_mul_x_right);
        let x3_consistency = (x3_lhs - x3_rhs) * kappa;

        let y3_lhs = y_left_mul_y_right + x_left_mul_x_right;
        let y3_rhs = point_y_output
            - point_y_output
                * EDWARDS_D
                * x_left_mul_y_right
                * y_left_mul_x_right;
        let y3_consistency = (y3_lhs - y3_rhs) * kappa.square();

        let identity = xy_consistency + x3_consistency + y3_consistency;

        identity * q_variable_group_add_i * curve_add_separation_challenge
    }

    pub(crate) fn compute_linearization(
        &self,
        curve_add_separation_challenge: &BlsScalar,
        evaluations: &ProofEvaluations,
    ) -> Polynomial {
        let q_variable_group_add_poly = &self.q_variable_group_add.0;

        let kappa = curve_add_separation_challenge.square();

        let point_x_left = evaluations.a_eval;
        let point_x_output = evaluations.a_w_eval;
        let point_y_left = evaluations.b_eval;
        let point_y_output = evaluations.b_w_eval;
        let point_x_right = evaluations.c_eval;
        let point_y_right = evaluations.d_eval;
        let x_left_mul_y_right = evaluations.d_w_eval;

        //

        let xy_consistency = point_x_left * point_y_right - x_left_mul_y_right;

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
            - point_y_output
                * EDWARDS_D
                * x_left_mul_y_right
                * y_left_mul_x_right;
        let y3_consistency = (y3_lhs - y3_rhs) * kappa.square();

        let identity = xy_consistency + x3_consistency + y3_consistency;

        q_variable_group_add_poly * &(identity * curve_add_separation_challenge)
    }
}
