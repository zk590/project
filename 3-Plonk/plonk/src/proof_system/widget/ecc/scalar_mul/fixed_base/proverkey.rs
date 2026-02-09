// 模块说明：本文件实现 PLONK
// 组件（src/proof_system/widget/ecc/scalar_mul/fixed_base/proverkey.rs）。

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
    pub(crate) q_l: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_r: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_c: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_fixed_group_add: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        ecc_separation_challenge: &BlsScalar,
        a_i: &BlsScalar,
        a_i_w: &BlsScalar,
        b_i: &BlsScalar,
        b_i_w: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        d_i_w: &BlsScalar,
    ) -> BlsScalar {
        let q_fixed_group_add_i = &self.q_fixed_group_add.1[index];
        let q_c_i = &self.q_c.1[index];

        let kappa = ecc_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        let x_beta = &self.q_l.1[index];
        let y_beta = &self.q_r.1[index];

        let acc_x = a_i;
        let acc_x_w = a_i_w;
        let acc_y = b_i;
        let acc_y_w = b_i_w;

        let xy_alpha = c_i;

        let accumulated_bit = d_i;
        let accumulated_bit_w = d_i_w;
        let bit = extract_bit(accumulated_bit, accumulated_bit_w);

        //

        let bit_consistency = check_bit_consistency(bit);

        let y_alpha =
            bit.square() * (y_beta - BlsScalar::one()) + BlsScalar::one();
        let x_alpha = bit * x_beta;

        let xy_consistency = ((bit * q_c_i) - xy_alpha) * kappa;

        let shifted_acc_x = acc_x_w;
        let x_consistency_lhs = shifted_acc_x
            + (shifted_acc_x * xy_alpha * acc_x * acc_y * EDWARDS_D);
        let x_consistency_rhs = (acc_x * y_alpha) + (acc_y * x_alpha);
        let x_acc_consistency =
            (x_consistency_lhs - x_consistency_rhs) * kappa_sq;

        let shifted_acc_y = acc_y_w;
        let y_consistency_lhs = shifted_acc_y
            - (shifted_acc_y * xy_alpha * acc_x * acc_y * EDWARDS_D);
        let y_consistency_rhs = (acc_y * y_alpha) + (acc_x * x_alpha);
        let y_acc_consistency =
            (y_consistency_lhs - y_consistency_rhs) * kappa_cu;

        let identity = bit_consistency
            + x_acc_consistency
            + y_acc_consistency
            + xy_consistency;

        identity * q_fixed_group_add_i * ecc_separation_challenge
    }

    pub(crate) fn compute_linearization(
        &self,
        ecc_separation_challenge: &BlsScalar,
        evaluations: &ProofEvaluations,
    ) -> Polynomial {
        let q_fixed_group_add_poly = &self.q_fixed_group_add.0;

        let kappa = ecc_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        let x_beta_eval = evaluations.q_l_eval;
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

        let y_alpha =
            bit.square() * (y_beta_eval - BlsScalar::one()) + BlsScalar::one();

        let x_alpha = x_beta_eval * bit;

        let xy_consistency = ((bit * evaluations.q_c_eval) - xy_alpha) * kappa;

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

        q_fixed_group_add_poly * &(combined_identity * ecc_separation_challenge)
    }
}

pub(crate) fn extract_bit(acc: &BlsScalar, acc_w: &BlsScalar) -> BlsScalar {
    acc_w - acc - acc
}

pub(crate) fn check_bit_consistency(bit: BlsScalar) -> BlsScalar {
    let one = BlsScalar::one();
    bit * (bit - one) * (bit + one)
}
