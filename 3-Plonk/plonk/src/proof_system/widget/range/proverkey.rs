// 模块说明：本文件实现 PLONK
// 组件（src/proof_system/widget/range/proverkey.rs）。

//

use crate::fft::{Evaluations, Polynomial};
use crate::proof_system::linearization_poly::ProofEvaluations;
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
    pub(crate) q_range: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        range_separation_challenge: &BlsScalar,
        a_i: &BlsScalar,
        b_i: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        d_i_w: &BlsScalar,
    ) -> BlsScalar {
        let four = BlsScalar::from(4);
        let q_range_i = &self.q_range.1[index];

        let kappa = range_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        //
        let c_minus_4d_delta = delta(c_i - four * d_i);
        let b_minus_4c_delta = delta(b_i - four * c_i) * kappa;
        let a_minus_4b_delta = delta(a_i - four * b_i) * kappa_sq;
        let d_shift_minus_4a_delta = delta(d_i_w - four * a_i) * kappa_cu;
        (c_minus_4d_delta
            + b_minus_4c_delta
            + a_minus_4b_delta
            + d_shift_minus_4a_delta)
            * q_range_i
            * range_separation_challenge
    }

    pub(crate) fn compute_linearization(
        &self,
        range_separation_challenge: &BlsScalar,
        evaluations: &ProofEvaluations,
    ) -> Polynomial {
        let four = BlsScalar::from(4);
        let q_range_poly = &self.q_range.0;

        let kappa = range_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;

        let c_minus_4d_delta =
            delta(evaluations.c_eval - four * evaluations.d_eval);
        let b_minus_4c_delta =
            delta(evaluations.b_eval - four * evaluations.c_eval) * kappa;
        let a_minus_4b_delta =
            delta(evaluations.a_eval - four * evaluations.b_eval) * kappa_sq;
        let d_shift_minus_4a_delta =
            delta(evaluations.d_w_eval - four * evaluations.a_eval) * kappa_cu;

        let combined_range_term = (c_minus_4d_delta
            + b_minus_4c_delta
            + a_minus_4b_delta
            + d_shift_minus_4a_delta)
            * range_separation_challenge;

        q_range_poly * &combined_range_term
    }
}

pub(crate) fn delta(f: BlsScalar) -> BlsScalar {
    let f_1 = f - BlsScalar::one();
    let f_2 = f - BlsScalar::from(2);
    let f_3 = f - BlsScalar::from(3);
    f * f_1 * f_2 * f_3
}
