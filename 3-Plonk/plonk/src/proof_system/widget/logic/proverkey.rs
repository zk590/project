// 模块说明：本文件实现 PLONK
// 组件（src/proof_system/widget/logic/proverkey.rs）。

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
    pub(crate) q_c: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_logic: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        logic_separation_challenge: &BlsScalar,
        a_i: &BlsScalar,
        a_i_w: &BlsScalar,
        b_i: &BlsScalar,
        b_i_w: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
        d_i_w: &BlsScalar,
    ) -> BlsScalar {
        let four = BlsScalar::from(4);

        let q_logic_i = &self.q_logic.1[index];
        let q_c_i = &self.q_c.1[index];

        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let a_shift_delta_input = a_i_w - four * a_i;
        let c_0 = delta(a_shift_delta_input);

        let b_shift_delta_input = b_i_w - four * b_i;
        let c_1 = delta(b_shift_delta_input) * kappa;

        let d_shift_delta_input = d_i_w - four * d_i;
        let c_2 = delta(d_shift_delta_input) * kappa_sq;

        let wire_w_eval = c_i;
        let c_3 = (wire_w_eval - a_shift_delta_input * b_shift_delta_input)
            * kappa_cu;

        let c_4 = delta_xor_and(
            &a_shift_delta_input,
            &b_shift_delta_input,
            wire_w_eval,
            &d_shift_delta_input,
            q_c_i,
        ) * kappa_qu;

        q_logic_i * (c_3 + c_0 + c_1 + c_2 + c_4) * logic_separation_challenge
    }

    pub(crate) fn compute_linearization(
        &self,
        logic_separation_challenge: &BlsScalar,
        evaluations: &ProofEvaluations,
    ) -> Polynomial {
        let four = BlsScalar::from(4);
        let q_logic_poly = &self.q_logic.0;

        let kappa = logic_separation_challenge.square();
        let kappa_sq = kappa.square();
        let kappa_cu = kappa_sq * kappa;
        let kappa_qu = kappa_cu * kappa;

        let a_shift_delta_input =
            evaluations.a_w_eval - four * evaluations.a_eval;
        let c_0 = delta(a_shift_delta_input);

        let b_shift_delta_input =
            evaluations.b_w_eval - four * evaluations.b_eval;
        let c_1 = delta(b_shift_delta_input) * kappa;

        let d_shift_delta_input =
            evaluations.d_w_eval - four * evaluations.d_eval;
        let c_2 = delta(d_shift_delta_input) * kappa_sq;

        let wire_w_eval = evaluations.c_eval;
        let c_3 = (wire_w_eval - a_shift_delta_input * b_shift_delta_input)
            * kappa_cu;

        let c_4 = delta_xor_and(
            &a_shift_delta_input,
            &b_shift_delta_input,
            &wire_w_eval,
            &d_shift_delta_input,
            &evaluations.q_c_eval,
        ) * kappa_qu;

        let combined_logic_term =
            (c_0 + c_1 + c_2 + c_3 + c_4) * logic_separation_challenge;

        q_logic_poly * &combined_logic_term
    }
}

pub(crate) fn delta(f: BlsScalar) -> BlsScalar {
    let f_1 = f - BlsScalar::one();
    let f_2 = f - BlsScalar::from(2);
    let f_3 = f - BlsScalar::from(3);
    f * f_1 * f_2 * f_3
}

#[allow(non_snake_case)]
pub(crate) fn delta_xor_and(
    a: &BlsScalar,
    b: &BlsScalar,
    w: &BlsScalar,
    c: &BlsScalar,
    q_c: &BlsScalar,
) -> BlsScalar {
    let nine = BlsScalar::from(9);
    let two = BlsScalar::from(2);
    let three = BlsScalar::from(3);
    let four = BlsScalar::from(4);
    let eighteen = BlsScalar::from(18);
    let eighty_one = BlsScalar::from(81);
    let eighty_three = BlsScalar::from(83);

    let F = w
        * (w * (four * w - eighteen * (a + b) + eighty_one)
            + eighteen * (a.square() + b.square())
            - eighty_one * (a + b)
            + eighty_three);
    let E = three * (a + b + c) - (two * F);
    let B = q_c * ((nine * c) - three * (a + b));
    B + E
}
