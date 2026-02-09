// 模块说明：本文件实现 PLONK
// 组件（src/proof_system/widget/arithmetic/proverkey.rs）。

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
    pub q_m: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_l: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_r: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_o: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_f: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_c: (Polynomial, Evaluations),
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub q_arith: (Polynomial, Evaluations),
}

impl ProverKey {
    pub(crate) fn compute_quotient_i(
        &self,
        index: usize,
        a_i: &BlsScalar,
        b_i: &BlsScalar,
        c_i: &BlsScalar,
        d_i: &BlsScalar,
    ) -> BlsScalar {
        let q_m_i = &self.q_m.1[index];
        let q_l_i = &self.q_l.1[index];
        let q_r_i = &self.q_r.1[index];
        let q_o_i = &self.q_o.1[index];
        let q_f_i = &self.q_f.1[index];
        let q_c_i = &self.q_c.1[index];
        let q_arith_i = &self.q_arith.1[index];

        //
        let mul_selector_term = a_i * b_i * q_m_i;
        let left_selector_term = a_i * q_l_i;
        let right_selector_term = b_i * q_r_i;
        let output_selector_term = c_i * q_o_i;
        let fourth_wire_term = d_i * q_f_i;
        let constant_selector_term = q_c_i;
        (mul_selector_term
            + left_selector_term
            + right_selector_term
            + output_selector_term
            + fourth_wire_term
            + constant_selector_term)
            * q_arith_i
    }

    pub(crate) fn compute_linearization(
        &self,
        evaluations: &ProofEvaluations,
    ) -> Polynomial {
        let q_m_poly = &self.q_m.0;
        let q_l_poly = &self.q_l.0;
        let q_r_poly = &self.q_r.0;
        let q_o_poly = &self.q_o.0;
        let q_f_poly = &self.q_f.0;
        let q_c_poly = &self.q_c.0;

        //

        let witness_product = evaluations.a_eval * evaluations.b_eval;
        let mul_selector_term = q_m_poly * &witness_product;

        let left_selector_term = q_l_poly * &evaluations.a_eval;

        let right_selector_term = q_r_poly * &evaluations.b_eval;

        let output_selector_term = q_o_poly * &evaluations.c_eval;

        let fourth_wire_term = q_f_poly * &evaluations.d_eval;

        let mut linearized_identity = &mul_selector_term + &left_selector_term;
        linearized_identity = &linearized_identity + &right_selector_term;
        linearized_identity = &linearized_identity + &output_selector_term;
        linearized_identity = &linearized_identity + &fourth_wire_term;
        linearized_identity = &linearized_identity + q_c_poly;
        linearized_identity = &linearized_identity * &evaluations.q_arith_eval;

        linearized_identity
    }
}
