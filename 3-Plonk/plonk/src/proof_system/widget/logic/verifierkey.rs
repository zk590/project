// 模块说明：本文件实现 PLONK
// 组件（src/proof_system/widget/logic/verifierkey.rs）。

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
    pub(crate) q_c: Commitment,
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_logic: Commitment,
}

#[cfg(feature = "alloc")]
mod alloc {
    use super::*;
    use crate::proof_system::linearization_poly::ProofEvaluations;
    use crate::proof_system::widget::logic::proverkey::{delta, delta_xor_and};
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use coset_bls12_381::{BlsScalar, G1Affine};

    impl VerifierKey {
        pub(crate) fn compute_linearization_commitment(
            &self,
            logic_separation_challenge: &BlsScalar,
            scalars: &mut Vec<BlsScalar>,
            points: &mut Vec<G1Affine>,
            evaluations: &ProofEvaluations,
        ) {
            let four = BlsScalar::from(4);

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
            scalars.push(
                (c_0 + c_1 + c_2 + c_3 + c_4) * logic_separation_challenge,
            );
            points.push(self.q_logic.0);
        }
    }
}
