// 模块说明：本文件实现 PLONK 组件（src/proof_system/linearization_poly.rs）。

//

#[cfg(feature = "alloc")]
use crate::{
    fft::{EvaluationDomain, Polynomial},
    proof_system::{proof, ProverKey},
};

use coset_bls12_381::BlsScalar;
use coset_bytes::{DeserializableSlice, Serializable};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Debug, Eq, PartialEq, Clone, Default)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct ProofEvaluations {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) a_eval: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) b_eval: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) c_eval: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) d_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) a_w_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) b_w_eval: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) d_w_eval: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_arith_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_c_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_l_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) q_r_eval: BlsScalar,
    //
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_1_eval: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_2_eval: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) s_sigma_3_eval: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) z_eval: BlsScalar,
}

impl Serializable<{ 15 * BlsScalar::SIZE }> for ProofEvaluations {
    type Error = coset_bytes::Error;

    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use coset_bytes::Write;

        let mut serialized_evaluations = [0u8; Self::SIZE];
        let mut writer = &mut serialized_evaluations[..];
        writer.write(&self.a_eval.to_bytes());
        writer.write(&self.b_eval.to_bytes());
        writer.write(&self.c_eval.to_bytes());
        writer.write(&self.d_eval.to_bytes());
        writer.write(&self.a_w_eval.to_bytes());
        writer.write(&self.b_w_eval.to_bytes());
        writer.write(&self.d_w_eval.to_bytes());
        writer.write(&self.q_arith_eval.to_bytes());
        writer.write(&self.q_c_eval.to_bytes());
        writer.write(&self.q_l_eval.to_bytes());
        writer.write(&self.q_r_eval.to_bytes());
        writer.write(&self.s_sigma_1_eval.to_bytes());
        writer.write(&self.s_sigma_2_eval.to_bytes());
        writer.write(&self.s_sigma_3_eval.to_bytes());
        writer.write(&self.z_eval.to_bytes());

        serialized_evaluations
    }

    fn from_bytes(
        serialized_evaluations: &[u8; Self::SIZE],
    ) -> Result<ProofEvaluations, Self::Error> {
        let mut evaluation_reader = &serialized_evaluations[..];
        let a_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let b_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let c_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let d_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let a_w_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let b_w_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let d_w_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let q_arith_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let q_c_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let q_l_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let q_r_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let s_sigma_1_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let s_sigma_2_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let s_sigma_3_eval = BlsScalar::from_reader(&mut evaluation_reader)?;
        let z_eval = BlsScalar::from_reader(&mut evaluation_reader)?;

        Ok(ProofEvaluations {
            a_eval,
            b_eval,
            c_eval,
            d_eval,
            a_w_eval,
            b_w_eval,
            d_w_eval,
            q_arith_eval,
            q_c_eval,
            q_l_eval,
            q_r_eval,
            s_sigma_1_eval,
            s_sigma_2_eval,
            s_sigma_3_eval,
            z_eval,
        })
    }
}

#[cfg(feature = "alloc")]
#[allow(clippy::type_complexity)]
pub(crate) fn build_linearization_polynomial(
    prover_key: &ProverKey,
    (
        alpha,
        beta,
        gamma,
        range_separation_challenge,
        logic_separation_challenge,
        fixed_base_separation_challenge,
        var_base_separation_challenge,
        z_challenge,
    ): &(
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
    ),
    z_poly: &Polynomial,
    evaluations: &ProofEvaluations,
    domain: &EvaluationDomain,
    t_low_poly: &Polynomial,
    t_mid_poly: &Polynomial,
    t_high_poly: &Polynomial,
    t_fourth_poly: &Polynomial,
    pub_inputs: &[BlsScalar],
) -> Polynomial {
    let circuit_linearization = build_circuit_linearization_terms(
        (
            range_separation_challenge,
            logic_separation_challenge,
            fixed_base_separation_challenge,
            var_base_separation_challenge,
        ),
        evaluations,
        prover_key,
    );

    let pi_eval =
        proof::alloc::compute_barycentric_eval(pub_inputs, z_challenge, domain);

    let circuit_linearization = &circuit_linearization + &pi_eval;

    let permutation_linearization =
        prover_key.permutation.compute_linearization(
            z_challenge,
            (alpha, beta, gamma),
            (
                &evaluations.a_eval,
                &evaluations.b_eval,
                &evaluations.c_eval,
                &evaluations.d_eval,
            ),
            (
                &evaluations.s_sigma_1_eval,
                &evaluations.s_sigma_2_eval,
                &evaluations.s_sigma_3_eval,
            ),
            &evaluations.z_eval,
            z_poly,
        );

    let domain_size = domain.size();

    let z_n = z_challenge.pow(&[domain_size as u64, 0, 0, 0]);
    let z_two_n = z_challenge.pow(&[2 * domain_size as u64, 0, 0, 0]);
    let z_three_n = z_challenge.pow(&[3 * domain_size as u64, 0, 0, 0]);

    let t_low_component = t_low_poly;
    let t_mid_component = t_mid_poly * &z_n;
    let t_high_component = t_high_poly * &z_two_n;
    let t_fourth_component = t_fourth_poly * &z_three_n;
    let quotient_prefix =
        &(t_low_component + &t_mid_component) + &t_high_component;

    let quotient_polynomial = &quotient_prefix + &t_fourth_component;

    let z_h_eval = -domain.evaluate_vanishing_polynomial(z_challenge);

    let quotient_polynomial = &quotient_polynomial * &z_h_eval;

    let linearized_identity =
        &circuit_linearization + &permutation_linearization;

    &linearized_identity + &quotient_polynomial
}

#[cfg(feature = "alloc")]
fn build_circuit_linearization_terms(
    (
        range_separation_challenge,
        logic_separation_challenge,
        fixed_base_separation_challenge,
        var_base_separation_challenge,
    ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
    evaluations: &ProofEvaluations,
    prover_key: &ProverKey,
) -> Polynomial {
    let arithmetic_component =
        prover_key.arithmetic.compute_linearization(evaluations);

    let range_component = prover_key
        .range
        .compute_linearization(range_separation_challenge, evaluations);

    let logic_component = prover_key
        .logic
        .compute_linearization(logic_separation_challenge, evaluations);

    let fixed_base_component = prover_key
        .fixed_base
        .compute_linearization(fixed_base_separation_challenge, evaluations);

    let variable_base_component = prover_key
        .variable_base
        .compute_linearization(var_base_separation_challenge, evaluations);

    let mut linearization_poly = &arithmetic_component + &range_component;
    linearization_poly += &logic_component;
    linearization_poly += &fixed_base_component;
    linearization_poly += &variable_base_component;

    linearization_poly
}

#[cfg(test)]
mod evaluations_tests {
    use super::*;

    #[test]
    fn proof_evaluations_coset_bytes_serde() {
        let proof_evals = ProofEvaluations::default();
        let bytes = proof_evals.to_bytes();
        let obtained_evals = ProofEvaluations::from_slice(&bytes)
            .expect("Deserialization error");
        assert_eq!(proof_evals.to_bytes(), obtained_evals.to_bytes())
    }
}
