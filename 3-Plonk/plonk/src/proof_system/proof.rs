//

use super::linearization_poly::ProofEvaluations;
use crate::commitment_scheme::Commitment;

use coset_bytes::{DeserializableSlice, Serializable};

#[cfg(feature = "std")]
use rayon::prelude::*;

const V_MAX_DEGREE: usize = 7;

#[cfg(feature = "rkyv-impl")]
use crate::util::check_field;
#[cfg(feature = "rkyv-impl")]
use bytecheck::{CheckBytes, StructCheckError};
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Debug, Eq, PartialEq, Clone, Default)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace"))
)]
pub struct Proof {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) a_comm: Commitment,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) b_comm: Commitment,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) c_comm: Commitment,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) d_comm: Commitment,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) z_comm: Commitment,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_low_comm: Commitment,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_mid_comm: Commitment,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_high_comm: Commitment,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) t_fourth_comm: Commitment,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) w_z_chall_comm: Commitment,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) w_z_chall_w_comm: Commitment,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) evaluations: ProofEvaluations,
}

#[cfg(feature = "rkyv-impl")]
impl<C> CheckBytes<C> for ArchivedProof {
    type Error = StructCheckError;

    unsafe fn check_bytes<'a>(
        value: *const Self,
        context: &mut C,
    ) -> Result<&'a Self, Self::Error> {
        check_field(&(*value).a_comm, context, "a_comm")?;
        check_field(&(*value).b_comm, context, "b_comm")?;
        check_field(&(*value).c_comm, context, "c_comm")?;
        check_field(&(*value).d_comm, context, "d_comm")?;

        check_field(&(*value).z_comm, context, "z_comm")?;

        check_field(&(*value).t_low_comm, context, "t_low_comm")?;
        check_field(&(*value).t_mid_comm, context, "t_mid_comm")?;
        check_field(&(*value).t_high_comm, context, "t_high_comm")?;
        check_field(&(*value).t_fourth_comm, context, "t_fourth_comm")?;

        check_field(&(*value).w_z_chall_comm, context, "w_z_chall_comm")?;
        check_field(&(*value).w_z_chall_w_comm, context, "w_z_chall_w_comm")?;
        check_field(&(*value).evaluations, context, "evaluations")?;

        Ok(&*value)
    }
}

impl Serializable<{ 11 * Commitment::SIZE + ProofEvaluations::SIZE }>
    for Proof
{
    type Error = coset_bytes::Error;

    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use coset_bytes::Write;

        let mut serialized_bytes = [0u8; Self::SIZE];
        let mut writer = &mut serialized_bytes[..];
        writer.write(&self.a_comm.to_bytes());
        writer.write(&self.b_comm.to_bytes());
        writer.write(&self.c_comm.to_bytes());
        writer.write(&self.d_comm.to_bytes());
        writer.write(&self.z_comm.to_bytes());
        writer.write(&self.t_low_comm.to_bytes());
        writer.write(&self.t_mid_comm.to_bytes());
        writer.write(&self.t_high_comm.to_bytes());
        writer.write(&self.t_fourth_comm.to_bytes());
        writer.write(&self.w_z_chall_comm.to_bytes());
        writer.write(&self.w_z_chall_w_comm.to_bytes());
        writer.write(&self.evaluations.to_bytes());

        serialized_bytes
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut buffer = &bytes[..];

        let a_comm = Commitment::from_reader(&mut buffer)?;
        let b_comm = Commitment::from_reader(&mut buffer)?;
        let c_comm = Commitment::from_reader(&mut buffer)?;
        let d_comm = Commitment::from_reader(&mut buffer)?;
        let z_comm = Commitment::from_reader(&mut buffer)?;
        let t_low_comm = Commitment::from_reader(&mut buffer)?;
        let t_mid_comm = Commitment::from_reader(&mut buffer)?;
        let t_high_comm = Commitment::from_reader(&mut buffer)?;
        let t_fourth_comm = Commitment::from_reader(&mut buffer)?;
        let w_z_chall_comm = Commitment::from_reader(&mut buffer)?;
        let w_z_chall_w_comm = Commitment::from_reader(&mut buffer)?;
        let evaluations = ProofEvaluations::from_reader(&mut buffer)?;

        Ok(Proof {
            a_comm,
            b_comm,
            c_comm,
            d_comm,
            z_comm,
            t_low_comm,
            t_mid_comm,
            t_high_comm,
            t_fourth_comm,
            w_z_chall_comm,
            w_z_chall_w_comm,
            evaluations,
        })
    }
}

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
pub(crate) mod alloc {
    use super::*;
    use crate::{
        commitment_scheme::{AggregateProof, OpeningKey},
        error::Error,
        fft::EvaluationDomain,
        proof_system::widget::VerifierKey,
        transcript::TranscriptProtocol,
        util::batch_inversion,
    };
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use coset_bls12_381::{
        multiscalar_mul::msm_variable_base, BlsScalar, G1Affine, G1Projective,
    };
    use merlin::Transcript;
    #[cfg(feature = "std")]
    use rayon::prelude::*;

    impl Proof {
        #[allow(non_snake_case)]
        /// 使用验证键、转录器与公开输入对证明执行完整验证。
        pub(crate) fn verify(
            &self,
            verifier_key: &VerifierKey,
            transcript: &mut Transcript,
            opening_key: &OpeningKey,
            pub_inputs: &[BlsScalar],
        ) -> Result<(), Error> {
            let domain = EvaluationDomain::new(verifier_key.n)?;

            //

            transcript.append_commitment(b"a_comm", &self.a_comm);
            transcript.append_commitment(b"b_comm", &self.b_comm);
            transcript.append_commitment(b"c_comm", &self.c_comm);
            transcript.append_commitment(b"d_comm", &self.d_comm);

            let beta = transcript.challenge_scalar(b"beta");
            transcript.append_scalar(b"beta", &beta);
            let gamma = transcript.challenge_scalar(b"gamma");

            transcript.append_commitment(b"z_comm", &self.z_comm);

            let alpha = transcript.challenge_scalar(b"alpha");
            let range_sep_challenge =
                transcript.challenge_scalar(b"range separation challenge");
            let logic_sep_challenge =
                transcript.challenge_scalar(b"logic separation challenge");
            let fixed_base_sep_challenge =
                transcript.challenge_scalar(b"fixed base separation challenge");
            let var_base_sep_challenge = transcript
                .challenge_scalar(b"variable base separation challenge");

            transcript.append_commitment(b"t_low_comm", &self.t_low_comm);
            transcript.append_commitment(b"t_mid_comm", &self.t_mid_comm);
            transcript.append_commitment(b"t_high_comm", &self.t_high_comm);
            transcript.append_commitment(b"t_fourth_comm", &self.t_fourth_comm);

            let z_challenge = transcript.challenge_scalar(b"z_challenge");

            transcript.append_scalar(b"a_eval", &self.evaluations.a_eval);
            transcript.append_scalar(b"b_eval", &self.evaluations.b_eval);
            transcript.append_scalar(b"c_eval", &self.evaluations.c_eval);
            transcript.append_scalar(b"d_eval", &self.evaluations.d_eval);

            transcript.append_scalar(
                b"s_sigma_1_eval",
                &self.evaluations.s_sigma_1_eval,
            );
            transcript.append_scalar(
                b"s_sigma_2_eval",
                &self.evaluations.s_sigma_2_eval,
            );
            transcript.append_scalar(
                b"s_sigma_3_eval",
                &self.evaluations.s_sigma_3_eval,
            );

            transcript.append_scalar(b"z_eval", &self.evaluations.z_eval);

            transcript.append_scalar(b"a_w_eval", &self.evaluations.a_w_eval);
            transcript.append_scalar(b"b_w_eval", &self.evaluations.b_w_eval);
            transcript.append_scalar(b"d_w_eval", &self.evaluations.d_w_eval);
            transcript
                .append_scalar(b"q_arith_eval", &self.evaluations.q_arith_eval);
            transcript.append_scalar(b"q_c_eval", &self.evaluations.q_c_eval);
            transcript.append_scalar(b"q_l_eval", &self.evaluations.q_l_eval);
            transcript.append_scalar(b"q_r_eval", &self.evaluations.q_r_eval);

            let v_challenge = transcript.challenge_scalar(b"v_challenge");
            let v_w_challenge = transcript.challenge_scalar(b"v_w_challenge");

            transcript
                .append_commitment(b"w_z_chall_comm", &self.w_z_chall_comm);
            transcript
                .append_commitment(b"w_z_chall_w_comm", &self.w_z_chall_w_comm);

            let u_challenge = transcript.challenge_scalar(b"u_challenge");

            let z_h_eval = domain.evaluate_vanishing_polynomial(&z_challenge);

            let l1_eval = compute_first_lagrange_evaluation(
                &domain,
                &z_h_eval,
                &z_challenge,
            );

            let linearization_commitment = self
                .compute_linearization_commitment(
                    &alpha,
                    &beta,
                    &gamma,
                    (
                        &range_sep_challenge,
                        &logic_sep_challenge,
                        &fixed_base_sep_challenge,
                        &var_base_sep_challenge,
                    ),
                    &z_challenge,
                    &u_challenge,
                    l1_eval,
                    verifier_key,
                    &domain,
                )
                .0;

            let pi_eval =
                compute_barycentric_eval(pub_inputs, &z_challenge, &domain);

            let r_0_eval = pi_eval
                - l1_eval * alpha.square()
                - alpha
                    * (self.evaluations.a_eval
                        + beta * self.evaluations.s_sigma_1_eval
                        + gamma)
                    * (self.evaluations.b_eval
                        + beta * self.evaluations.s_sigma_2_eval
                        + gamma)
                    * (self.evaluations.c_eval
                        + beta * self.evaluations.s_sigma_3_eval
                        + gamma)
                    * (self.evaluations.d_eval + gamma)
                    * self.evaluations.z_eval;

            let mut v_coefficients_for_e = vec![v_challenge];

            for i in 1..V_MAX_DEGREE {
                v_coefficients_for_e
                    .push(v_coefficients_for_e[i - 1] * v_challenge);
            }

            v_coefficients_for_e.push(v_w_challenge * u_challenge);
            v_coefficients_for_e
                .push(v_coefficients_for_e[V_MAX_DEGREE] * v_w_challenge);
            v_coefficients_for_e
                .push(v_coefficients_for_e[V_MAX_DEGREE + 1] * v_w_challenge);

            let e_evaluations = vec![
                self.evaluations.a_eval,
                self.evaluations.b_eval,
                self.evaluations.c_eval,
                self.evaluations.d_eval,
                self.evaluations.s_sigma_1_eval,
                self.evaluations.s_sigma_2_eval,
                self.evaluations.s_sigma_3_eval,
                self.evaluations.a_w_eval,
                self.evaluations.b_w_eval,
                self.evaluations.d_w_eval,
            ];

            let mut e_scalar: BlsScalar = e_evaluations
                .iter()
                .zip(v_coefficients_for_e.iter())
                .map(|(eval, coeff)| eval * coeff)
                .sum();
            e_scalar += -r_0_eval + (u_challenge * self.evaluations.z_eval);

            let msm_points = vec![
                self.a_comm.0,
                self.b_comm.0,
                self.c_comm.0,
                self.d_comm.0,
                verifier_key.permutation.s_sigma_1.0,
                verifier_key.permutation.s_sigma_2.0,
                verifier_key.permutation.s_sigma_3.0,
                opening_key.g,
                self.w_z_chall_w_comm.0,
                self.w_z_chall_comm.0,
                self.w_z_chall_w_comm.0,
            ];

            let mut msm_scalars = v_coefficients_for_e[..V_MAX_DEGREE].to_vec();

            msm_scalars[0] += v_coefficients_for_e[V_MAX_DEGREE];
            msm_scalars[1] += v_coefficients_for_e[V_MAX_DEGREE + 1];
            msm_scalars[3] += v_coefficients_for_e[V_MAX_DEGREE + 2];

            msm_scalars.push(e_scalar);
            msm_scalars.push(u_challenge);
            msm_scalars.push(z_challenge);
            msm_scalars.push(u_challenge * z_challenge * domain.group_gen);

            #[cfg(not(feature = "std"))]
            let msm_results: Vec<G1Projective> = msm_points
                .iter()
                .zip(msm_scalars.iter())
                .map(|(point, scalar)| point * scalar)
                .collect();

            #[cfg(feature = "std")]
            let msm_results: Vec<G1Projective> = msm_points
                .par_iter()
                .zip(msm_scalars.par_iter())
                .map(|(point, scalar)| point * scalar)
                .collect();

            let mut aggregated_commitment: G1Projective =
                msm_results[..V_MAX_DEGREE].iter().sum();
            aggregated_commitment += linearization_commitment;

            let e_commitment = msm_results[V_MAX_DEGREE];

            //

            let left_pairing_point = G1Affine::from(
                -(self.w_z_chall_comm.0 + msm_results[V_MAX_DEGREE + 1]),
            );

            let right_pairing_point = G1Affine::from(
                msm_results[V_MAX_DEGREE + 2]
                    + msm_results[V_MAX_DEGREE + 3]
                    + aggregated_commitment
                    - e_commitment,
            );

            let pairing = coset_bls12_381::multi_miller_loop(&[
                (&left_pairing_point, &opening_key.prepared_x_h),
                (&right_pairing_point, &opening_key.prepared_h),
            ])
            .final_exponentiation();

            if pairing != coset_bls12_381::Gt::identity() {
                return Err(Error::ProofVerificationError);
            };

            Ok(())
        }

        /// 计算线性化多项式对应的承诺点。
        #[allow(clippy::too_many_arguments)]
        fn compute_linearization_commitment(
            &self,
            alpha: &BlsScalar,
            beta: &BlsScalar,
            gamma: &BlsScalar,
            (
                range_sep_challenge,
                logic_sep_challenge,
                fixed_base_sep_challenge,
                var_base_sep_challenge,
            ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
            z_challenge: &BlsScalar,
            u_challenge: &BlsScalar,
            l1_eval: BlsScalar,
            verifier_key: &VerifierKey,
            domain: &EvaluationDomain,
        ) -> Commitment {
            let mut scalars: Vec<_> = Vec::with_capacity(6);
            let mut points: Vec<G1Affine> = Vec::with_capacity(6);

            verifier_key.arithmetic.compute_linearization_commitment(
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.range.compute_linearization_commitment(
                range_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.logic.compute_linearization_commitment(
                logic_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.fixed_base.compute_linearization_commitment(
                fixed_base_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.variable_base.compute_linearization_commitment(
                var_base_sep_challenge,
                &mut scalars,
                &mut points,
                &self.evaluations,
            );

            verifier_key.permutation.compute_linearization_commitment(
                &mut scalars,
                &mut points,
                &self.evaluations,
                z_challenge,
                u_challenge,
                (alpha, beta, gamma),
                &l1_eval,
                self.z_comm.0,
            );

            let domain_size = domain.size();
            let z_h_eval = -domain.evaluate_vanishing_polynomial(z_challenge);

            let z_n_term =
                z_challenge.pow(&[domain_size as u64, 0, 0, 0]) * z_h_eval;
            let z_two_n_term =
                z_challenge.pow(&[2 * domain_size as u64, 0, 0, 0]) * z_h_eval;
            let z_three_n_term =
                z_challenge.pow(&[3 * domain_size as u64, 0, 0, 0]) * z_h_eval;

            scalars.push(z_h_eval);
            points.push(self.t_low_comm.0);

            scalars.push(z_n_term);
            points.push(self.t_mid_comm.0);

            scalars.push(z_two_n_term);
            points.push(self.t_high_comm.0);

            scalars.push(z_three_n_term);
            points.push(self.t_fourth_comm.0);

            Commitment::from(msm_variable_base(&points, &scalars))
        }
    }

    /// 计算第一拉格朗日基函数在挑战点处的取值。
    fn compute_first_lagrange_evaluation(
        domain: &EvaluationDomain,
        z_h_eval: &BlsScalar,
        z_challenge: &BlsScalar,
    ) -> BlsScalar {
        let n_fr = BlsScalar::from(domain.size() as u64);
        let denom = n_fr * (z_challenge - BlsScalar::one());
        z_h_eval * denom.invert().unwrap()
    }

    /// 通过重心插值在挑战点上评估公开输入多项式。
    pub(crate) fn compute_barycentric_eval(
        evaluations: &[BlsScalar],
        point: &BlsScalar,
        domain: &EvaluationDomain,
    ) -> BlsScalar {
        let numerator = (point.pow(&[domain.size() as u64, 0, 0, 0])
            - BlsScalar::one())
            * domain.size_inv;

        #[cfg(not(feature = "std"))]
        let evaluation_indices = (0..evaluations.len()).into_iter();

        #[cfg(feature = "std")]
        let evaluation_indices = (0..evaluations.len()).into_par_iter();

        let non_zero_indices: Vec<usize> = evaluation_indices
            .filter(|&i| {
                let evaluation = &evaluations[i];
                evaluation != &BlsScalar::zero()
            })
            .collect();

        #[cfg(not(feature = "std"))]
        let non_zero_index_positions = (0..non_zero_indices.len()).into_iter();

        #[cfg(feature = "std")]
        let non_zero_index_positions =
            (0..non_zero_indices.len()).into_par_iter();

        let mut denominators: Vec<BlsScalar> = non_zero_index_positions
            .clone()
            .map(|i| {
                let index = non_zero_indices[i];

                (domain.group_gen_inv.pow(&[index as u64, 0, 0, 0]) * point)
                    - BlsScalar::one()
            })
            .collect();
        batch_inversion(&mut denominators);

        let result: BlsScalar = non_zero_index_positions
            .map(|i| {
                let evaluation_index = non_zero_indices[i];
                let evaluation_value = evaluations[evaluation_index];

                denominators[i] * evaluation_value
            })
            .sum();

        result * numerator
    }
}

#[cfg(test)]
mod proof_tests {
    use super::*;
    use coset_bls12_381::BlsScalar;
    use ff::Field;
    use rand_core::OsRng;

    #[test]
    fn test_coset_bytes_serde_proof() {
        let proof = Proof {
            a_comm: Commitment::default(),
            b_comm: Commitment::default(),
            c_comm: Commitment::default(),
            d_comm: Commitment::default(),
            z_comm: Commitment::default(),
            t_low_comm: Commitment::default(),
            t_mid_comm: Commitment::default(),
            t_high_comm: Commitment::default(),
            t_fourth_comm: Commitment::default(),
            w_z_chall_comm: Commitment::default(),
            w_z_chall_w_comm: Commitment::default(),
            evaluations: ProofEvaluations {
                a_eval: BlsScalar::random(&mut OsRng),
                b_eval: BlsScalar::random(&mut OsRng),
                c_eval: BlsScalar::random(&mut OsRng),
                d_eval: BlsScalar::random(&mut OsRng),
                a_w_eval: BlsScalar::random(&mut OsRng),
                b_w_eval: BlsScalar::random(&mut OsRng),
                d_w_eval: BlsScalar::random(&mut OsRng),
                q_arith_eval: BlsScalar::random(&mut OsRng),
                q_c_eval: BlsScalar::random(&mut OsRng),
                q_l_eval: BlsScalar::random(&mut OsRng),
                q_r_eval: BlsScalar::random(&mut OsRng),
                s_sigma_1_eval: BlsScalar::random(&mut OsRng),
                s_sigma_2_eval: BlsScalar::random(&mut OsRng),
                s_sigma_3_eval: BlsScalar::random(&mut OsRng),
                z_eval: BlsScalar::random(&mut OsRng),
            },
        };

        let proof_bytes = proof.to_bytes();
        let got_proof = Proof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(got_proof, proof);
    }
}
