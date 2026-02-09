// 模块说明：本文件实现 PLONK 组件（src/commitment_scheme/kzg10/key.rs）。

//

use super::{proof::Proof, Commitment};
use crate::{
    error::Error, fft::Polynomial, transcript::TranscriptProtocol, util,
};
use alloc::vec::Vec;
use coset_bls12_381::{
    multiscalar_mul::msm_variable_base, BlsScalar, G1Affine, G1Projective,
    G2Affine, G2Prepared,
};
use coset_bytes::{DeserializableSlice, Serializable};
use merlin::Transcript;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub struct CommitKey {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) powers_of_g: Vec<G1Affine>,
}

impl CommitKey {
    pub fn to_raw_var_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            u64::SIZE + self.powers_of_g.len() * G1Affine::RAW_SIZE,
        );

        let len = self.powers_of_g.len() as u64;
        let len = len.to_le_bytes();
        bytes.extend_from_slice(&len);

        self.powers_of_g
            .iter()
            .for_each(|g| bytes.extend_from_slice(&g.to_raw_bytes()));

        bytes
    }

    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut len = [0u8; u64::SIZE];
        len.copy_from_slice(&bytes[..u64::SIZE]);
        let len = u64::from_le_bytes(len);

        let powers_of_g = bytes[u64::SIZE..]
            .chunks_exact(G1Affine::RAW_SIZE)
            .zip(0..len)
            .map(|(c, _)| G1Affine::from_slice_unchecked(c))
            .collect();

        Self { powers_of_g }
    }

    pub fn to_var_bytes(&self) -> Vec<u8> {
        self.powers_of_g
            .iter()
            .flat_map(|item| item.to_bytes().to_vec())
            .collect()
    }

    pub fn from_slice(bytes: &[u8]) -> Result<CommitKey, Error> {
        let powers_of_g = bytes
            .chunks(G1Affine::SIZE)
            .map(G1Affine::from_slice)
            .collect::<Result<Vec<G1Affine>, coset_bytes::Error>>()?;

        Ok(CommitKey { powers_of_g })
    }

    pub(crate) fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }

    pub(crate) fn truncate(
        &self,
        mut truncated_degree: usize,
    ) -> Result<CommitKey, Error> {
        match truncated_degree {
            0 => Err(Error::TruncatedDegreeIsZero),

            i if i > self.max_degree() => Err(Error::TruncatedDegreeTooLarge),
            i => {
                if i == 1 {
                    truncated_degree += 1
                };
                let truncated_powers = Self {
                    powers_of_g: self.powers_of_g[..=truncated_degree].to_vec(),
                };
                Ok(truncated_powers)
            }
        }
    }

    fn check_commit_degree_is_within_bounds(
        &self,
        poly_degree: usize,
    ) -> Result<(), Error> {
        match (poly_degree == 0, poly_degree > self.max_degree()) {
            (true, _) => Err(Error::PolynomialDegreeIsZero),
            (false, true) => Err(Error::PolynomialDegreeTooLarge),
            (false, false) => Ok(()),
        }
    }

    pub(crate) fn commit(
        &self,
        polynomial: &Polynomial,
    ) -> Result<Commitment, Error> {
        self.check_commit_degree_is_within_bounds(polynomial.degree())?;

        Ok(Commitment::from(msm_variable_base(
            &self.powers_of_g,
            polynomial,
        )))
    }

    pub(crate) fn compute_aggregate_witness(
        polynomials: &[Polynomial],
        point: &BlsScalar,
        v_challenge: &BlsScalar,
    ) -> Polynomial {
        let powers = util::powers_of(v_challenge, polynomials.len() - 1);

        assert_eq!(powers.len(), polynomials.len());

        let numerator: Polynomial = polynomials
            .iter()
            .zip(powers.iter())
            .map(|(poly, v_challenge)| poly * v_challenge)
            .sum();
        numerator.ruffini(*point)
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Sized + Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]

pub struct OpeningKey {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) g: G1Affine,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) h: G2Affine,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) x_h: G2Affine,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) prepared_h: G2Prepared,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) prepared_x_h: G2Prepared,
}

impl Serializable<{ G1Affine::SIZE + G2Affine::SIZE * 2 }> for OpeningKey {
    type Error = coset_bytes::Error;
    #[allow(unused_must_use)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use coset_bytes::Write;
        let mut serialized_opening_key = [0u8; Self::SIZE];
        let mut writer = &mut serialized_opening_key[..];

        writer.write(&self.g.to_bytes());
        writer.write(&self.h.to_bytes());
        writer.write(&self.x_h.to_bytes());

        serialized_opening_key
    }

    fn from_bytes(
        serialized_opening_key: &[u8; Self::SIZE],
    ) -> Result<Self, Self::Error> {
        let mut opening_key_reader = &serialized_opening_key[..];
        let g = G1Affine::from_reader(&mut opening_key_reader)?;
        let h = G2Affine::from_reader(&mut opening_key_reader)?;
        let beta_h = G2Affine::from_reader(&mut opening_key_reader)?;

        Ok(Self::new(g, h, beta_h))
    }
}

impl OpeningKey {
    pub(crate) fn new(g: G1Affine, h: G2Affine, x_h: G2Affine) -> OpeningKey {
        let prepared_h = G2Prepared::from(h);
        let prepared_x_h = G2Prepared::from(x_h);
        OpeningKey {
            g,
            h,
            x_h,
            prepared_h,
            prepared_x_h,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn batch_check(
        &self,
        points: &[BlsScalar],
        proofs: &[Proof],
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        let mut total_c = G1Projective::identity();
        let mut total_w = G1Projective::identity();

        let u_challenge = transcript.challenge_scalar(b"batch");
        let powers = util::powers_of(&u_challenge, proofs.len() - 1);

        let mut g_multiplier = BlsScalar::zero();

        for ((proof, u_challenge), point) in
            proofs.iter().zip(powers).zip(points)
        {
            let mut c = G1Projective::from(proof.commitment_to_polynomial.0);
            let w = proof.commitment_to_witness.0;
            c += w * point;
            g_multiplier += u_challenge * proof.evaluated_point;

            total_c += c * u_challenge;
            total_w += w * u_challenge;
        }
        total_c -= self.g * g_multiplier;

        let affine_total_w = G1Affine::from(-total_w);
        let affine_total_c = G1Affine::from(total_c);

        let pairing = coset_bls12_381::multi_miller_loop(&[
            (&affine_total_w, &self.prepared_x_h),
            (&affine_total_c, &self.prepared_h),
        ])
        .final_exponentiation();

        if pairing != coset_bls12_381::Gt::identity() {
            return Err(Error::PairingCheckFailure);
        };
        Ok(())
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::commitment_scheme::{AggregateProof, PublicParameters};
    use crate::fft::Polynomial;
    use coset_bls12_381::BlsScalar;
    use coset_bytes::Serializable;
    use merlin::Transcript;
    use rand_core::OsRng;

    fn check(op_key: &OpeningKey, point: BlsScalar, proof: Proof) -> bool {
        let inner_a: G1Affine = (proof.commitment_to_polynomial.0
            - (op_key.g * proof.evaluated_point))
            .into();

        let inner_b: G2Affine = (op_key.x_h - (op_key.h * point)).into();
        let prepared_inner_b = G2Prepared::from(-inner_b);

        let pairing = coset_bls12_381::multi_miller_loop(&[
            (&inner_a, &op_key.prepared_h),
            (&proof.commitment_to_witness.0, &prepared_inner_b),
        ])
        .final_exponentiation();

        pairing == coset_bls12_381::Gt::identity()
    }

    fn open_single(
        ck: &CommitKey,
        polynomial: &Polynomial,
        value: &BlsScalar,
        point: &BlsScalar,
    ) -> Result<Proof, Error> {
        let witness_poly = compute_single_witness(polynomial, point);
        Ok(Proof {
            commitment_to_witness: ck.commit(&witness_poly)?,
            evaluated_point: *value,
            commitment_to_polynomial: ck.commit(polynomial)?,
        })
    }

    fn open_multiple(
        ck: &CommitKey,
        polynomials: &[Polynomial],
        evaluations: Vec<BlsScalar>,
        point: &BlsScalar,
        transcript: &mut Transcript,
    ) -> Result<AggregateProof, Error> {
        let mut polynomial_commitments = Vec::with_capacity(polynomials.len());
        for poly in polynomials.iter() {
            polynomial_commitments.push(ck.commit(poly)?)
        }

        let v_challenge = transcript.challenge_scalar(b"v_challenge");

        let witness_poly = CommitKey::compute_aggregate_witness(
            polynomials,
            point,
            &v_challenge,
        );

        let witness_commitment = ck.commit(&witness_poly)?;

        let aggregate_proof = AggregateProof {
            commitment_to_witness: witness_commitment,
            evaluated_points: evaluations,
            commitments_to_polynomials: polynomial_commitments,
        };
        Ok(aggregate_proof)
    }

    fn compute_single_witness(
        polynomial: &Polynomial,
        point: &BlsScalar,
    ) -> Polynomial {
        polynomial.ruffini(*point)
    }

    fn setup_test(degree: usize) -> Result<(CommitKey, OpeningKey), Error> {
        let srs = PublicParameters::setup(degree, &mut OsRng)?;
        srs.trim(degree)
    }
    #[test]
    fn test_basic_commit() -> Result<(), Error> {
        let degree = 25;
        let (ck, opening_key) = setup_test(degree)?;
        let point = BlsScalar::from(10);

        let poly = Polynomial::rand(degree, &mut OsRng);
        let value = poly.evaluate(&point);

        let proof = open_single(&ck, &poly, &value, &point)?;

        let ok = check(&opening_key, point, proof);
        assert!(ok);
        Ok(())
    }
    #[test]
    fn test_batch_verification() -> Result<(), Error> {
        let degree = 25;
        let (ck, vk) = setup_test(degree)?;

        let point_a = BlsScalar::from(10);
        let point_b = BlsScalar::from(11);

        let poly_a = Polynomial::rand(degree, &mut OsRng);
        let value_a = poly_a.evaluate(&point_a);
        let proof_a = open_single(&ck, &poly_a, &value_a, &point_a)?;
        assert!(check(&vk, point_a, proof_a));

        let poly_b = Polynomial::rand(degree, &mut OsRng);
        let value_b = poly_b.evaluate(&point_b);
        let proof_b = open_single(&ck, &poly_b, &value_b, &point_b)?;
        assert!(check(&vk, point_b, proof_b));

        vk.batch_check(
            &[point_a, point_b],
            &[proof_a, proof_b],
            &mut Transcript::new(b""),
        )
    }
    #[test]
    fn test_aggregate_witness() -> Result<(), Error> {
        let max_degree = 27;
        let (ck, opening_key) = setup_test(max_degree)?;
        let point = BlsScalar::from(10);

        let aggregated_proof = {
            let poly_a = Polynomial::rand(25, &mut OsRng);
            let poly_a_eval = poly_a.evaluate(&point);

            let poly_b = Polynomial::rand(26 + 1, &mut OsRng);
            let poly_b_eval = poly_b.evaluate(&point);

            let poly_c = Polynomial::rand(27, &mut OsRng);
            let poly_c_eval = poly_c.evaluate(&point);

            open_multiple(
                &ck,
                &[poly_a, poly_b, poly_c],
                vec![poly_a_eval, poly_b_eval, poly_c_eval],
                &point,
                &mut Transcript::new(b"agg_flatten"),
            )?
        };

        let ok = {
            let transcript = &mut Transcript::new(b"agg_flatten");
            let v_challenge = transcript.challenge_scalar(b"v_challenge");
            let flattened_proof = aggregated_proof.flatten(&v_challenge);
            check(&opening_key, point, flattened_proof)
        };

        assert!(ok);
        Ok(())
    }

    #[test]
    fn test_batch_with_aggregation() -> Result<(), Error> {
        let max_degree = 28;
        let (ck, opening_key) = setup_test(max_degree)?;
        let point_a = BlsScalar::from(10);
        let point_b = BlsScalar::from(11);

        let (aggregated_proof, single_proof) = {
            let poly_a = Polynomial::rand(25, &mut OsRng);
            let poly_a_eval = poly_a.evaluate(&point_a);

            let poly_b = Polynomial::rand(26, &mut OsRng);
            let poly_b_eval = poly_b.evaluate(&point_a);

            let poly_c = Polynomial::rand(27, &mut OsRng);
            let poly_c_eval = poly_c.evaluate(&point_a);

            let poly_d = Polynomial::rand(28, &mut OsRng);
            let poly_d_eval = poly_d.evaluate(&point_b);

            let aggregated_proof = open_multiple(
                &ck,
                &[poly_a, poly_b, poly_c],
                vec![poly_a_eval, poly_b_eval, poly_c_eval],
                &point_a,
                &mut Transcript::new(b"agg_batch"),
            )?;

            let single_proof =
                open_single(&ck, &poly_d, &poly_d_eval, &point_b)?;

            (aggregated_proof, single_proof)
        };

        let mut transcript = Transcript::new(b"agg_batch");
        let v_challenge = transcript.challenge_scalar(b"v_challenge");
        let flattened_proof = aggregated_proof.flatten(&v_challenge);

        opening_key.batch_check(
            &[point_a, point_b],
            &[flattened_proof, single_proof],
            &mut transcript,
        )
    }

    #[test]
    fn commit_key_serde() -> Result<(), Error> {
        let (commit_key, _) = setup_test(11)?;
        let ck_bytes = commit_key.to_var_bytes();
        let ck_bytes_safe = CommitKey::from_slice(&ck_bytes)?;

        assert_eq!(commit_key.powers_of_g, ck_bytes_safe.powers_of_g);
        Ok(())
    }

    #[test]
    fn opening_key_coset_bytes() -> Result<(), Error> {
        let (_, opening_key) = setup_test(7)?;
        let ok_bytes = opening_key.to_bytes();
        let obtained_key = OpeningKey::from_bytes(&ok_bytes)?;

        assert_eq!(opening_key.to_bytes(), obtained_key.to_bytes());
        Ok(())
    }

    #[test]
    fn commit_key_bytes_unchecked() -> Result<(), Error> {
        let (ck, _) = setup_test(7)?;

        let ck_p = unsafe {
            let bytes = ck.to_raw_var_bytes();
            CommitKey::from_slice_unchecked(&bytes)
        };

        assert_eq!(ck, ck_p);
        Ok(())
    }
}
