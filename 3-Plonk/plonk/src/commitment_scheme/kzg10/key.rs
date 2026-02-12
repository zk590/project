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
    /// 将提交键编码为原始字节格式。
    /// 输出包含点数量前缀与每个 G1 点的原始字节表示，适合高性能缓存场景。
    /// 该格式假设输入受信任，不提供强健的结构化错误恢复能力。
    pub fn to_raw_var_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            u64::SIZE + self.powers_of_g.len() * G1Affine::RAW_SIZE,
        );

        let powers_len = self.powers_of_g.len() as u64;
        let powers_len_bytes = powers_len.to_le_bytes();
        bytes.extend_from_slice(&powers_len_bytes);

        self.powers_of_g
            .iter()
            .for_each(|power| bytes.extend_from_slice(&power.to_raw_bytes()));

        bytes
    }

    /// 从原始字节恢复提交键（不做完整校验）。
    /// 调用方需保证字节来源可信且与编码格式严格匹配。
    /// 推荐仅在受控环境中与 `to_raw_var_bytes` 配套使用。
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut powers_len_bytes = [0u8; u64::SIZE];
        powers_len_bytes.copy_from_slice(&bytes[..u64::SIZE]);
        let powers_len = u64::from_le_bytes(powers_len_bytes);

        let powers_of_g = bytes[u64::SIZE..]
            .chunks_exact(G1Affine::RAW_SIZE)
            .zip(0..powers_len)
            .map(|(serialized_power, _)| {
                G1Affine::from_slice_unchecked(serialized_power)
            })
            .collect();

        Self { powers_of_g }
    }

    /// 将提交键编码为安全可解析格式。
    /// 该格式按点序列顺序写入标准压缩字节，便于跨端传输。
    /// 对应的 `from_slice` 会逐点解析并返回结构化错误。
    pub fn to_var_bytes(&self) -> Vec<u8> {
        self.powers_of_g
            .iter()
            .flat_map(|item| item.to_bytes().to_vec())
            .collect()
    }

    /// 从字节切片解析提交键。
    /// 输入按固定点大小分块，每块解析为一个 `G1Affine`。
    /// 任意块解析失败都会中止并返回错误，避免半有效键被误用。
    pub fn from_slice(bytes: &[u8]) -> Result<CommitKey, Error> {
        let powers_of_g = bytes
            .chunks(G1Affine::SIZE)
            .map(G1Affine::from_slice)
            .collect::<Result<Vec<G1Affine>, coset_bytes::Error>>()?;

        Ok(CommitKey { powers_of_g })
    }

    /// 返回提交键支持的最大多项式度数。
    /// 该上界由 `powers_of_g` 长度决定，是提交算法的容量约束核心参数。
    /// 调用方可在提交前用该值进行输入多项式度数预检查。
    pub(crate) fn max_degree(&self) -> usize {
        self.powers_of_g.len() - 1
    }

    /// 裁剪提交键到指定度数范围。
    /// 裁剪后仅保留所需幂次点，减少内存占用并限制可提交多项式规模。
    /// 当目标度数非法（过小或过大）时返回明确错误。
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
                let truncated_commit_key = Self {
                    powers_of_g: self.powers_of_g[..=truncated_degree].to_vec(),
                };
                Ok(truncated_commit_key)
            }
        }
    }

    /// 校验提交多项式度数是否在提交键支持范围内。
    /// 该检查用于在昂贵 MSM 前快速失败，避免不必要计算开销。
    /// 返回值区分“零度非法”与“超过上界”两类错误，便于上层诊断。
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

    /// 对多项式执行 KZG 提交。
    /// 该过程将多项式系数与 SRS 幂次点做 MSM，得到单个承诺点。
    /// 在执行提交前会先进行度数边界校验以保证参数合法。
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

    /// 计算批量打开所需的聚合见证多项式。
    /// 做法是按挑战值幂次线性组合多个多项式，再对目标点执行 Ruffini 除法。
    /// 返回结果可用于一次性生成批量等价见证，降低验证开销。
    pub(crate) fn compute_aggregate_witness(
        polynomials: &[Polynomial],
        point: &BlsScalar,
        v_challenge: &BlsScalar,
    ) -> Polynomial {
        let challenge_powers =
            util::powers_of(v_challenge, polynomials.len() - 1);

        assert_eq!(challenge_powers.len(), polynomials.len());

        let numerator: Polynomial = polynomials
            .iter()
            .zip(challenge_powers.iter())
            .map(|(polynomial, challenge_power)| polynomial * challenge_power)
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
    /// 将 opening key 编码为定长字节。
    /// 编码内容包含 `g`、`h` 与 `x_h`，不包含预处理后的配对辅助结构。
    /// 反序列化时会通过 `new` 自动重建预处理字段。
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use coset_bytes::Write;
        let mut serialized_opening_key = [0u8; Self::SIZE];
        let mut writer = &mut serialized_opening_key[..];

        writer.write(&self.g.to_bytes());
        writer.write(&self.h.to_bytes());
        writer.write(&self.x_h.to_bytes());

        serialized_opening_key
    }

    /// 从定长字节恢复 opening key。
    /// 该过程逐项解析群元素并重新构建配对预处理缓存。
    /// 若任一群元素字节无效则返回错误，防止错误密钥进入验证流程。
    fn from_bytes(
        serialized_opening_key: &[u8; Self::SIZE],
    ) -> Result<Self, Self::Error> {
        let mut opening_key_bytes = &serialized_opening_key[..];
        let generator_g1 = G1Affine::from_reader(&mut opening_key_bytes)?;
        let generator_g2 = G2Affine::from_reader(&mut opening_key_bytes)?;
        let x_h = G2Affine::from_reader(&mut opening_key_bytes)?;

        Ok(Self::new(generator_g1, generator_g2, x_h))
    }
}

impl OpeningKey {
    /// 构造 opening key 并预计算配对加速结构。
    /// 预处理后的 `prepared_h` 与 `prepared_x_h` 可显著降低批量验证开销。
    /// 该构造是反序列化与参数生成路径共享的统一入口。
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
    /// 对一组证明执行批量配对校验。
    /// 该算法通过挑战值将多条等式压缩为两次配对的单条关系。
    /// 若配对结果不是单位元则返回校验失败错误。
    pub(crate) fn batch_check(
        &self,
        points: &[BlsScalar],
        proofs: &[Proof],
        transcript: &mut Transcript,
    ) -> Result<(), Error> {
        let mut total_c = G1Projective::identity();
        let mut total_w = G1Projective::identity();

        let u_challenge = transcript.challenge_scalar(b"batch");
        let challenge_powers = util::powers_of(&u_challenge, proofs.len() - 1);

        let mut g_multiplier = BlsScalar::zero();

        for ((proof, challenge_power), point) in
            proofs.iter().zip(challenge_powers).zip(points)
        {
            let mut polynomial_commitment =
                G1Projective::from(proof.commitment_to_polynomial.0);
            let witness_commitment = proof.commitment_to_witness.0;
            polynomial_commitment += witness_commitment * point;
            g_multiplier += challenge_power * proof.evaluated_point;

            total_c += polynomial_commitment * challenge_power;
            total_w += witness_commitment * challenge_power;
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

        let is_valid = check(&opening_key, point, proof);
        assert!(is_valid);
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

        let is_valid = {
            let transcript = &mut Transcript::new(b"agg_flatten");
            let v_challenge = transcript.challenge_scalar(b"v_challenge");
            let flattened_proof = aggregated_proof.flatten(&v_challenge);
            check(&opening_key, point, flattened_proof)
        };

        assert!(is_valid);
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
