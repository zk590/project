use super::Commitment;
use coset_bls12_381::BlsScalar;

#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct Proof {
    pub(crate) commitment_to_witness: Commitment,

    pub(crate) evaluated_point: BlsScalar,

    pub(crate) commitment_to_polynomial: Commitment,
}

#[cfg(feature = "alloc")]
pub(crate) mod alloc {
    use super::*;
    use crate::util::powers_of;
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use coset_bls12_381::G1Projective;
    #[cfg(feature = "std")]
    use rayon::prelude::*;

    #[derive(Debug)]
    #[allow(dead_code)]
    pub(crate) struct AggregateProof {
        pub(crate) commitment_to_witness: Commitment,

        pub(crate) evaluated_points: Vec<BlsScalar>,

        pub(crate) commitments_to_polynomials: Vec<Commitment>,
    }

    #[allow(dead_code)]
    impl AggregateProof {
        /// 使用见证承诺初始化聚合证明容器。
        /// 初始状态仅包含共享 witness 承诺，评估点与多项式承诺留空待追加。
        /// 该构造通常在批量打开流程中作为累加器起点使用。
        pub(crate) fn with_witness(witness: Commitment) -> AggregateProof {
            AggregateProof {
                commitment_to_witness: witness,
                evaluated_points: Vec::new(),
                commitments_to_polynomials: Vec::new(),
            }
        }

        /// 追加一个待聚合证明片段。
        /// 输入包含单点评估值与对应多项式承诺，顺序会影响最终线性组合。
        /// 所有片段应来自同一批次上下文，确保挑战幂次对齐。
        pub(crate) fn add_part(&mut self, proof_part: (BlsScalar, Commitment)) {
            self.evaluated_points.push(proof_part.0);
            self.commitments_to_polynomials.push(proof_part.1);
        }

        /// 按挑战值幂次将聚合容器压平为单个证明。
        /// 该步骤分别对承诺与评估值做同构线性组合，得到可一次校验的等价证明。
        /// 挑战值必须与转录器上下文绑定，否则会破坏批量验证的安全性。
        pub(crate) fn flatten(&self, challenge: &BlsScalar) -> Proof {
            let challenge_powers =
                powers_of(challenge, self.commitments_to_polynomials.len() - 1);

            #[cfg(not(feature = "std"))]
            let flattened_poly_commitments_iter = self
                .commitments_to_polynomials
                .iter()
                .zip(challenge_powers.iter());
            #[cfg(not(feature = "std"))]
            let flattened_poly_evaluations_iter =
                self.evaluated_points.iter().zip(challenge_powers.iter());

            #[cfg(feature = "std")]
            let flattened_poly_commitments_iter = self
                .commitments_to_polynomials
                .par_iter()
                .zip(challenge_powers.par_iter());
            #[cfg(feature = "std")]
            let flattened_poly_evaluations_iter = self
                .evaluated_points
                .par_iter()
                .zip(challenge_powers.par_iter());

            let flattened_poly_commitments: G1Projective =
                flattened_poly_commitments_iter
                    .map(|(polynomial_commitment, challenge_power)| {
                        polynomial_commitment.0 * challenge_power
                    })
                    .sum();

            let flattened_poly_evaluations: BlsScalar =
                flattened_poly_evaluations_iter
                    .map(|(evaluation, challenge_power)| {
                        evaluation * challenge_power
                    })
                    .sum();

            Proof {
                commitment_to_witness: self.commitment_to_witness,
                evaluated_point: flattened_poly_evaluations,
                commitment_to_polynomial: Commitment::from(
                    flattened_poly_commitments,
                ),
            }
        }
    }
}
