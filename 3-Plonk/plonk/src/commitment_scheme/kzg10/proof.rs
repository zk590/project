// 模块说明：本文件实现 PLONK 组件（src/commitment_scheme/kzg10/proof.rs）。

//

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
        pub(crate) fn with_witness(witness: Commitment) -> AggregateProof {
            AggregateProof {
                commitment_to_witness: witness,
                evaluated_points: Vec::new(),
                commitments_to_polynomials: Vec::new(),
            }
        }

        pub(crate) fn add_part(&mut self, part: (BlsScalar, Commitment)) {
            self.evaluated_points.push(part.0);
            self.commitments_to_polynomials.push(part.1);
        }

        pub(crate) fn flatten(&self, v_challenge: &BlsScalar) -> Proof {
            let powers = powers_of(
                v_challenge,
                self.commitments_to_polynomials.len() - 1,
            );

            #[cfg(not(feature = "std"))]
            let flattened_poly_commitments_iter =
                self.commitments_to_polynomials.iter().zip(powers.iter());
            #[cfg(not(feature = "std"))]
            let flattened_poly_evaluations_iter =
                self.evaluated_points.iter().zip(powers.iter());

            #[cfg(feature = "std")]
            let flattened_poly_commitments_iter = self
                .commitments_to_polynomials
                .par_iter()
                .zip(powers.par_iter());
            #[cfg(feature = "std")]
            let flattened_poly_evaluations_iter =
                self.evaluated_points.par_iter().zip(powers.par_iter());

            let flattened_poly_commitments: G1Projective =
                flattened_poly_commitments_iter
                    .map(|(poly, v_challenge)| poly.0 * v_challenge)
                    .sum();

            let flattened_poly_evaluations: BlsScalar =
                flattened_poly_evaluations_iter
                    .map(|(eval, v_challenge)| eval * v_challenge)
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
