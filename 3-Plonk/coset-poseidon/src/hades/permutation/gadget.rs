// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use coset_bls12_381::BlsScalar;
use plonk::prelude::*;
use dusk_safe::Safe;

use crate::hades::{MDS_MATRIX, ROUND_CONSTANTS, WIDTH};

use super::Hades;

/// An implementation for the [`Hades`] permutation operating on [`Witness`]es.
/// Requires a reference to a plonk circuit [`Composer`].
pub(crate) struct GadgetPermutation<'a> {
    /// A reference to the constraint system used by the gadgets
    composer: &'a mut Composer,
}

impl<'a> GadgetPermutation<'a> {
    /// Constructs a new `GadgetPermutation` with the constraint system.
    pub fn new(composer: &'a mut Composer) -> Self {
        Self { composer }
    }
}

impl<'a> Safe<Witness, WIDTH> for GadgetPermutation<'a> {
    fn permute(&mut self, state: &mut [Witness; WIDTH]) {
        self.perm(state);
    }

    fn tag(&mut self, input: &[u8]) -> Witness {
        let tag = BlsScalar::hash_to_scalar(input.as_ref());
        // append the tag as a constant
        self.composer.append_constant(tag)
    }

    fn add(&mut self, right: &Witness, left: &Witness) -> Witness {
        let constraint = Constraint::new().left(1).a(*left).right(1).b(*right);
        self.composer.gate_add(constraint)
    }
}

impl<'a> Hades<Witness> for GadgetPermutation<'a> {
    fn add_round_constants(
        &mut self,
        round: usize,
        state: &mut [Witness; WIDTH],
    ) {
        // To save constraints we only add the constants here in the first
        // round. The remaining constants will be added in the matrix
        // multiplication.
        if round == 0 {
            state.iter_mut().enumerate().for_each(|(i, w)| {
                let constant = ROUND_CONSTANTS[0][i];
                let constraint =
                    Constraint::new().left(1).a(*w).constant(constant);

                *w = self.composer.gate_add(constraint);
            });
        }
    }

    fn quintic_s_box(&mut self, value: &mut Witness) {
        let constraint = Constraint::new().mult(1).a(*value).b(*value);
        let v2 = self.composer.gate_mul(constraint);

        let constraint = Constraint::new().mult(1).a(v2).b(v2);
        let v4 = self.composer.gate_mul(constraint);

        let constraint = Constraint::new().mult(1).a(v4).b(*value);
        *value = self.composer.gate_mul(constraint);
    }

    /// Adds a constraint for each matrix coefficient multiplication
    fn mul_matrix(&mut self, round: usize, state: &mut [Witness; WIDTH]) {
        let mut result = [Composer::ZERO; WIDTH];

        // Implementation optimized for WIDTH = 5
        //
        // The resulting array `r` will be defined as
        // r[x] = sum_{j=0..WIDTH} ( MDS[x][j] * state[j] ) + c
        // with c being the constant for the next round.
        //
        // q_l = MDS[x][0]
        // q_r = MDS[x][1]
        // q_4 = MDS[x][2]
        // w_l = state[0]
        // w_r = state[1]
        // w_4 = state[2]
        // r[x] = q_l · w_l + q_r · w_r + q_4 · w_4;
        //
        // q_l = MDS[x][3]
        // q_r = MDS[x][4]
        // q_4 = 1
        // w_l = state[3]
        // w_r = state[4]
        // w_4 = r[x]
        // r[x] = q_l · w_l + q_r · w_r + q_4 · w_4 + c;
        for j in 0..WIDTH {
            // c is the next round's constant and hence zero for the last round.
            let c = match round + 1 < Self::ROUNDS {
                true => ROUND_CONSTANTS[round + 1][j],
                false => BlsScalar::zero(),
            };

            let constraint = Constraint::new()
                .left(MDS_MATRIX[j][0])
                .a(state[0])
                .right(MDS_MATRIX[j][1])
                .b(state[1])
                .fourth(MDS_MATRIX[j][2])
                .d(state[2]);

            result[j] = self.composer.gate_add(constraint);

            let constraint = Constraint::new()
                .left(MDS_MATRIX[j][3])
                .a(state[3])
                .right(MDS_MATRIX[j][4])
                .b(state[4])
                .fourth(1)
                .d(result[j])
                .constant(c);

            result[j] = self.composer.gate_add(constraint);
        }

        state.copy_from_slice(&result);
    }
}

#[cfg(feature = "encryption")]
impl dusk_safe::Encryption<Witness, WIDTH> for GadgetPermutation<'_> {
    fn subtract(&mut self, minuend: &Witness, subtrahend: &Witness) -> Witness {
        let constraint = Constraint::new()
            .left(1)
            .a(*minuend)
            .right(-BlsScalar::one())
            .b(*subtrahend);
        self.composer.gate_add(constraint)
    }

    fn is_equal(&mut self, lhs: &Witness, rhs: &Witness) -> bool {
        self.composer.assert_equal(*lhs, *rhs);
        // for the encryption to work we need to return true here, the proof
        // creation will fail at a later point if the above assertion isn't met
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hades::ScalarPermutation;

    use core::result::Result;
    use ff::Field;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[derive(Default)]
    struct TestCircuit {
        input_state: [BlsScalar; WIDTH],
        expected_state: [BlsScalar; WIDTH],
    }

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let zero_witness = Composer::ZERO;

            let mut permuted_witnesses: [Witness; WIDTH] = [zero_witness; WIDTH];

            let mut input_witnesses: [Witness; WIDTH] = [zero_witness; WIDTH];
            self.input_state
                .iter()
                .zip(input_witnesses.iter_mut())
                .for_each(|(input_scalar, witness_slot)| {
                    *witness_slot = composer.append_witness(*input_scalar);
                });

            let mut expected_witnesses: [Witness; WIDTH] = [zero_witness; WIDTH];
            self.expected_state
                .iter()
                .zip(expected_witnesses.iter_mut())
                .for_each(|(expected_scalar, witness_slot)| {
                    *witness_slot = composer.append_witness(*expected_scalar);
                });

            // Apply Hades gadget permutation.
            GadgetPermutation::new(composer).permute(&mut input_witnesses);

            // Copy the result of the permutation into the local result buffer.
            permuted_witnesses.copy_from_slice(&input_witnesses);

            // Check that the Gadget permutation result equals scalar permutation result.
            permuted_witnesses
                .iter()
                .zip(expected_witnesses.iter())
                .for_each(|(permuted_witness, expected_witness)| {
                    composer.assert_equal(*permuted_witness, *expected_witness);
                });

            Ok(())
        }
    }

    /// Generate a random input and perform a permutation
    fn generate_permuted_state() -> ([BlsScalar; WIDTH], [BlsScalar; WIDTH]) {
        let mut input_state = [BlsScalar::zero(); WIDTH];

        let mut deterministic_rng = StdRng::seed_from_u64(0xbeef);

        input_state.iter_mut().for_each(|scalar_slot| {
            *scalar_slot = BlsScalar::random(&mut deterministic_rng)
        });

        let mut expected_state = [BlsScalar::zero(); WIDTH];

        expected_state.copy_from_slice(&input_state);
        ScalarPermutation::new().permute(&mut expected_state);

        (input_state, expected_state)
    }

    /// Setup the test circuit prover and verifier
    fn setup() -> Result<(Prover, Verifier), Error> {
        const CAPACITY: usize = 1 << 10;

        let mut deterministic_rng = StdRng::seed_from_u64(0xbeef);

        let public_parameters =
            PublicParameters::setup(CAPACITY, &mut deterministic_rng)?;
        let circuit_label = b"hades_gadget_tester";

        Compiler::compile::<TestCircuit>(&public_parameters, circuit_label)
    }

    #[test]
    fn preimage() -> Result<(), Error> {
        let (prover, verifier) = setup()?;

        let (input_state, expected_state) = generate_permuted_state();

        let circuit = TestCircuit {
            input_state,
            expected_state,
        };
        let mut deterministic_rng = StdRng::seed_from_u64(0xbeef);

        // Proving
        let (proof, public_inputs) = prover.prove(&mut deterministic_rng, &circuit)?;

        // Verifying
        verifier.verify(&proof, &public_inputs)?;

        Ok(())
    }

    #[test]
    fn preimage_constant() -> Result<(), Error> {
        let (prover, verifier) = setup()?;

        // Prepare input & output
        let input_state = [BlsScalar::from(5000u64); WIDTH];
        let mut expected_state = [BlsScalar::from(5000u64); WIDTH];
        ScalarPermutation::new().permute(&mut expected_state);

        let circuit = TestCircuit {
            input_state,
            expected_state,
        };
        let mut deterministic_rng = StdRng::seed_from_u64(0xbeef);

        // Proving
        let (proof, public_inputs) = prover.prove(&mut deterministic_rng, &circuit)?;

        // Verifying
        verifier.verify(&proof, &public_inputs)?;

        Ok(())
    }

    #[test]
    fn preimage_fails() -> Result<(), Error> {
        let (prover, _) = setup()?;

        // Generate [31, 0, 0, 0, 0] as real input to the perm but build the
        // proof with [31, 31, 31, 31, 31]. This should fail on verification
        // since the Proof contains incorrect statements.
        let special_scalar = BlsScalar::from(31u64);

        let mut input_state = [BlsScalar::zero(); WIDTH];
        input_state[1] = special_scalar;

        let mut expected_state = [BlsScalar::from(31u64); WIDTH];
        ScalarPermutation::new().permute(&mut expected_state);

        let circuit = TestCircuit {
            input_state,
            expected_state,
        };
        let mut deterministic_rng = StdRng::seed_from_u64(0xbeef);

        // Proving should fail
        assert!(
            prover
                .prove(&mut deterministic_rng, &circuit)
                .is_err(),
            "proving should fail since the circuit is invalid"
        );

        Ok(())
    }
}
