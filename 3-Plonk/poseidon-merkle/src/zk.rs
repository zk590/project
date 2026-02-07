// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{Opening, ARITY};

use coset_merkle::Aggregate;
use plonk::prelude::{BlsScalar, Composer, Constraint, Witness};
use coset_poseidon::{Domain, HashGadget};

/// Builds the gadget for the poseidon opening and returns the computed
/// root.
pub fn opening_gadget<T, const H: usize>(
    composer: &mut Composer,
    opening: &Opening<T, H>,
    leaf: Witness,
) -> Witness
where
    T: Clone + Aggregate<ARITY>,
{
    // append the siblings and position to the circuit
    let mut level_witnesses = [[Composer::ZERO; ARITY]; H];
    // if i == position: pos_bits[i] = 1 else: pos_bits[i] = 0
    let mut position_bits = [[Composer::ZERO; ARITY]; H];
    for level_index in (0..H).rev() {
        let level = &opening.branch()[level_index];
        for (item_index, item) in level.iter().enumerate() {
            if item_index == opening.positions()[level_index] {
                position_bits[level_index][item_index] =
                    composer.append_witness(BlsScalar::one());
            } else {
                position_bits[level_index][item_index] =
                    composer.append_witness(BlsScalar::zero());
            }

            level_witnesses[level_index][item_index] =
                composer.append_witness(item.hash);
            // ensure that the entries of pos_bits are either 0 or 1
            composer.component_boolean(position_bits[level_index][item_index]);
        }

        // ensure there is *exactly* one bit turned on in the array, by
        // checking that the sum of all position bits equals 1
        let constraint = Constraint::new()
            .left(1)
            .a(position_bits[level_index][0])
            .right(1)
            .b(position_bits[level_index][1])
            .fourth(1)
            .d(position_bits[level_index][2]);
        let mut position_bits_sum = composer.gate_add(constraint);
        let constraint =
            Constraint::new()
                .left(1)
                .a(position_bits_sum)
                .right(1)
                .b(position_bits[level_index][3]);
        position_bits_sum = composer.gate_add(constraint);
        composer.assert_equal_constant(position_bits_sum, BlsScalar::one(), None);
    }

    // keep track of the computed hash along our path with needle
    let mut current_hash_witness = leaf;
    for level_index in (0..H).rev() {
        for item_index in 0..ARITY {
            // assert that:
            // pos_bits[h][i] * level_hash[i] = pos_bits[h][i] * needle
            let constraint = Constraint::new()
                .mult(1)
                .a(position_bits[level_index][item_index])
                .b(level_witnesses[level_index][item_index]);
            let level_hash_constrained = composer.gate_mul(constraint);
            let constraint =
                Constraint::new()
                    .mult(1)
                    .a(position_bits[level_index][item_index])
                    .b(current_hash_witness);
            let current_hash_constrained = composer.gate_mul(constraint);
            // ensure the computed hash matches the stored one
            composer
                .assert_equal(level_hash_constrained, current_hash_constrained);
        }

        // hash the current level
        current_hash_witness = HashGadget::digest(
            composer,
            Domain::Merkle4,
            &level_witnesses[level_index],
        )[0];
    }

    // return the computed root as a witness in the circuit
    current_hash_witness
}
