


//


use crate::{Opening, ARITY};

use coset_merkle::Aggregate;
use plonk::prelude::{BlsScalar, Composer, Constraint, Witness};
use coset_poseidon::{Domain, HashGadget};



/// 在电路中验证 Merkle opening，并返回逐层重建后的根哈希 witness。
pub fn opening_gadget<T, const H: usize>(
    composer: &mut Composer,
    opening: &Opening<T, H>,
    leaf: Witness,
) -> Witness
where
    T: Clone + Aggregate<ARITY>,
{

    // 每一层的分支哈希 witness。
    let mut level_witnesses = [[Composer::ZERO; ARITY]; H];

    // 每一层位置 one-hot 位：仅真实路径索引为 1。
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

            composer.component_boolean(position_bits[level_index][item_index]);
        }



        // 约束 one-hot 位之和必须为 1，确保每层仅选择一个分支。
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


    // 自底向上校验路径节点并重算父层哈希。
    let mut current_hash_witness = leaf;
    for level_index in (0..H).rev() {
        for item_index in 0..ARITY {


            // 被选中的分支哈希必须等于当前层传入哈希。
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

            composer
                .assert_equal(level_hash_constrained, current_hash_constrained);
        }


        current_hash_witness = HashGadget::digest(
            composer,
            Domain::Merkle4,
            &level_witnesses[level_index],
        )[0];
    }


    current_hash_witness
}
