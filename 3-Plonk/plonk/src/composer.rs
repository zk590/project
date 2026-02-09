//

use alloc::vec::Vec;
use core::{cmp, ops};
use hashbrown::HashMap;

use coset_bls12_381::BlsScalar;
use coset_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};

use crate::bit_iterator::BitIterator8;
use crate::error::Error;
use crate::runtime::{Runtime, RuntimeEvent};

mod circuit;
mod compress;
mod constraint_system;
mod gate;

pub(crate) mod permutation;

pub use circuit::Circuit;
pub use constraint_system::{Constraint, Witness, WitnessPoint};
pub use gate::Gate;

pub(crate) use constraint_system::{Selector, WireData, WiredWitness};
pub(crate) use permutation::Permutation;

#[derive(Debug, Clone)]
pub struct Composer {
    pub(crate) constraints: Vec<Gate>,

    pub(crate) public_inputs: HashMap<usize, BlsScalar>,

    pub(crate) witnesses: Vec<BlsScalar>,

    pub(crate) perm: Permutation,

    pub(crate) runtime: Runtime,
}

impl ops::Index<Witness> for Composer {
    type Output = BlsScalar;

    fn index(&self, witness: Witness) -> &Self::Output {
        &self.witnesses[witness.index()]
    }
}

impl Composer {
    /// 常量 0 对应的 witness。
    pub const ZERO: Witness = Witness::ZERO;

    /// 常量 1 对应的 witness。
    pub const ONE: Witness = Witness::ONE;

    pub const IDENTITY: WitnessPoint = WitnessPoint::new(Self::ZERO, Self::ONE);

    /// 返回当前电路中的约束数量。
    pub fn constraints(&self) -> usize {
        self.constraints.len()
    }

    pub(crate) fn from_bytes(compressed: &[u8]) -> Result<Self, Error> {
        compress::CompressedCircuit::from_bytes(compressed)
    }

    fn append_witness_internal(&mut self, witness: BlsScalar) -> Witness {
        let witness_index = self.witnesses.len();

        self.perm.new_witness();

        self.witnesses.push(witness);

        Witness::new(witness_index)
    }

    fn append_custom_gate_internal(&mut self, constraint: Constraint) {
        let gate_index = self.constraints.len();

        let left_witness = constraint.witness(WiredWitness::A);
        let right_witness = constraint.witness(WiredWitness::B);
        let output_witness = constraint.witness(WiredWitness::C);
        let fourth_witness = constraint.witness(WiredWitness::D);

        let q_m = *constraint.coeff(Selector::Multiplication);
        let q_l = *constraint.coeff(Selector::Left);
        let q_r = *constraint.coeff(Selector::Right);
        let q_o = *constraint.coeff(Selector::Output);
        let q_f = *constraint.coeff(Selector::Fourth);
        let q_c = *constraint.coeff(Selector::Constant);

        let q_arith = *constraint.coeff(Selector::Arithmetic);
        let q_range = *constraint.coeff(Selector::Range);
        let q_logic = *constraint.coeff(Selector::Logic);
        let q_fixed_group_add = *constraint.coeff(Selector::GroupAddFixedBase);
        let q_variable_group_add =
            *constraint.coeff(Selector::GroupAddVariableBase);

        let gate = Gate {
            q_m,
            q_l,
            q_r,
            q_o,
            q_f,
            q_c,
            q_arith,
            q_range,
            q_logic,
            q_fixed_group_add,
            q_variable_group_add,
            a: left_witness,
            b: right_witness,
            c: output_witness,
            d: fourth_witness,
        };

        self.constraints.push(gate);

        if constraint.has_public_input() {
            let pi = *constraint.coeff(Selector::PublicInput);

            self.public_inputs.insert(gate_index, pi);
        }

        self.perm.add_witnesses_to_map(
            left_witness,
            right_witness,
            output_witness,
            fourth_witness,
            gate_index,
        );
    }

    pub(crate) fn runtime(&mut self) -> &mut Runtime {
        &mut self.runtime
    }

    /// 创建一个已初始化的 `Composer`，并写入基础常量与占位门。
    pub fn initialized() -> Self {
        let mut composer = Self::uninitialized();

        let zero = composer.append_witness(0);
        let one = composer.append_witness(1);

        composer.assert_equal_constant(zero, 0, None);
        composer.assert_equal_constant(one, 1, None);

        composer.append_dummy_gates();

        composer
    }

    /// 创建未初始化 `Composer`（不含基础常量门）。
    pub(crate) fn uninitialized() -> Self {
        Self {
            constraints: Vec::new(),
            public_inputs: HashMap::new(),
            witnesses: Vec::new(),
            perm: Permutation::new(),
            runtime: Runtime::new(),
        }
    }

    fn append_dummy_gates(&mut self) {
        let six = self.append_witness(BlsScalar::from(6));
        let one = self.append_witness(BlsScalar::from(1));
        let seven = self.append_witness(BlsScalar::from(7));
        let min_twenty = self.append_witness(-BlsScalar::from(20));

        let constraint = Constraint::new()
            .mult(1)
            .left(2)
            .right(3)
            .fourth(1)
            .constant(4)
            .output(4)
            .a(six)
            .b(seven)
            .d(one)
            .c(min_twenty);

        self.append_gate(constraint);

        let constraint = Constraint::new()
            .mult(1)
            .left(1)
            .right(1)
            .constant(127)
            .output(1)
            .a(min_twenty)
            .b(six)
            .c(seven);

        self.append_gate(constraint);
    }

    /// 追加一个 witness，并记录运行时事件。
    pub fn append_witness<W: Into<BlsScalar>>(
        &mut self,
        witness: W,
    ) -> Witness {
        let witness = witness.into();

        let witness = self.append_witness_internal(witness);

        let witness_value = self[witness];
        self.runtime().event(RuntimeEvent::WitnessAppended {
            w: witness,
            v: witness_value,
        });

        witness
    }

    /// 追加一条自定义约束门。
    pub fn append_custom_gate(&mut self, constraint: Constraint) {
        self.runtime()
            .event(RuntimeEvent::ConstraintAppended { c: constraint });

        self.append_custom_gate_internal(constraint)
    }

    /// 追加逻辑组件约束，支持按位 `AND/XOR` 聚合。
    pub fn append_logic_component<const BIT_PAIRS: usize>(
        &mut self,
        a: Witness,
        b: Witness,
        is_component_xor: bool,
    ) -> Witness {
        let num_bits = cmp::min(BIT_PAIRS * 2, 256);
        let num_quads = num_bits >> 1;

        let bls_four = BlsScalar::from(4u64);
        let mut left_acc = BlsScalar::zero();
        let mut right_acc = BlsScalar::zero();
        let mut out_acc = BlsScalar::zero();

        let a_bit_iter = BitIterator8::new(self[a].to_bytes());
        let a_bits: Vec<_> = a_bit_iter.skip(256 - num_bits).collect();
        let b_bit_iter = BitIterator8::new(self[b].to_bytes());
        let b_bits: Vec<_> = b_bit_iter.skip(256 - num_bits).collect();

        //
        // * +-----+-----+-----+-----+

        // * +-----+-----+-----+-----+

        // * |  :  |  :  |  :  |  :  |

        // * +-----+-----+-----+-----+

        //

        //

        let mut constraint = if is_component_xor {
            Constraint::logic_xor(&Constraint::new())
        } else {
            Constraint::logic(&Constraint::new())
        };

        for i in 0..num_quads {
            let idx = i * 2;

            let left_most_bit = (a_bits[idx] as u8) << 1;
            let right_most_bit = a_bits[idx + 1] as u8;
            let left_quad = left_most_bit + right_most_bit;
            let left_quad_bls = BlsScalar::from(left_quad as u64);

            let left_most_bit = (b_bits[idx] as u8) << 1;
            let right_most_bit = b_bits[idx + 1] as u8;
            let right_quad = left_most_bit + right_most_bit;
            let right_quad_bls = BlsScalar::from(right_quad as u64);

            let out_quad_bls = if is_component_xor {
                left_quad ^ right_quad
            } else {
                left_quad & right_quad
            } as u64;
            let out_quad_bls = BlsScalar::from(out_quad_bls);

            let prod_quad_bls = (left_quad * right_quad) as u64;
            let prod_quad_bls = BlsScalar::from(prod_quad_bls);

            left_acc = left_acc * bls_four + left_quad_bls;
            right_acc = right_acc * bls_four + right_quad_bls;
            out_acc = out_acc * bls_four + out_quad_bls;

            let wit_a = self.append_witness(left_acc);
            let wit_b = self.append_witness(right_acc);
            let wit_c = self.append_witness(prod_quad_bls);
            let wit_d = self.append_witness(out_acc);

            constraint = constraint.c(wit_c);

            self.append_custom_gate(constraint);

            constraint = constraint.a(wit_a).b(wit_b).d(wit_d);
        }

        let left_witness = constraint.witness(WiredWitness::A);
        let right_witness = constraint.witness(WiredWitness::B);
        let fourth_witness = constraint.witness(WiredWitness::D);

        let constraint = Constraint::new()
            .a(left_witness)
            .b(right_witness)
            .d(fourth_witness);

        self.append_custom_gate(constraint);

        fourth_witness
    }

    pub fn component_mul_generator<P: Into<JubJubExtended>>(
        &mut self,
        jubjub: Witness,
        generator: P,
    ) -> Result<WitnessPoint, Error> {
        let generator = generator.into();

        let bits: usize = 256;

        let mut wnaf_point_multiples: Vec<_> = {
            let mut multiples = vec![JubJubExtended::default(); bits];

            multiples[0] = generator;

            for i in 1..bits {
                multiples[i] = multiples[i - 1].double();
            }

            coset_jubjub::batch_normalize(&mut multiples).collect()
        };

        wnaf_point_multiples.reverse();

        let scalar: JubJubScalar =
            match JubJubScalar::from_bytes(&self[jubjub].to_bytes()).into() {
                Some(s) => s,
                None => return Err(Error::JubJubScalarMalformed),
            };

        let width = 2;
        let wnaf_entries = scalar.compute_windowed_naf(width);

        debug_assert_eq!(
            wnaf_entries.len(),
            bits,
            "the wnaf_entries array is expected to be 256 elements long"
        );

        let mut scalar_acc = vec![BlsScalar::zero()];
        let mut point_acc = vec![JubJubAffine::identity()];

        let two = BlsScalar::from(2u64);
        let xy_alphas: Vec<_> = wnaf_entries
            .iter()
            .rev()
            .enumerate()
            .map(|(i, entry)| {
                let (scalar_to_add, point_to_add) = match entry {
                    0 => (BlsScalar::zero(), JubJubAffine::identity()),
                    -1 => (BlsScalar::one().neg(), -wnaf_point_multiples[i]),
                    1 => (BlsScalar::one(), wnaf_point_multiples[i]),
                    _ => return Err(Error::UnsupportedWNAF2k),
                };

                let prev_accumulator = two * scalar_acc[i];
                let scalar = prev_accumulator + scalar_to_add;
                scalar_acc.push(scalar);

                let accumulated_point = JubJubExtended::from(point_acc[i]);
                let addend_point = JubJubExtended::from(point_to_add);
                let point = accumulated_point + addend_point;
                point_acc.push(point.into());

                let x_alpha = point_to_add.get_u();
                let y_alpha = point_to_add.get_v();

                Ok(x_alpha * y_alpha)
            })
            .collect::<Result<_, Error>>()?;

        for i in 0..bits {
            let acc_x = self.append_witness(point_acc[i].get_u());
            let acc_y = self.append_witness(point_acc[i].get_v());
            let accumulated_bit = self.append_witness(scalar_acc[i]);

            if i == 0 {
                self.assert_equal_constant(acc_x, BlsScalar::zero(), None);
                self.assert_equal_constant(acc_y, BlsScalar::one(), None);
                self.assert_equal_constant(
                    accumulated_bit,
                    BlsScalar::zero(),
                    None,
                );
            }

            let x_beta = wnaf_point_multiples[i].get_u();
            let y_beta = wnaf_point_multiples[i].get_v();

            let xy_alpha = self.append_witness(xy_alphas[i]);
            let xy_beta = x_beta * y_beta;

            let wnaf_round = constraint_system::ecc::WnafRound {
                acc_x,
                acc_y,
                accumulated_bit,
                xy_alpha,
                x_beta,
                y_beta,
                xy_beta,
            };

            let constraint =
                Constraint::group_add_fixed_base(&Constraint::new())
                    .left(wnaf_round.x_beta)
                    .right(wnaf_round.y_beta)
                    .constant(wnaf_round.xy_beta)
                    .a(wnaf_round.acc_x)
                    .b(wnaf_round.acc_y)
                    .c(wnaf_round.xy_alpha)
                    .d(wnaf_round.accumulated_bit);

            self.append_custom_gate(constraint)
        }

        let acc_x = self.append_witness(point_acc[bits].get_u());
        let acc_y = self.append_witness(point_acc[bits].get_v());

        //

        let last_accumulated_bit = self.append_witness(scalar_acc[bits]);

        let constraint =
            Constraint::new().a(acc_x).b(acc_y).d(last_accumulated_bit);
        self.append_gate(constraint);

        self.assert_equal(last_accumulated_bit, jubjub);

        Ok(WitnessPoint::new(acc_x, acc_y))
    }

    pub fn append_gate(&mut self, constraint: Constraint) {
        let constraint = Constraint::arithmetic(&constraint);

        self.append_custom_gate(constraint)
    }

    pub fn append_evaluated_output(
        &mut self,
        s: Constraint,
    ) -> Option<Witness> {
        let left_witness = s.witness(WiredWitness::A);
        let right_witness = s.witness(WiredWitness::B);
        let fourth_witness = s.witness(WiredWitness::D);

        let left_value = self[left_witness];
        let right_value = self[right_witness];
        let fourth_value = self[fourth_witness];

        let qm = s.coeff(Selector::Multiplication);
        let ql = s.coeff(Selector::Left);
        let qr = s.coeff(Selector::Right);
        let qf = s.coeff(Selector::Fourth);
        let qc = s.coeff(Selector::Constant);
        let pi = s.coeff(Selector::PublicInput);

        let polynomial_value = qm * left_value * right_value
            + ql * left_value
            + qr * right_value
            + qf * fourth_value
            + qc
            + pi;

        let output_selector = s.coeff(Selector::Output);

        #[allow(dead_code)]
        let output_value = {
            const ONE: BlsScalar = BlsScalar::one();
            const MINUS_ONE: BlsScalar = BlsScalar([
                0xfffffffd00000003,
                0xfb38ec08fffb13fc,
                0x99ad88181ce5880f,
                0x5bc8f5f97cd877d8,
            ]);

            if output_selector == &ONE {
                Some(-polynomial_value)
            } else if output_selector == &MINUS_ONE {
                Some(polynomial_value)
            } else {
                output_selector.invert().map(|inverse_selector| {
                    polynomial_value * (-inverse_selector)
                })
            }
        };

        output_value.map(|value| self.append_witness(value))
    }

    pub fn append_constant<C: Into<BlsScalar>>(
        &mut self,
        constant: C,
    ) -> Witness {
        let constant = constant.into();
        let witness = self.append_witness(constant);

        self.assert_equal_constant(witness, constant, None);

        witness
    }

    pub fn append_point<P: Into<JubJubAffine>>(
        &mut self,
        affine: P,
    ) -> WitnessPoint {
        let affine = affine.into();

        let point_u_witness = self.append_witness(affine.get_u());
        let point_v_witness = self.append_witness(affine.get_v());

        WitnessPoint::new(point_u_witness, point_v_witness)
    }

    pub fn append_constant_point<P: Into<JubJubAffine>>(
        &mut self,
        affine: P,
    ) -> WitnessPoint {
        let affine = affine.into();

        let point_u_witness = self.append_constant(affine.get_u());
        let point_v_witness = self.append_constant(affine.get_v());

        WitnessPoint::new(point_u_witness, point_v_witness)
    }

    pub fn append_public_point<P: Into<JubJubAffine>>(
        &mut self,
        affine: P,
    ) -> WitnessPoint {
        let affine = affine.into();
        let point = self.append_point(affine);

        self.assert_equal_constant(
            *point.x(),
            BlsScalar::zero(),
            Some(affine.get_u()),
        );

        self.assert_equal_constant(
            *point.y(),
            BlsScalar::zero(),
            Some(affine.get_v()),
        );

        point
    }

    pub fn append_public<P: Into<BlsScalar>>(&mut self, public: P) -> Witness {
        let public = public.into();
        let witness = self.append_witness(public);

        let constraint = Constraint::new()
            .left(-BlsScalar::one())
            .a(witness)
            .public(public);
        self.append_gate(constraint);

        witness
    }

    pub fn assert_equal(
        &mut self,
        left_witness: Witness,
        right_witness: Witness,
    ) {
        let constraint = Constraint::new()
            .left(1)
            .right(-BlsScalar::one())
            .a(left_witness)
            .b(right_witness);

        self.append_gate(constraint);
    }

    pub fn append_logic_and<const BIT_PAIRS: usize>(
        &mut self,
        a: Witness,
        b: Witness,
    ) -> Witness {
        self.append_logic_component::<BIT_PAIRS>(a, b, false)
    }

    pub fn append_logic_xor<const BIT_PAIRS: usize>(
        &mut self,
        a: Witness,
        b: Witness,
    ) -> Witness {
        self.append_logic_component::<BIT_PAIRS>(a, b, true)
    }

    pub fn assert_equal_constant<C: Into<BlsScalar>>(
        &mut self,
        witness: Witness,
        constant: C,
        public: Option<BlsScalar>,
    ) {
        let constant = constant.into();
        let constraint = Constraint::new()
            .left(-BlsScalar::one())
            .a(witness)
            .constant(constant);
        let constraint = public
            .map(|public_input| constraint.public(public_input))
            .unwrap_or(constraint);

        self.append_gate(constraint);
    }

    pub fn assert_equal_point(
        &mut self,
        left_point: WitnessPoint,
        right_point: WitnessPoint,
    ) {
        self.assert_equal(*left_point.x(), *right_point.x());
        self.assert_equal(*left_point.y(), *right_point.y());
    }

    pub fn assert_equal_public_point<P: Into<JubJubAffine>>(
        &mut self,
        point: WitnessPoint,
        public: P,
    ) {
        let public = public.into();

        self.assert_equal_constant(
            *point.x(),
            BlsScalar::zero(),
            Some(public.get_u()),
        );

        self.assert_equal_constant(
            *point.y(),
            BlsScalar::zero(),
            Some(public.get_v()),
        );
    }

    pub fn component_neg_point(&mut self, point: WitnessPoint) -> WitnessPoint {
        let constraint =
            Constraint::new().left(-BlsScalar::one()).a(*point.x());
        let neg_p_x = self.gate_mul(constraint);

        WitnessPoint::new(neg_p_x, *point.y())
    }

    pub fn component_sub_point(
        &mut self,
        a: WitnessPoint,
        b: WitnessPoint,
    ) -> WitnessPoint {
        let neg_b = self.component_neg_point(b);

        self.component_add_point(a, neg_b)
    }

    pub fn component_add_point(
        &mut self,
        a: WitnessPoint,
        b: WitnessPoint,
    ) -> WitnessPoint {
        let x_1 = *a.x();
        let y_1 = *a.y();
        let x_2 = *b.x();
        let y_2 = *b.y();

        let p1 = JubJubAffine::from_raw_unchecked(self[x_1], self[y_1]);
        let p2 = JubJubAffine::from_raw_unchecked(self[x_2], self[y_2]);

        let point: JubJubAffine = (JubJubExtended::from(p1) + p2).into();

        let x_3 = point.get_u();
        let y_3 = point.get_v();

        let x1_y2 = self[x_1] * self[y_2];

        let x_1_y_2 = self.append_witness(x1_y2);
        let x_3 = self.append_witness(x_3);
        let y_3 = self.append_witness(y_3);

        let constraint = Constraint::new().a(x_1).b(y_1).c(x_2).d(y_2);
        let constraint = Constraint::group_add_variable_base(&constraint);

        self.append_custom_gate(constraint);

        let constraint = Constraint::new().a(x_3).b(y_3).d(x_1_y_2);

        self.append_custom_gate(constraint);

        WitnessPoint::new(x_3, y_3)
    }

    pub fn component_boolean(&mut self, witness: Witness) {
        let zero = Self::ZERO;
        let constraint = Constraint::new()
            .mult(1)
            .output(-BlsScalar::one())
            .a(witness)
            .b(witness)
            .c(witness)
            .d(zero);

        self.append_gate(constraint);
    }

    pub fn component_decomposition<const N: usize>(
        &mut self,
        scalar: Witness,
    ) -> [Witness; N] {
        assert!(0 < N && N <= 256);

        let mut decomposition = [Self::ZERO; N];

        let acc = Self::ZERO;
        let acc = self[scalar]
            .to_bits()
            .iter()
            .enumerate()
            .zip(decomposition.iter_mut())
            .fold(acc, |acc, ((i, bit), w_bit)| {
                *w_bit = self.append_witness(BlsScalar::from(*bit as u64));

                self.component_boolean(*w_bit);

                let constraint = Constraint::new()
                    .left(BlsScalar::pow_of_2(i as u64))
                    .right(1)
                    .a(*w_bit)
                    .b(acc);

                self.gate_add(constraint)
            });

        self.assert_equal(acc, scalar);

        decomposition
    }

    pub fn component_select_identity(
        &mut self,
        bit: Witness,
        selected_point: WitnessPoint,
    ) -> WitnessPoint {
        let selected_x = self.component_select_zero(bit, *selected_point.x());
        let selected_y = self.component_select_one(bit, *selected_point.y());

        WitnessPoint::new(selected_x, selected_y)
    }

    pub fn component_mul_point(
        &mut self,
        jubjub: Witness,
        point: WitnessPoint,
    ) -> WitnessPoint {
        let scalar_bits = self.component_decomposition::<252>(jubjub);

        let mut result = Self::IDENTITY;

        for bit in scalar_bits.iter().rev() {
            result = self.component_add_point(result, result);

            let point_to_add = self.component_select_identity(*bit, point);
            result = self.component_add_point(result, point_to_add);
        }

        result
    }

    pub fn component_select(
        &mut self,
        bit: Witness,
        a: Witness,
        b: Witness,
    ) -> Witness {
        let constraint = Constraint::new().mult(1).a(bit).b(a);
        let bit_times_a = self.gate_mul(constraint);

        let constraint =
            Constraint::new().left(-BlsScalar::one()).constant(1).a(bit);
        let one_min_bit = self.gate_add(constraint);

        let constraint = Constraint::new().mult(1).a(one_min_bit).b(b);
        let one_min_bit_b = self.gate_mul(constraint);

        let constraint = Constraint::new()
            .left(1)
            .right(1)
            .a(one_min_bit_b)
            .b(bit_times_a);
        self.gate_add(constraint)
    }

    pub fn component_select_one(
        &mut self,
        bit: Witness,
        value: Witness,
    ) -> Witness {
        let bit_value = self[bit];
        let selected_value = self[value];

        let output_value =
            BlsScalar::one() - bit_value + (bit_value * selected_value);
        let output_witness = self.append_witness(output_value);

        let constraint = Constraint::new()
            .mult(1)
            .left(-BlsScalar::one())
            .output(-BlsScalar::one())
            .constant(1)
            .a(bit)
            .b(value)
            .c(output_witness);

        self.append_gate(constraint);

        output_witness
    }

    pub fn component_select_point(
        &mut self,
        bit: Witness,
        left_point: WitnessPoint,
        right_point: WitnessPoint,
    ) -> WitnessPoint {
        let selected_x =
            self.component_select(bit, *left_point.x(), *right_point.x());
        let selected_y =
            self.component_select(bit, *left_point.y(), *right_point.y());

        WitnessPoint::new(selected_x, selected_y)
    }

    pub fn component_select_zero(
        &mut self,
        bit: Witness,
        value: Witness,
    ) -> Witness {
        let constraint = Constraint::new().mult(1).a(bit).b(value);

        self.gate_mul(constraint)
    }

    pub fn component_range<const BIT_PAIRS: usize>(
        &mut self,
        witness: Witness,
    ) {
        let num_bits = cmp::min(BIT_PAIRS * 2, 256);

        if num_bits == 0 {
            let constraint = Constraint::new().left(1).a(witness);
            self.append_gate(constraint);
            return;
        }

        let bits = self[witness];
        let bit_iter = BitIterator8::new(bits.to_bytes());
        let mut bits: Vec<_> = bit_iter.collect();
        bits.reverse();

        let mut num_gates = num_bits >> 3;

        if num_bits % 8 != 0 {
            num_gates += 1;
        }

        let num_quads = num_gates * 4;

        let pad = 1 + (((num_quads << 1) - num_bits) >> 1);

        let used_gates = num_gates + 1;

        let base = Constraint::new();
        let base = Constraint::range(&base);
        let mut constraints = vec![base; used_gates];

        let mut accumulators: Vec<Witness> = Vec::new();
        let mut accumulator = BlsScalar::zero();
        let four = BlsScalar::from(4);

        for i in pad..=num_quads {
            let bit_index = (num_quads - i) << 1;
            let q_0 = bits[bit_index] as u64;
            let q_1 = bits[bit_index + 1] as u64;
            let quad = q_0 + (2 * q_1);

            accumulator = four * accumulator;
            accumulator += BlsScalar::from(quad);

            let accumulator_var = self.append_witness(accumulator);

            accumulators.push(accumulator_var);

            let idx = i / 4;
            let witness = match i % 4 {
                0 => WiredWitness::D,
                1 => WiredWitness::C,
                2 => WiredWitness::B,
                3 => WiredWitness::A,
                _ => unreachable!(),
            };

            constraints[idx].set_witness(witness, accumulator_var);
        }

        if let Some(last_constraint) = constraints.last_mut() {
            *last_constraint = Constraint::new();
        }

        if let Some(accumulator) = accumulators.last() {
            if let Some(last_constraint) = constraints.last_mut() {
                last_constraint.set_witness(WiredWitness::D, *accumulator);
            }
        }

        constraints
            .into_iter()
            .for_each(|constraint| self.append_custom_gate(constraint));

        if let Some(accumulator) = accumulators.last() {
            self.assert_equal(*accumulator, witness);
        }
    }

    pub fn gate_add(&mut self, constraint: Constraint) -> Witness {
        let arithmetic_constraint =
            Constraint::arithmetic(&constraint).output(-BlsScalar::one());

        let output_witness = self
            .append_evaluated_output(arithmetic_constraint)
            .expect("output selector is -1");
        let arithmetic_constraint = arithmetic_constraint.c(output_witness);

        self.append_gate(arithmetic_constraint);

        output_witness
    }

    pub fn gate_mul(&mut self, constraint: Constraint) -> Witness {
        let arithmetic_constraint =
            Constraint::arithmetic(&constraint).output(-BlsScalar::one());

        let output_witness = self
            .append_evaluated_output(arithmetic_constraint)
            .expect("output selector is -1");
        let arithmetic_constraint = arithmetic_constraint.c(output_witness);

        self.append_gate(arithmetic_constraint);

        output_witness
    }

    pub fn prove<C>(constraints: usize, circuit: &C) -> Result<Self, Error>
    where
        C: Circuit,
    {
        let mut composer = Self::initialized();

        circuit.circuit(&mut composer)?;

        let description_size = composer.constraints();
        if description_size != constraints {
            return Err(Error::InvalidCircuitSize(
                description_size,
                constraints,
            ));
        }

        composer.runtime().event(RuntimeEvent::ProofFinished);

        Ok(composer)
    }

    pub(crate) fn public_input_indexes(&self) -> Vec<usize> {
        let mut public_input_indexes: Vec<_> =
            self.public_inputs.keys().copied().collect();

        public_input_indexes.as_mut_slice().sort();

        public_input_indexes
    }

    pub(crate) fn public_inputs(&self) -> Vec<BlsScalar> {
        self.public_input_indexes()
            .iter()
            .filter_map(|idx| self.public_inputs.get(idx).copied())
            .collect()
    }

    pub(crate) fn dense_public_inputs(
        public_input_indexes: &[usize],
        public_inputs: &[BlsScalar],
        size: usize,
    ) -> Vec<BlsScalar> {
        let mut dense_public_inputs = vec![BlsScalar::zero(); size];

        public_input_indexes
            .iter()
            .zip(public_inputs.iter())
            .for_each(|(idx, pi)| dense_public_inputs[*idx] = *pi);

        dense_public_inputs
    }
}
