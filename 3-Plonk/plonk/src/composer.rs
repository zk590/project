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

    /// 通过 witness 索引读取其对应标量值。
    /// 该实现让 `Composer` 可用下标语法访问 witness，提升约束构造可读性。
    /// 调用方需保证 witness 来源于当前 composer，否则会触发越界 panic。
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

    /// 从压缩字节恢复 `Composer`。
    /// 该接口主要用于电路缓存回放或跨进程传输后的重建场景。
    /// 反序列化失败时会返回统一 `Error`，由调用方决定重试或回退策略。
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
            let public_input_value = *constraint.coeff(Selector::PublicInput);

            self.public_inputs.insert(gate_index, public_input_value);
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
    /// 该构造只分配空容器，不插入任何 witness/constraint。
    /// 适用于高级调用方完全手动控制初始化时序的场景。
    /// 若用于常规电路构建，建议优先使用 `initialized()`。
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
            witness,
            value: witness_value,
        });

        witness
    }

    /// 追加一条自定义约束门。
    pub fn append_custom_gate(&mut self, constraint: Constraint) {
        self.runtime()
            .event(RuntimeEvent::ConstraintAppended { constraint });

        self.append_custom_gate_internal(constraint)
    }

    /// 追加逻辑组件约束，支持按位 `AND/XOR` 聚合。
    pub fn append_logic_component<const BIT_PAIRS: usize>(
        &mut self,
        left_witness: Witness,
        right_witness: Witness,
        is_component_xor: bool,
    ) -> Witness {
        let constrained_bit_count = cmp::min(BIT_PAIRS * 2, 256);
        let quad_count = constrained_bit_count >> 1;

        let bls_four = BlsScalar::from(4u64);
        let mut left_acc = BlsScalar::zero();
        let mut right_acc = BlsScalar::zero();
        let mut out_acc = BlsScalar::zero();

        let left_bit_iterator =
            BitIterator8::new(self[left_witness].to_bytes());
        let left_bits: Vec<_> = left_bit_iterator
            .skip(256 - constrained_bit_count)
            .collect();
        let right_bit_iterator =
            BitIterator8::new(self[right_witness].to_bytes());
        let right_bits: Vec<_> = right_bit_iterator
            .skip(256 - constrained_bit_count)
            .collect();

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

        for quad_index in 0..quad_count {
            let bit_index = quad_index * 2;

            let left_most_bit = (left_bits[bit_index] as u8) << 1;
            let right_most_bit = left_bits[bit_index + 1] as u8;
            let left_quad = left_most_bit + right_most_bit;
            let left_quad_bls = BlsScalar::from(left_quad as u64);

            let left_most_bit = (right_bits[bit_index] as u8) << 1;
            let right_most_bit = right_bits[bit_index + 1] as u8;
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
        let bits: usize = 256;
        let mut wnaf_point_multiples =
            self.build_wnaf_point_multiples(generator.into(), bits);
        wnaf_point_multiples.reverse();

        let scalar_value = self.parse_jubjub_scalar(jubjub)?;

        let width = 2;
        let wnaf_entries = scalar_value.compute_windowed_naf(width);

        debug_assert_eq!(
            wnaf_entries.len(),
            bits,
            "the wnaf_entries array is expected to be 256 elements long"
        );

        let mut scalar_acc = vec![BlsScalar::zero()];
        let mut point_acc = vec![JubJubAffine::identity()];

        let two = BlsScalar::from(2u64);
        let addend_xy_products: Vec<_> = wnaf_entries
            .iter()
            .rev()
            .enumerate()
            .map(|(wnaf_index, entry)| {
                let (scalar_to_add, point_to_add) = match entry {
                    0 => (BlsScalar::zero(), JubJubAffine::identity()),
                    -1 => (
                        BlsScalar::one().neg(),
                        -wnaf_point_multiples[wnaf_index],
                    ),
                    1 => (BlsScalar::one(), wnaf_point_multiples[wnaf_index]),
                    _ => return Err(Error::UnsupportedWNAF2k),
                };

                let prev_accumulator = two * scalar_acc[wnaf_index];
                let scalar = prev_accumulator + scalar_to_add;
                scalar_acc.push(scalar);

                let accumulated_point =
                    JubJubExtended::from(point_acc[wnaf_index]);
                let addend_point = JubJubExtended::from(point_to_add);
                let point = accumulated_point + addend_point;
                point_acc.push(point.into());

                let x_alpha = point_to_add.get_u();
                let y_alpha = point_to_add.get_v();

                Ok(x_alpha * y_alpha)
            })
            .collect::<Result<_, Error>>()?;

        for round_index in 0..bits {
            let accumulator_x =
                self.append_witness(point_acc[round_index].get_u());
            let accumulator_y =
                self.append_witness(point_acc[round_index].get_v());
            let accumulated_scalar =
                self.append_witness(scalar_acc[round_index]);

            if round_index == 0 {
                self.assert_equal_constant(
                    accumulator_x,
                    BlsScalar::zero(),
                    None,
                );
                self.assert_equal_constant(
                    accumulator_y,
                    BlsScalar::one(),
                    None,
                );
                self.assert_equal_constant(
                    accumulated_scalar,
                    BlsScalar::zero(),
                    None,
                );
            }

            let precomputed_x = wnaf_point_multiples[round_index].get_u();
            let precomputed_y = wnaf_point_multiples[round_index].get_v();

            let addend_xy_product =
                self.append_witness(addend_xy_products[round_index]);
            let precomputed_xy_product = precomputed_x * precomputed_y;

            let wnaf_round = constraint_system::ecc::WnafRound {
                accumulator_x,
                accumulator_y,
                accumulated_scalar,
                addend_xy_product,
                precomputed_x,
                precomputed_y,
                precomputed_xy_product,
            };

            self.append_wnaf_round_gate(wnaf_round);
        }

        let final_accumulator_x = self.append_witness(point_acc[bits].get_u());
        let final_accumulator_y = self.append_witness(point_acc[bits].get_v());

        //

        let final_accumulated_scalar = self.append_witness(scalar_acc[bits]);

        let constraint = Constraint::new()
            .a(final_accumulator_x)
            .b(final_accumulator_y)
            .d(final_accumulated_scalar);
        self.append_gate(constraint);

        self.assert_equal(final_accumulated_scalar, jubjub);

        Ok(WitnessPoint::new(final_accumulator_x, final_accumulator_y))
    }

    /// 构造 fixed-base 标量乘所需的预计算点表。
    /// 结果按连续二倍序列生成，后续会按 WNAF 扫描方向反转使用。
    /// 该辅助函数只负责点表准备，不涉及约束写入。
    fn build_wnaf_point_multiples(
        &self,
        generator: JubJubExtended,
        bits: usize,
    ) -> Vec<JubJubAffine> {
        let mut multiples = vec![JubJubExtended::default(); bits];
        multiples[0] = generator;

        for multiple_index in 1..bits {
            multiples[multiple_index] = multiples[multiple_index - 1].double();
        }

        coset_jubjub::batch_normalize(&mut multiples).collect()
    }

    /// 从 witness 读取并解析 JubJub 标量。
    /// 若字节不满足标量域约束，返回 `JubJubScalarMalformed`。
    /// 该检查用于避免无效输入进入 WNAF 约束流程。
    fn parse_jubjub_scalar(
        &self,
        scalar_witness: Witness,
    ) -> Result<JubJubScalar, Error> {
        match JubJubScalar::from_bytes(&self[scalar_witness].to_bytes()).into()
        {
            Some(parsed_scalar) => Ok(parsed_scalar),
            None => Err(Error::JubJubScalarMalformed),
        }
    }

    /// 追加一轮 fixed-base WNAF 约束门。
    /// 该门把预计算点、累加点与累加标量关系编码为群加法约束。
    /// 该辅助函数用于减少 `component_mul_generator` 的重复模板代码。
    fn append_wnaf_round_gate(
        &mut self,
        wnaf_round: constraint_system::ecc::WnafRound<Witness>,
    ) {
        let constraint = Constraint::group_add_fixed_base(&Constraint::new())
            .left(wnaf_round.precomputed_x)
            .right(wnaf_round.precomputed_y)
            .constant(wnaf_round.precomputed_xy_product)
            .a(wnaf_round.accumulator_x)
            .b(wnaf_round.accumulator_y)
            .c(wnaf_round.addend_xy_product)
            .d(wnaf_round.accumulated_scalar);

        self.append_custom_gate(constraint)
    }

    pub fn append_gate(&mut self, constraint: Constraint) {
        let constraint = Constraint::arithmetic(&constraint);

        self.append_custom_gate(constraint)
    }

    pub fn append_evaluated_output(
        &mut self,
        constraint: Constraint,
    ) -> Option<Witness> {
        let left_witness = constraint.witness(WiredWitness::A);
        let right_witness = constraint.witness(WiredWitness::B);
        let fourth_witness = constraint.witness(WiredWitness::D);

        let left_value = self[left_witness];
        let right_value = self[right_witness];
        let fourth_value = self[fourth_witness];

        let multiplication_selector =
            constraint.coeff(Selector::Multiplication);
        let left_selector = constraint.coeff(Selector::Left);
        let right_selector = constraint.coeff(Selector::Right);
        let fourth_selector = constraint.coeff(Selector::Fourth);
        let constant_selector = constraint.coeff(Selector::Constant);
        let public_input_selector = constraint.coeff(Selector::PublicInput);

        let polynomial_value =
            multiplication_selector * left_value * right_value
                + left_selector * left_value
                + right_selector * right_value
                + fourth_selector * fourth_value
                + constant_selector
                + public_input_selector;

        let output_selector = constraint.coeff(Selector::Output);

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
        point: P,
    ) -> WitnessPoint {
        let point = point.into();

        let point_x_witness = self.append_witness(point.get_u());
        let point_y_witness = self.append_witness(point.get_v());

        WitnessPoint::new(point_x_witness, point_y_witness)
    }

    pub fn append_constant_point<P: Into<JubJubAffine>>(
        &mut self,
        point: P,
    ) -> WitnessPoint {
        let point = point.into();

        let point_x_witness = self.append_constant(point.get_u());
        let point_y_witness = self.append_constant(point.get_v());

        WitnessPoint::new(point_x_witness, point_y_witness)
    }

    pub fn append_public_point<P: Into<JubJubAffine>>(
        &mut self,
        point: P,
    ) -> WitnessPoint {
        let point = point.into();
        let witness_point = self.append_point(point);

        self.assert_equal_constant(
            *witness_point.x(),
            BlsScalar::zero(),
            Some(point.get_u()),
        );

        self.assert_equal_constant(
            *witness_point.y(),
            BlsScalar::zero(),
            Some(point.get_v()),
        );

        witness_point
    }

    pub fn append_public<P: Into<BlsScalar>>(
        &mut self,
        public_value: P,
    ) -> Witness {
        let public_value = public_value.into();
        let witness = self.append_witness(public_value);

        let constraint = Constraint::new()
            .left(-BlsScalar::one())
            .a(witness)
            .public(public_value);
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
        left_witness: Witness,
        right_witness: Witness,
    ) -> Witness {
        self.append_logic_component::<BIT_PAIRS>(
            left_witness,
            right_witness,
            false,
        )
    }

    pub fn append_logic_xor<const BIT_PAIRS: usize>(
        &mut self,
        left_witness: Witness,
        right_witness: Witness,
    ) -> Witness {
        self.append_logic_component::<BIT_PAIRS>(
            left_witness,
            right_witness,
            true,
        )
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
        public_point: P,
    ) {
        let public_point = public_point.into();

        self.assert_public_coordinate(*point.x(), public_point.get_u());
        self.assert_public_coordinate(*point.y(), public_point.get_v());
    }

    /// 对单个坐标施加“等于公开输入”的约束。
    /// 内部沿用 `assert_equal_constant(..., 0, Some(public_value))` 语义。
    /// 该辅助函数用于减少公开点坐标断言中的重复代码。
    fn assert_public_coordinate(
        &mut self,
        coordinate_witness: Witness,
        public_value: BlsScalar,
    ) {
        self.assert_equal_constant(
            coordinate_witness,
            BlsScalar::zero(),
            Some(public_value),
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
        left_point: WitnessPoint,
        right_point: WitnessPoint,
    ) -> WitnessPoint {
        let neg_right_point = self.component_neg_point(right_point);

        self.component_add_point(left_point, neg_right_point)
    }

    /// 追加可变基点加法的关系门（仅约束输入点之间的群关系）。
    /// 该门负责把左右输入点绑定到 variable-base 加法约束系统。
    /// 输出点 witness 的一致性由后续补充门单独约束。
    fn append_variable_base_addition_gate(
        &mut self,
        left_x_witness: Witness,
        left_y_witness: Witness,
        right_x_witness: Witness,
        right_y_witness: Witness,
    ) {
        let constraint = Constraint::new()
            .a(left_x_witness)
            .b(left_y_witness)
            .c(right_x_witness)
            .d(right_y_witness);
        let constraint = Constraint::group_add_variable_base(&constraint);
        self.append_custom_gate(constraint);
    }

    /// 追加点加法输出一致性门。
    /// 该门把 `sum_x/sum_y` 与中间乘积 witness 绑定，完成可验证输出落盘。
    /// 该拆分可减少 `component_add_point` 中重复模板拼装代码。
    fn append_point_addition_output_gate(
        &mut self,
        sum_x_witness: Witness,
        sum_y_witness: Witness,
        left_x_mul_right_y_witness: Witness,
    ) {
        let constraint = Constraint::new()
            .a(sum_x_witness)
            .b(sum_y_witness)
            .d(left_x_mul_right_y_witness);
        self.append_custom_gate(constraint);
    }

    pub fn component_add_point(
        &mut self,
        left_point: WitnessPoint,
        right_point: WitnessPoint,
    ) -> WitnessPoint {
        let left_x_witness = *left_point.x();
        let left_y_witness = *left_point.y();
        let right_x_witness = *right_point.x();
        let right_y_witness = *right_point.y();

        let left_affine = JubJubAffine::from_raw_unchecked(
            self[left_x_witness],
            self[left_y_witness],
        );
        let right_affine = JubJubAffine::from_raw_unchecked(
            self[right_x_witness],
            self[right_y_witness],
        );

        let sum_point: JubJubAffine =
            (JubJubExtended::from(left_affine) + right_affine).into();

        let sum_x = sum_point.get_u();
        let sum_y = sum_point.get_v();

        let left_x_mul_right_y = self[left_x_witness] * self[right_y_witness];

        let left_x_mul_right_y_witness =
            self.append_witness(left_x_mul_right_y);
        let sum_x_witness = self.append_witness(sum_x);
        let sum_y_witness = self.append_witness(sum_y);

        self.append_variable_base_addition_gate(
            left_x_witness,
            left_y_witness,
            right_x_witness,
            right_y_witness,
        );
        self.append_point_addition_output_gate(
            sum_x_witness,
            sum_y_witness,
            left_x_mul_right_y_witness,
        );

        WitnessPoint::new(sum_x_witness, sum_y_witness)
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

        let initial_accumulator = Self::ZERO;
        let final_accumulator = self[scalar]
            .to_bits()
            .iter()
            .enumerate()
            .zip(decomposition.iter_mut())
            .fold(
                initial_accumulator,
                |running_accumulator, ((bit_index, bit), bit_witness_slot)| {
                    let bit_witness =
                        self.append_boolean_bit_witness(*bit as u64);
                    *bit_witness_slot = bit_witness;

                    self.accumulate_decomposition_bit(
                        bit_index,
                        bit_witness,
                        running_accumulator,
                    )
                },
            );

        self.assert_equal(final_accumulator, scalar);

        decomposition
    }

    /// 追加一个布尔 bit witness，并施加布尔约束。
    /// 输入为 `0/1` 数值，输出为对应 witness。
    /// 该辅助函数用于统一分解流程中的 bit 写入逻辑。
    fn append_boolean_bit_witness(&mut self, bit_value: u64) -> Witness {
        let bit_witness = self.append_witness(BlsScalar::from(bit_value));
        self.component_boolean(bit_witness);
        bit_witness
    }

    /// 把一个 bit 按位权累加到分解累加器。
    /// 约束形式与原实现保持一致：`2^i * bit + accumulator`。
    /// 返回更新后的累加器 witness。
    fn accumulate_decomposition_bit(
        &mut self,
        bit_index: usize,
        bit_witness: Witness,
        running_accumulator: Witness,
    ) -> Witness {
        let constraint = Constraint::new()
            .left(BlsScalar::pow_of_2(bit_index as u64))
            .right(1)
            .a(bit_witness)
            .b(running_accumulator);
        self.gate_add(constraint)
    }

    pub fn component_select_identity(
        &mut self,
        bit: Witness,
        selected_point: WitnessPoint,
    ) -> WitnessPoint {
        let selected_coordinates =
            self.select_identity_coordinates(bit, selected_point);
        Self::witness_point_from_coordinates(selected_coordinates)
    }

    /// 选择点坐标或单位元坐标。
    /// 对 x 坐标执行 `bit * x`，对 y 坐标执行 `1 - bit + bit * y`。
    /// 返回值分别对应选中点的 x/y witness。
    fn select_identity_coordinates(
        &mut self,
        bit: Witness,
        selected_point: WitnessPoint,
    ) -> (Witness, Witness) {
        let selected_x = self.component_select_zero(bit, *selected_point.x());
        let selected_y = self.component_select_one(bit, *selected_point.y());
        (selected_x, selected_y)
    }

    pub fn component_mul_point(
        &mut self,
        jubjub: Witness,
        point: WitnessPoint,
    ) -> WitnessPoint {
        let scalar_bits = self.component_decomposition::<252>(jubjub);

        let mut result = Self::IDENTITY;

        for bit in scalar_bits.iter().rev() {
            result = self.mul_point_round(result, *bit, point);
        }

        result
    }

    /// 执行一次标量乘“倍点 + 条件加点”轮次。
    /// 先把当前累加点做一次自加，再根据当前 bit 选择是否叠加输入点。
    /// 该辅助函数用于压缩 `component_mul_point` 的循环体复杂度。
    fn mul_point_round(
        &mut self,
        accumulated_point: WitnessPoint,
        selector_bit: Witness,
        base_point: WitnessPoint,
    ) -> WitnessPoint {
        let doubled_point =
            self.component_add_point(accumulated_point, accumulated_point);
        let point_to_add =
            self.component_select_identity(selector_bit, base_point);
        self.component_add_point(doubled_point, point_to_add)
    }

    pub fn component_select(
        &mut self,
        bit: Witness,
        when_bit_is_one: Witness,
        when_bit_is_zero: Witness,
    ) -> Witness {
        let selected_when_one = self.multiply_witnesses(bit, when_bit_is_one);
        let one_minus_bit = self.compute_one_minus_bit(bit);
        let selected_when_zero =
            self.multiply_witnesses(one_minus_bit, when_bit_is_zero);

        self.add_witness_pair(selected_when_zero, selected_when_one)
    }

    /// 计算两个 witness 的乘积并返回新 witness。
    /// 该辅助函数统一封装乘法门构造，减少选择组件中的模板重复。
    /// 返回值表示 `left_witness * right_witness` 的约束化结果。
    fn multiply_witnesses(
        &mut self,
        left_witness: Witness,
        right_witness: Witness,
    ) -> Witness {
        let constraint =
            Constraint::new().mult(1).a(left_witness).b(right_witness);
        self.gate_mul(constraint)
    }

    /// 计算 `1 - bit` 并返回结果 witness。
    /// 该表达式在二值选择逻辑中用于构建“bit 为 0 时”的通道。
    /// 要求 `bit` 已被布尔约束限制为 0/1。
    fn compute_one_minus_bit(&mut self, bit: Witness) -> Witness {
        let constraint =
            Constraint::new().left(-BlsScalar::one()).constant(1).a(bit);
        self.gate_add(constraint)
    }

    /// 计算两个 witness 的和并返回结果 witness。
    /// 该辅助函数用于选择组件最后的两分支聚合步骤。
    /// 返回值表示 `left_witness + right_witness` 的约束化结果。
    fn add_witness_pair(
        &mut self,
        left_witness: Witness,
        right_witness: Witness,
    ) -> Witness {
        let constraint = Constraint::new()
            .left(1)
            .right(1)
            .a(left_witness)
            .b(right_witness);
        self.gate_add(constraint)
    }

    pub fn component_select_one(
        &mut self,
        bit: Witness,
        value: Witness,
    ) -> Witness {
        let output_witness = self.append_select_one_output(bit, value);
        self.append_select_one_constraint(bit, value, output_witness);

        output_witness
    }

    /// 计算 `1 - bit + bit * value` 的输出 witness。
    /// 该表达式在 bit=0 时返回 1，在 bit=1 时返回 value。
    /// 返回值仅写入 witness，约束由配套函数追加。
    fn append_select_one_output(
        &mut self,
        bit: Witness,
        value: Witness,
    ) -> Witness {
        let bit_value = self[bit];
        let selected_value = self[value];
        let output_value =
            BlsScalar::one() - bit_value + (bit_value * selected_value);
        self.append_witness(output_value)
    }

    /// 为 `component_select_one` 追加约束门。
    /// 约束关系与历史实现保持一致，不改变选择组件语义。
    /// 该辅助函数用于把输出计算与门拼装解耦。
    fn append_select_one_constraint(
        &mut self,
        bit: Witness,
        value: Witness,
        output_witness: Witness,
    ) {
        let constraint = Constraint::new()
            .mult(1)
            .left(-BlsScalar::one())
            .output(-BlsScalar::one())
            .constant(1)
            .a(bit)
            .b(value)
            .c(output_witness);
        self.append_gate(constraint);
    }

    pub fn component_select_point(
        &mut self,
        bit: Witness,
        left_point: WitnessPoint,
        right_point: WitnessPoint,
    ) -> WitnessPoint {
        let selected_coordinates =
            self.select_point_coordinates(bit, left_point, right_point);
        Self::witness_point_from_coordinates(selected_coordinates)
    }

    /// 将一对坐标 witness 组装为 `WitnessPoint`。
    /// 该封装用于统一点选择路径的返回结构拼装。
    /// 不引入新约束，仅做数据结构转换。
    fn witness_point_from_coordinates(
        (x_coordinate, y_coordinate): (Witness, Witness),
    ) -> WitnessPoint {
        WitnessPoint::new(x_coordinate, y_coordinate)
    }

    /// 在两个点之间按位选择坐标对。
    /// `bit=1` 选择左点，`bit=0` 选择右点。
    /// 该辅助函数统一 x/y 两个坐标通道的选择流程。
    fn select_point_coordinates(
        &mut self,
        bit: Witness,
        left_point: WitnessPoint,
        right_point: WitnessPoint,
    ) -> (Witness, Witness) {
        let selected_x = self.select_point_coordinate(
            bit,
            *left_point.x(),
            *right_point.x(),
        );
        let selected_y = self.select_point_coordinate(
            bit,
            *left_point.y(),
            *right_point.y(),
        );
        (selected_x, selected_y)
    }

    /// 在两个候选坐标之间按位选择。
    /// `bit=1` 选择左值，`bit=0` 选择右值。
    /// 该辅助函数用于点坐标选择，避免 x/y 维度重复代码。
    fn select_point_coordinate(
        &mut self,
        selector_bit: Witness,
        left_coordinate: Witness,
        right_coordinate: Witness,
    ) -> Witness {
        self.component_select(selector_bit, left_coordinate, right_coordinate)
    }

    pub fn component_select_zero(
        &mut self,
        bit: Witness,
        value: Witness,
    ) -> Witness {
        self.multiply_witnesses(bit, value)
    }

    /// 根据被约束比特数计算 range 组件所需门数。
    /// 每个 range gate 可承载 8 bit（4 个 quad）。
    /// 非整除时向上补一门，保证覆盖全部目标位。
    fn compute_range_gate_count(constrained_bit_count: usize) -> usize {
        let mut range_gate_count = constrained_bit_count >> 3;
        if constrained_bit_count % 8 != 0 {
            range_gate_count += 1;
        }
        range_gate_count
    }

    /// 计算 quad 偏移对应的门内 wire 位置。
    /// 映射顺序与原实现一致：3->A,2->B,1->C,0->D。
    /// 该函数用于统一 range 约束写线规则。
    fn range_wire_slot_for_quad_offset(quad_offset: usize) -> WiredWitness {
        match quad_offset % 4 {
            0 => WiredWitness::D,
            1 => WiredWitness::C,
            2 => WiredWitness::B,
            3 => WiredWitness::A,
            _ => unreachable!(),
        }
    }

    /// 初始化一组 range 约束模板门。
    /// 模板门数量由调用方给定，默认均带 `q_range` 选择子。
    /// 后续会把累加器 witness 按 quad 位置填充到对应线位。
    fn init_range_constraints(used_gate_count: usize) -> Vec<Constraint> {
        let base = Constraint::new();
        let base = Constraint::range(&base);
        vec![base; used_gate_count]
    }

    /// 完成 range 约束尾门规范化。
    /// 最后一门重置为普通门，并把最终累加器放到 D 线用于一致性检查。
    /// 该步骤保证与历史布局兼容，不改变约束语义。
    fn finalize_range_constraints(
        constraints: &mut [Constraint],
        accumulators: &[Witness],
    ) {
        if let Some(last_constraint) = constraints.last_mut() {
            *last_constraint = Constraint::new();
        }

        if let Some(last_accumulator) = accumulators.last() {
            if let Some(last_constraint) = constraints.last_mut() {
                last_constraint.set_witness(WiredWitness::D, *last_accumulator);
            }
        }
    }

    /// 从 witness 提取位序列并转换为低位在前顺序。
    /// 该顺序与 range 组件的 quad 扫描方式保持一致。
    /// 返回值可直接按双 bit（quad）索引读取。
    fn reversed_bit_values_for_range(&self, witness: Witness) -> Vec<bool> {
        let witness_value = self[witness];
        let bit_iter = BitIterator8::new(witness_value.to_bytes());
        let mut bit_values: Vec<_> = bit_iter.collect();
        bit_values.reverse();
        bit_values
    }

    /// 断言 range 累加器最终值与目标 witness 相等。
    /// 若累加器为空则不追加约束。
    /// 该封装用于统一 range 组件末尾收敛逻辑。
    fn assert_range_accumulator_matches_witness(
        &mut self,
        accumulators: &[Witness],
        witness: Witness,
    ) {
        if let Some(last_accumulator) = accumulators.last() {
            self.assert_equal(*last_accumulator, witness);
        }
    }

    pub fn component_range<const BIT_PAIRS: usize>(
        &mut self,
        witness: Witness,
    ) {
        let constrained_bit_count = cmp::min(BIT_PAIRS * 2, 256);

        if constrained_bit_count == 0 {
            let constraint = Constraint::new().left(1).a(witness);
            self.append_gate(constraint);
            return;
        }

        let bit_values = self.reversed_bit_values_for_range(witness);

        let range_gate_count =
            Self::compute_range_gate_count(constrained_bit_count);
        let quad_count = range_gate_count * 4;

        let leading_padding_quads =
            1 + (((quad_count << 1) - constrained_bit_count) >> 1);

        let used_gate_count = range_gate_count + 1;
        let mut constraints = Self::init_range_constraints(used_gate_count);

        let mut accumulators: Vec<Witness> = Vec::new();
        let mut accumulator = BlsScalar::zero();
        let four = BlsScalar::from(4);

        for quad_offset in leading_padding_quads..=quad_count {
            let bit_index = (quad_count - quad_offset) << 1;
            let low_bit = bit_values[bit_index] as u64;
            let high_bit = bit_values[bit_index + 1] as u64;
            let quad_value = low_bit + (2 * high_bit);

            accumulator = four * accumulator;
            accumulator += BlsScalar::from(quad_value);

            let accumulator_var = self.append_witness(accumulator);

            accumulators.push(accumulator_var);

            let gate_index = quad_offset / 4;
            let wire_index = Self::range_wire_slot_for_quad_offset(quad_offset);

            constraints[gate_index].set_witness(wire_index, accumulator_var);
        }

        Self::finalize_range_constraints(&mut constraints, &accumulators);

        constraints
            .into_iter()
            .for_each(|constraint| self.append_custom_gate(constraint));

        self.assert_range_accumulator_matches_witness(&accumulators, witness);
    }

    pub fn gate_add(&mut self, constraint: Constraint) -> Witness {
        self.apply_arithmetic_output_gate(constraint)
    }

    pub fn gate_mul(&mut self, constraint: Constraint) -> Witness {
        self.apply_arithmetic_output_gate(constraint)
    }

    /// 应用一条带输出求值的算术门并返回输出 witness。
    /// 该流程统一了 `gate_add` 与 `gate_mul` 的公共模板逻辑。
    /// 输出选择子固定为 `-1`，与历史约束布局保持一致。
    fn apply_arithmetic_output_gate(
        &mut self,
        constraint: Constraint,
    ) -> Witness {
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
