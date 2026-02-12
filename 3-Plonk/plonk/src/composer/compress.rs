use coset_bytes::Serializable;
use hashbrown::HashMap;
use msgpacker::{MsgPacker, Packable, Unpackable};

use alloc::vec::Vec;

use super::{BlsScalar, Composer, Constraint, Error, Gate, Selector, Witness};

mod hades;

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, MsgPacker,
)]
pub struct CompressedConstraint {
    pub polynomial: usize,
    pub a: usize,
    pub b: usize,
    pub c: usize,
    pub d: usize,
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, MsgPacker,
)]
pub struct CompressedPolynomial {
    pub q_m: usize,
    pub q_l: usize,
    pub q_r: usize,
    pub q_o: usize,
    pub q_f: usize,
    pub q_c: usize,
    pub q_arith: usize,
    pub q_range: usize,
    pub q_logic: usize,
    pub q_fixed_group_add: usize,
    pub q_variable_group_add: usize,
}

/// 构建“标量值 -> 索引”的压缩字典。
/// 默认预置 `0/1/-1` 三个高频常量；启用 Hades 优化时额外注入轮常量与 MDS 常量。
/// 该字典用于把约束中的标量系数离散化，降低序列化体积。
fn build_scalar_index_map(
    hades_optimization: bool,
) -> HashMap<BlsScalar, usize> {
    let mut scalars: HashMap<BlsScalar, usize> = {
        [BlsScalar::zero(), BlsScalar::one(), -BlsScalar::one()]
            .into_iter()
            .enumerate()
            .map(|(index, scalar)| (scalar, index))
            .collect()
    };
    if hades_optimization {
        for constant in hades::constants() {
            let len = scalars.len();
            scalars.entry(constant).or_insert(len);
        }
        for matrix_row in hades::mds() {
            for scalar in matrix_row {
                let len = scalars.len();
                scalars.entry(scalar).or_insert(len);
            }
        }
    }
    scalars
}

#[derive(Debug, Clone, PartialEq, Eq, MsgPacker)]
pub struct CompressedCircuit {
    hades_optimization: bool,
    public_inputs: Vec<usize>,
    witnesses: usize,
    scalars: Vec<[u8; BlsScalar::SIZE]>,
    polynomials: Vec<CompressedPolynomial>,
    constraints: Vec<CompressedConstraint>,
}

impl CompressedCircuit {
    /// 将 `Composer` 压缩编码为字节流。
    /// 该过程会抽取公开输入索引、去重标量/多项式并重写约束为索引形式。
    /// 最终输出经过 `msgpacker` 打包与 `miniz` 压缩，便于持久化与传输。
    pub fn from_composer(
        hades_optimization: bool,
        composer: Composer,
    ) -> Vec<u8> {
        let mut sorted_public_input_indices: Vec<_> =
            composer.public_inputs.keys().copied().collect();
        sorted_public_input_indices.sort();

        let witness_count = composer.witnesses.len();
        let gate_constraints = composer.constraints;

        let constraints = gate_constraints.into_iter();
        let mut scalar_index_map = build_scalar_index_map(hades_optimization);
        let preloaded_scalar_count = scalar_index_map.len();
        let mut polynomial_index_map = HashMap::new();
        let constraints = constraints
            .map(
                |Gate {
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
                     a,
                     b,
                     c,
                     d,
                 }| {
                    let next_scalar_index = scalar_index_map.len();
                    let q_m = *scalar_index_map
                        .entry(q_m)
                        .or_insert(next_scalar_index);
                    let next_scalar_index = scalar_index_map.len();
                    let q_l = *scalar_index_map
                        .entry(q_l)
                        .or_insert(next_scalar_index);
                    let next_scalar_index = scalar_index_map.len();
                    let q_r = *scalar_index_map
                        .entry(q_r)
                        .or_insert(next_scalar_index);
                    let next_scalar_index = scalar_index_map.len();
                    let q_o = *scalar_index_map
                        .entry(q_o)
                        .or_insert(next_scalar_index);
                    let next_scalar_index = scalar_index_map.len();
                    let q_f = *scalar_index_map
                        .entry(q_f)
                        .or_insert(next_scalar_index);
                    let next_scalar_index = scalar_index_map.len();
                    let q_c = *scalar_index_map
                        .entry(q_c)
                        .or_insert(next_scalar_index);
                    let next_scalar_index = scalar_index_map.len();
                    let q_arith = *scalar_index_map
                        .entry(q_arith)
                        .or_insert(next_scalar_index);
                    let next_scalar_index = scalar_index_map.len();
                    let q_range = *scalar_index_map
                        .entry(q_range)
                        .or_insert(next_scalar_index);
                    let next_scalar_index = scalar_index_map.len();
                    let q_logic = *scalar_index_map
                        .entry(q_logic)
                        .or_insert(next_scalar_index);
                    let next_scalar_index = scalar_index_map.len();
                    let q_fixed_group_add = *scalar_index_map
                        .entry(q_fixed_group_add)
                        .or_insert(next_scalar_index);
                    let next_scalar_index = scalar_index_map.len();
                    let q_variable_group_add = *scalar_index_map
                        .entry(q_variable_group_add)
                        .or_insert(next_scalar_index);
                    let polynomial = CompressedPolynomial {
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
                    };

                    let len = polynomial_index_map.len();
                    let polynomial =
                        *polynomial_index_map.entry(polynomial).or_insert(len);

                    CompressedConstraint {
                        polynomial,
                        a: a.index(),
                        b: b.index(),
                        c: c.index(),
                        d: d.index(),
                    }
                },
            )
            .collect();

        let mut serialized_scalars =
            vec![[0u8; BlsScalar::SIZE]; scalar_index_map.len()];
        scalar_index_map.into_iter().for_each(|(scalar, index)| {
            serialized_scalars[index] = scalar.to_bytes()
        });

        let serialized_scalars =
            serialized_scalars.split_off(preloaded_scalar_count);

        let mut deduplicated_polynomials =
            vec![CompressedPolynomial::default(); polynomial_index_map.len()];
        polynomial_index_map
            .into_iter()
            .for_each(|(polynomial, index)| {
                deduplicated_polynomials[index] = polynomial
            });

        let compressed = Self {
            hades_optimization,
            public_inputs: sorted_public_input_indices,
            witnesses: witness_count,
            scalars: serialized_scalars,
            polynomials: deduplicated_polynomials,
            constraints,
        };
        let mut packed_bytes = Vec::with_capacity(
            1 + compressed.scalars.len() * BlsScalar::SIZE
                + compressed.polynomials.len() * 88
                + compressed.constraints.len() * 40,
        );
        compressed.pack(&mut packed_bytes);
        miniz_oxide::deflate::compress_to_vec(&packed_bytes, 10)
    }

    /// 从压缩字节恢复 `Composer`。
    /// 该函数会先解压与反打包，再重建标量表、约束门和公开输入映射。
    /// 输入非法时返回 `InvalidCompressedCircuit` 或标量解析错误。
    pub fn from_bytes(compressed: &[u8]) -> Result<Composer, Error> {
        let decompressed_bytes =
            miniz_oxide::inflate::decompress_to_vec(compressed)
                .map_err(|_| Error::InvalidCompressedCircuit)?;
        let (
            _,
            Self {
                hades_optimization,
                public_inputs,
                witnesses,
                scalars,
                polynomials,
                constraints,
            },
        ) = Self::unpack(&decompressed_bytes)
            .map_err(|_| Error::InvalidCompressedCircuit)?;

        let scalar_index_map = build_scalar_index_map(hades_optimization);
        let mut all_scalar_values =
            vec![BlsScalar::zero(); scalar_index_map.len()];
        scalar_index_map
            .into_iter()
            .for_each(|(scalar, index)| all_scalar_values[index] = scalar);
        for serialized_scalar in scalars {
            let scalar: BlsScalar =
                match BlsScalar::from_bytes(&serialized_scalar).into() {
                    Some(scalar) => scalar,
                    None => return Err(Error::BlsScalarMalformed),
                };
            all_scalar_values.push(scalar);
        }

        let mut composer = Composer::uninitialized();

        let mut next_public_input_position = 0;
        (0..witnesses).for_each(|_| {
            composer.append_witness(BlsScalar::zero());
        });

        for (
            gate_index,
            CompressedConstraint {
                polynomial: polynomial_index,
                a: witness_a_index,
                b: witness_b_index,
                c: witness_c_index,
                d: witness_d_index,
            },
        ) in constraints.into_iter().enumerate()
        {
            let CompressedPolynomial {
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
            } = polynomials
                .get(polynomial_index)
                .copied()
                .ok_or(Error::InvalidCompressedCircuit)?;

            let read_scalar_by_index = |scalar_index: usize| {
                all_scalar_values
                    .get(scalar_index)
                    .copied()
                    .ok_or(Error::InvalidCompressedCircuit)
            };

            let q_m = read_scalar_by_index(q_m)?;
            let q_l = read_scalar_by_index(q_l)?;
            let q_r = read_scalar_by_index(q_r)?;
            let q_o = read_scalar_by_index(q_o)?;
            let q_f = read_scalar_by_index(q_f)?;
            let q_c = read_scalar_by_index(q_c)?;
            let q_arith = read_scalar_by_index(q_arith)?;
            let q_range = read_scalar_by_index(q_range)?;
            let q_logic = read_scalar_by_index(q_logic)?;
            let q_fixed_group_add = read_scalar_by_index(q_fixed_group_add)?;
            let q_variable_group_add =
                read_scalar_by_index(q_variable_group_add)?;

            let witness_a = Witness::new(witness_a_index);
            let witness_b = Witness::new(witness_b_index);
            let witness_c = Witness::new(witness_c_index);
            let witness_d = Witness::new(witness_d_index);

            let mut constraint = Constraint::default()
                .set(Selector::Multiplication, q_m)
                .set(Selector::Left, q_l)
                .set(Selector::Right, q_r)
                .set(Selector::Output, q_o)
                .set(Selector::Fourth, q_f)
                .set(Selector::Constant, q_c)
                .set(Selector::Arithmetic, q_arith)
                .set(Selector::Range, q_range)
                .set(Selector::Logic, q_logic)
                .set(Selector::GroupAddFixedBase, q_fixed_group_add)
                .set(Selector::GroupAddVariableBase, q_variable_group_add)
                .a(witness_a)
                .b(witness_b)
                .c(witness_c)
                .d(witness_d);

            if let Some(public_input_gate_index) =
                public_inputs.get(next_public_input_position)
            {
                if public_input_gate_index == &gate_index {
                    next_public_input_position += 1;
                    constraint = constraint.public(BlsScalar::zero());
                }
            }

            composer.append_custom_gate(constraint);
        }

        Ok(composer)
    }
}
