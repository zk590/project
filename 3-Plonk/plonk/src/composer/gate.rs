// 模块说明：本文件实现 PLONK 组件（src/composer/gate.rs）。

//

use coset_bls12_381::BlsScalar;

use crate::prelude::Witness;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    pub(crate) q_m: BlsScalar,

    pub(crate) q_l: BlsScalar,

    pub(crate) q_r: BlsScalar,

    pub(crate) q_o: BlsScalar,

    pub(crate) q_f: BlsScalar,

    pub(crate) q_c: BlsScalar,

    pub(crate) q_arith: BlsScalar,

    pub(crate) q_range: BlsScalar,

    pub(crate) q_logic: BlsScalar,

    pub(crate) q_fixed_group_add: BlsScalar,

    pub(crate) q_variable_group_add: BlsScalar,

    pub(crate) a: Witness,

    pub(crate) b: Witness,

    pub(crate) c: Witness,

    pub(crate) d: Witness,
}
