use coset_bls12_381::BlsScalar;

use crate::prelude::Witness;

/// 电路中的单条门约束记录。
/// 该结构同时包含 selector 系数与四条线绑定的 witness，
/// 是 `Composer` 内部门表的基础存储单元。
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

impl Gate {
    #[allow(dead_code)]
    /// 返回门上四条线绑定的 witness。
    /// 顺序固定为 `(a, b, c, d)`，与约束系统线位编码一致。
    /// 该辅助访问器不改变内部数据，仅做只读聚合。
    pub(crate) const fn wires(&self) -> (Witness, Witness, Witness, Witness) {
        (self.a, self.b, self.c, self.d)
    }
}
