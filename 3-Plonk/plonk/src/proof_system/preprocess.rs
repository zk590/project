// 模块说明：本文件实现 PLONK 组件（src/proof_system/preprocess.rs）。

use crate::fft::Polynomial;

/// 预处理阶段的 selector 多项式集合（算术/逻辑/范围/群运算）。
pub(crate) type SelectorPolynomials = [Polynomial; 11];
/// 预处理阶段的 sigma 置换多项式集合。
pub(crate) type SigmaPolynomials = [Polynomial; 4];

pub(crate) struct Polynomials {
    pub(crate) q_m: Polynomial,
    pub(crate) q_l: Polynomial,
    pub(crate) q_r: Polynomial,
    pub(crate) q_o: Polynomial,
    pub(crate) q_f: Polynomial,
    pub(crate) q_c: Polynomial,

    pub(crate) q_arith: Polynomial,
    pub(crate) q_range: Polynomial,
    pub(crate) q_logic: Polynomial,
    pub(crate) q_fixed_group_add: Polynomial,
    pub(crate) q_variable_group_add: Polynomial,

    pub(crate) s_sigma_1: Polynomial,
    pub(crate) s_sigma_2: Polynomial,
    pub(crate) s_sigma_3: Polynomial,
    pub(crate) s_sigma_4: Polynomial,
}

#[allow(dead_code)]
impl Polynomials {
    /// 由 selector 与 sigma 两组多项式构造预处理对象。
    /// 该构造器集中约束字段顺序，避免调用点重复展开。
    pub(crate) fn from_parts(
        selectors: SelectorPolynomials,
        sigma: SigmaPolynomials,
    ) -> Self {
        let [q_m, q_l, q_r, q_o, q_f, q_c, q_arith, q_range, q_logic, q_fixed_group_add, q_variable_group_add] =
            selectors;
        let [s_sigma_1, s_sigma_2, s_sigma_3, s_sigma_4] = sigma;

        Self {
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
            s_sigma_1,
            s_sigma_2,
            s_sigma_3,
            s_sigma_4,
        }
    }
}
