// 模块说明：本文件实现 PLONK 组件（src/proof_system/preprocess.rs）。

//

use crate::fft::Polynomial;

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
