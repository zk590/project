// 模块说明：本文件实现 PLONK 组件（src/fft.rs）。

//

cfg_if::cfg_if!(
if #[cfg(feature = "alloc")]
{
    pub(crate) mod evaluations;
    pub(crate) mod polynomial;

    pub(crate) use evaluations::Evaluations;
    pub(crate) use polynomial::Polynomial;
});

pub(crate) mod domain;

#[allow(unused_imports)]
pub(crate) use domain::EvaluationDomain;
