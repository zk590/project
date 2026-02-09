// 模块说明：本文件实现 PLONK
// 组件（src/proof_system/widget/ecc/curve_addition.rs）。

//

#[cfg(feature = "alloc")]
mod proverkey;

mod verifierkey;

#[cfg(feature = "alloc")]
pub(crate) use proverkey::ProverKey;

pub(crate) use verifierkey::VerifierKey;
