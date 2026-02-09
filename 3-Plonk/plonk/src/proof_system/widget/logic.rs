// 模块说明：本文件实现 PLONK 组件（src/proof_system/widget/logic.rs）。

//

#[cfg(feature = "alloc")]
pub(crate) mod proverkey;
#[cfg(feature = "alloc")]
pub(crate) use proverkey::ProverKey;

mod verifierkey;
pub(crate) use verifierkey::VerifierKey;
