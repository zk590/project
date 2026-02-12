/// `plonk` 的常用导出集合。
/// 该模块聚合编译、证明、验证和基础类型，方便调用方一次性引入核心 API。
/// 建议上层 crate 通过 `use plonk::prelude::*;` 使用统一入口。
#[cfg(feature = "alloc")]
pub use crate::{
    commitment_scheme::PublicParameters,
    compiler::{Compiler, Prover, Verifier},
    composer::{Circuit, Composer, Constraint, Witness, WitnessPoint},
};

pub use crate::error::Error;
pub use crate::proof_system::Proof;
pub use coset_bls12_381::BlsScalar;
pub use coset_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
