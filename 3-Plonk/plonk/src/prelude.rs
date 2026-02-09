// 模块说明：本文件实现 PLONK 组件（src/prelude.rs）。

//

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
