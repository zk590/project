// 模块说明：本文件实现 PLONK 组件（src/commitment_scheme.rs）。

//

mod kzg10;

pub(crate) use kzg10::Commitment;

#[cfg(feature = "alloc")]
pub(crate) use kzg10::AggregateProof;

#[cfg(feature = "alloc")]
pub(crate) use kzg10::{CommitKey, OpeningKey};

#[cfg(feature = "alloc")]
pub use kzg10::PublicParameters;

#[cfg(all(feature = "alloc", feature = "rkyv-impl"))]
pub use kzg10::{
    ArchivedCommitKey, ArchivedOpeningKey, ArchivedPublicParameters,
    CommitKeyResolver, OpeningKeyResolver, PublicParametersResolver,
};
