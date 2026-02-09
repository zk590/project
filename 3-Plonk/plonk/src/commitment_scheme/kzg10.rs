// 模块说明：本文件实现 PLONK 组件（src/commitment_scheme/kzg10.rs）。

//

cfg_if::cfg_if!(
if #[cfg(feature = "alloc")]
{
    pub mod key;
    pub mod srs;

    pub(crate) use proof::alloc::AggregateProof;

    pub use key::{CommitKey, OpeningKey};
    pub use srs::PublicParameters;

    cfg_if::cfg_if!(
        if #[cfg(feature = "rkyv-impl")] {
            pub use key::{ArchivedCommitKey, CommitKeyResolver, ArchivedOpeningKey, OpeningKeyResolver};
            pub use srs::{ArchivedPublicParameters, PublicParametersResolver};
        }
    );
});

pub(crate) mod commitment;
pub(crate) mod proof;

pub(crate) use commitment::Commitment;
