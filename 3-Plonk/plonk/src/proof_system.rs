// 模块说明：本文件实现 PLONK 组件（src/proof_system.rs）。

//

pub(crate) mod linearization_poly;
pub(crate) mod proof;
pub(crate) mod widget;

cfg_if::cfg_if!(
    if #[cfg(feature = "alloc")] {
        pub(crate) mod quotient_poly;
        pub(crate) mod preprocess;

        pub(crate) use widget::alloc::ProverKey;
        pub(crate) use widget::VerifierKey;

        cfg_if::cfg_if!(
            if #[cfg(feature = "rkyv-impl")] {
                pub use widget::alloc::{ArchivedProverKey, ProverKeyResolver};
            }
        );
    }
);

pub use proof::Proof;

cfg_if::cfg_if!(
    if #[cfg(feature = "rkyv-impl")] {
        pub use proof::{ArchivedProof, ProofResolver};
        pub use widget::{ArchivedVerifierKey, VerifierKeyResolver};
    }
);
