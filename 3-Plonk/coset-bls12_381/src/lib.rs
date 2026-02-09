//!

//!

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![allow(missing_docs)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::suspicious_arithmetic_impl)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
#[cfg(feature = "groups")]
mod tests;

#[macro_use]
mod util;

mod coset;
#[cfg(feature = "groups")]
use coset::choice;
#[cfg(all(feature = "groups", feature = "alloc"))]
pub use coset::multiscalar_mul;

mod scalar;

pub use scalar::Scalar as BlsScalar;
#[cfg(feature = "rkyv-impl")]
pub use scalar::{
    ArchivedScalar as ArchivedBlsScalar, ScalarResolver as BlsScalarResolver,
};
pub use scalar::{GENERATOR, ROOT_OF_UNITY, TWO_ADACITY};

#[cfg(feature = "groups")]
mod fp;
#[cfg(feature = "groups")]
mod fp2;
#[cfg(feature = "groups")]
mod g1;
#[cfg(feature = "groups")]
mod g2;

#[cfg(all(feature = "groups", feature = "rkyv-impl"))]
pub use g1::{ArchivedG1Affine, G1AffineResolver};
#[cfg(feature = "groups")]
pub use g1::{G1Affine, G1Projective};
#[cfg(all(feature = "groups", feature = "rkyv-impl"))]
pub use g2::{ArchivedG2Affine, G2AffineResolver};
#[cfg(feature = "groups")]
pub use g2::{G2Affine, G2Projective};

#[cfg(feature = "groups")]
mod fp12;
#[cfg(feature = "groups")]
mod fp6;

#[cfg(feature = "groups")]
const BLS_X: u64 = 0xd201_0000_0001_0000;
#[cfg(feature = "groups")]
const BLS_X_IS_NEGATIVE: bool = true;

#[cfg(feature = "pairings")]
mod pairings;

#[cfg(feature = "pairings")]
pub use pairings::{pairing, Bls12, Gt, MillerLoopResult};

#[cfg(all(feature = "pairings", feature = "alloc"))]
pub use pairings::{multi_miller_loop, G2Prepared};

#[cfg(all(feature = "pairings", feature = "rkyv-impl"))]
pub use pairings::{
    ArchivedG2Prepared, ArchivedGt, ArchivedMillerLoopResult,
    G2PreparedResolver, GtResolver, MillerLoopResultResolver,
};

#[cfg(feature = "experimental")]
pub(crate) use digest::generic_array;

#[cfg(feature = "experimental")]
pub mod hash_to_curve;
