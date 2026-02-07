


//


#[cfg(feature = "alloc")]
pub(crate) mod proverkey;
#[cfg(feature = "alloc")]
pub(crate) use proverkey::ProverKey;

mod verifierkey;
pub(crate) use verifierkey::VerifierKey;
