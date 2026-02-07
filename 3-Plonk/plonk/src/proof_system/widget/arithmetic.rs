


//


#[cfg(feature = "alloc")]
mod proverkey;

mod verifierkey;

#[cfg(feature = "alloc")]
pub(crate) use proverkey::ProverKey;

pub(crate) use verifierkey::VerifierKey;
