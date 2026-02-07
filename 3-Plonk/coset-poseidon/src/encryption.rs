


//



//!

//!


//!






//!







//!






//!





//!

//! ```

#[cfg(feature = "zk")]
pub(crate) mod gadget;

use alloc::vec::Vec;

use coset_bls12_381::BlsScalar;
use coset_jubjub::JubJubAffine;

use crate::hades::ScalarPermutation;
use crate::{Domain, Error};



///

///

pub fn encrypt(
    plaintext_message: impl AsRef<[BlsScalar]>,
    shared_secret: &JubJubAffine,
    nonce_scalar: &BlsScalar,
) -> Result<Vec<BlsScalar>, Error> {
    let shared_secret_coordinates =
        [shared_secret.get_u(), shared_secret.get_v()];
    Ok(dusk_safe::encrypt(
        ScalarPermutation::new(),
        Domain::Encryption,
        plaintext_message,
        &shared_secret_coordinates,
        nonce_scalar,
    )?)
}




///

///

pub fn decrypt(
    ciphertext: impl AsRef<[BlsScalar]>,
    shared_secret: &JubJubAffine,
    nonce_scalar: &BlsScalar,
) -> Result<Vec<BlsScalar>, Error> {
    let shared_secret_coordinates =
        [shared_secret.get_u(), shared_secret.get_v()];
    Ok(dusk_safe::decrypt(
        ScalarPermutation::new(),
        Domain::Encryption,
        ciphertext,
        &shared_secret_coordinates,
        nonce_scalar,
    )?)
}
