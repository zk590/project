


//


use alloc::vec::Vec;

use plonk::prelude::{Composer, Witness, WitnessPoint};

use crate::hades::GadgetPermutation;
use crate::{Domain, Error};



///

///

pub fn encrypt_gadget(
    composer: &mut Composer,
    plaintext_message: impl AsRef<[Witness]>,
    shared_secret: &WitnessPoint,
    nonce_witness: &Witness,
) -> Result<Vec<Witness>, Error> {
    let shared_secret_coordinates = [*shared_secret.x(), *shared_secret.y()];
    Ok(dusk_safe::encrypt(
        GadgetPermutation::new(composer),
        Domain::Encryption,
        plaintext_message,
        &shared_secret_coordinates,
        nonce_witness,
    )?)
}




///

///

pub fn decrypt_gadget(
    composer: &mut Composer,
    ciphertext: impl AsRef<[Witness]>,
    shared_secret: &WitnessPoint,
    nonce_witness: &Witness,
) -> Result<Vec<Witness>, Error> {
    let shared_secret_coordinates = [*shared_secret.x(), *shared_secret.y()];
    Ok(dusk_safe::decrypt(
        GadgetPermutation::new(composer),
        Domain::Encryption,
        ciphertext,
        &shared_secret_coordinates,
        nonce_witness,
    )?)
}
