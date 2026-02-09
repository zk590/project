//

use alloc::vec::Vec;

use plonk::prelude::{Composer, Witness, WitnessPoint};

use crate::hades::GadgetPermutation;
use crate::{Domain, Error};

/// 电路内的 Poseidon 加密 gadget，返回密文 witness 向量。
pub fn encrypt_gadget(
    composer: &mut Composer,
    plaintext_message: impl AsRef<[Witness]>,
    shared_secret: &WitnessPoint,
    nonce_witness: &Witness,
) -> Result<Vec<Witness>, Error> {
    let shared_secret_coordinates = [*shared_secret.x(), *shared_secret.y()];
    Ok(coset_safe::encrypt(
        GadgetPermutation::new(composer),
        Domain::Encryption,
        plaintext_message,
        &shared_secret_coordinates,
        nonce_witness,
    )?)
}

/// 电路内的 Poseidon 解密 gadget。
pub fn decrypt_gadget(
    composer: &mut Composer,
    ciphertext: impl AsRef<[Witness]>,
    shared_secret: &WitnessPoint,
    nonce_witness: &Witness,
) -> Result<Vec<Witness>, Error> {
    let shared_secret_coordinates = [*shared_secret.x(), *shared_secret.y()];
    Ok(coset_safe::decrypt(
        GadgetPermutation::new(composer),
        Domain::Encryption,
        ciphertext,
        &shared_secret_coordinates,
        nonce_witness,
    )?)
}
