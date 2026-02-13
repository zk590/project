// Poseidon 加解密在 PLONK 约束系统中的 gadget 封装。

use alloc::vec::Vec;

use plonk::prelude::{Composer, Witness, WitnessPoint};

use crate::hades::GadgetPermutation;
use crate::{Domain, Error};

/// 提取 witness 形式共享密钥点的 `(x, y)` 坐标。
#[inline]
fn witness_point_coordinates(shared_secret: &WitnessPoint) -> [Witness; 2] {
    [*shared_secret.x(), *shared_secret.y()]
}

/// 电路内的 Poseidon 加密 gadget，返回密文 witness 向量。
pub fn encrypt_gadget(
    composer: &mut Composer,
    plaintext_message: impl AsRef<[Witness]>,
    shared_secret: &WitnessPoint,
    nonce_witness: &Witness,
) -> Result<Vec<Witness>, Error> {
    let shared_secret_coordinates = witness_point_coordinates(shared_secret);
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
    let shared_secret_coordinates = witness_point_coordinates(shared_secret);
    Ok(coset_safe::decrypt(
        GadgetPermutation::new(composer),
        Domain::Encryption,
        ciphertext,
        &shared_secret_coordinates,
        nonce_witness,
    )?)
}
