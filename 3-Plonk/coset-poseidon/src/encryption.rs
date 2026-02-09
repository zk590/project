//

//! ```

#[cfg(feature = "zk")]
pub(crate) mod gadget;

use alloc::vec::Vec;

use coset_bls12_381::BlsScalar;
use coset_jubjub::JubJubAffine;

use crate::hades::ScalarPermutation;
use crate::{Domain, Error};

/// 使用 Poseidon sponge 进行加密，返回密文字段向量。
pub fn encrypt(
    plaintext_message: impl AsRef<[BlsScalar]>,
    shared_secret: &JubJubAffine,
    nonce_scalar: &BlsScalar,
) -> Result<Vec<BlsScalar>, Error> {
    let shared_secret_coordinates =
        [shared_secret.get_u(), shared_secret.get_v()];
    Ok(coset_safe::encrypt(
        ScalarPermutation::new(),
        Domain::Encryption,
        plaintext_message,
        &shared_secret_coordinates,
        nonce_scalar,
    )?)
}

/// 使用相同共享密钥和随机数对密文执行解密。
pub fn decrypt(
    ciphertext: impl AsRef<[BlsScalar]>,
    shared_secret: &JubJubAffine,
    nonce_scalar: &BlsScalar,
) -> Result<Vec<BlsScalar>, Error> {
    let shared_secret_coordinates =
        [shared_secret.get_u(), shared_secret.get_v()];
    Ok(coset_safe::decrypt(
        ScalarPermutation::new(),
        Domain::Encryption,
        ciphertext,
        &shared_secret_coordinates,
        nonce_scalar,
    )?)
}
