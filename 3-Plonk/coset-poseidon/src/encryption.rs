#[cfg(feature = "zk")]
pub(crate) mod gadget;

use alloc::vec::Vec;

use coset_bls12_381::BlsScalar;
use coset_jubjub::JubJubAffine;

use crate::hades::ScalarPermutation;
use crate::{Domain, Error};

/// 提取共享密钥仿射点的 `(u, v)` 坐标，作为加解密关联输入。
#[inline]
fn shared_secret_coordinates(secret_point: &JubJubAffine) -> [BlsScalar; 2] {
    [secret_point.get_u(), secret_point.get_v()]
}

/// 使用 Poseidon sponge 进行加密，返回密文字段向量。
/// 该函数把共享密钥点坐标作为关联输入，与随机数共同驱动加密流程。
/// 底层调用 `coset_safe::encrypt`，并固定使用 `Domain::Encryption` 域分离。
/// 返回值是字段元素序列，便于直接进入后续零知识电路或序列化管线。
pub fn encrypt(
    plaintext_message: impl AsRef<[BlsScalar]>,
    shared_secret: &JubJubAffine,
    nonce_scalar: &BlsScalar,
) -> Result<Vec<BlsScalar>, Error> {
    let shared_secret_coordinates = shared_secret_coordinates(shared_secret);
    Ok(coset_safe::encrypt(
        ScalarPermutation::new(),
        Domain::Encryption,
        plaintext_message,
        &shared_secret_coordinates,
        nonce_scalar,
    )?)
}

/// 使用相同共享密钥和随机数对密文执行解密。
/// 解密侧必须复用与加密完全一致的域标签、密钥坐标和随机数上下文。
/// 任一参数不匹配都会导致解密失败或得到无意义输出，从而触发错误返回。
/// 该接口保持与加密接口对称，便于上层协议按同一数据结构编排调用。
pub fn decrypt(
    ciphertext: impl AsRef<[BlsScalar]>,
    shared_secret: &JubJubAffine,
    nonce_scalar: &BlsScalar,
) -> Result<Vec<BlsScalar>, Error> {
    let shared_secret_coordinates = shared_secret_coordinates(shared_secret);
    Ok(coset_safe::decrypt(
        ScalarPermutation::new(),
        Domain::Encryption,
        ciphertext,
        &shared_secret_coordinates,
        nonce_scalar,
    )?)
}
