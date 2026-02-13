//! 基于 JubJub 的 ElGamal 密文结构与加解密/同态运算接口。

use crate::{JubJubAffine, JubJubExtended, JubJubScalar};

use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use coset_bytes::{DeserializableSlice, Error as BytesError, Serializable};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Default)]
#[cfg_attr(feature = "rkyv-impl", derive(Archive, Serialize, Deserialize))]
#[cfg_attr(feature = "rkyv-impl", archive_attr(derive(CheckBytes)))]
pub struct ElgamalCipher {
    gamma: JubJubExtended,
    delta: JubJubExtended,
}

impl ElgamalCipher {
    /// 按固定布局切分密文字节：前 32 字节为 `gamma`，后 32 字节为 `delta`。
    #[inline]
    fn split_cipher_bytes(bytes: &[u8; Self::SIZE]) -> (&[u8], &[u8]) {
        (&bytes[..32], &bytes[32..])
    }
}

impl Serializable<64> for ElgamalCipher {
    type Error = BytesError;

    /// 序列化密文 `(gamma, delta)` 为 64 字节。
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let gamma: JubJubAffine = self.gamma.into();
        let gamma = gamma.to_bytes();

        let delta: JubJubAffine = self.delta.into();
        let delta = delta.to_bytes();

        let mut bytes = [0u8; Self::SIZE];

        bytes[..32].copy_from_slice(&gamma);
        bytes[32..].copy_from_slice(&delta);

        bytes
    }

    /// 从 64 字节反序列化密文。
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let (gamma_bytes, delta_bytes) = Self::split_cipher_bytes(bytes);
        let gamma = JubJubAffine::from_slice(gamma_bytes)?;
        let delta = JubJubAffine::from_slice(delta_bytes)?;
        let cipher = ElgamalCipher::new(gamma.into(), delta.into());
        Ok(cipher)
    }
}

impl ElgamalCipher {

    /// 构造 ElGamal 密文对象。
    pub fn new(gamma: JubJubExtended, delta: JubJubExtended) -> Self {
        Self { gamma, delta }
    }

    /// 返回密文第一部分 `gamma = rG`。
    pub fn gamma(&self) -> &JubJubExtended {
        &self.gamma
    }

    /// 返回密文第二部分 `delta = M + rPK`。
    pub fn delta(&self) -> &JubJubExtended {
        &self.delta
    }

    /// ElGamal 加密：输出 `(rG, M + rPK)`。
    pub fn encrypt(
        secret: &JubJubScalar,
        public: &JubJubExtended,
        generator: &JubJubExtended,
        message: &JubJubExtended,
    ) -> Self {
        let gamma = generator * secret;
        let delta = message + public * secret;

        Self::new(gamma, delta)
    }

    /// ElGamal 解密：`delta - sk * gamma`。
    pub fn decrypt(&self, secret: &JubJubScalar) -> JubJubExtended {
        self.delta - self.gamma * secret
    }

    /// 以给定闭包对 `(gamma, delta)` 做分量级二元运算。
    /// 用于统一实现密文同态加减，减少重复的字段组合样板代码。
    #[inline]
    fn combine_with<F>(&self, other: &ElgamalCipher, mut op: F) -> ElgamalCipher
    where
        F: FnMut(JubJubExtended, JubJubExtended) -> JubJubExtended,
    {
        ElgamalCipher::new(op(self.gamma, other.gamma), op(self.delta, other.delta))
    }
}

impl Add for &ElgamalCipher {
    type Output = ElgamalCipher;

    fn add(self, other: &ElgamalCipher) -> ElgamalCipher {
        self.combine_with(other, |left, right| left + right)
    }
}

impl Add for ElgamalCipher {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        &self + &other
    }
}

impl AddAssign for ElgamalCipher {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl Sub for &ElgamalCipher {
    type Output = ElgamalCipher;

    fn sub(self, other: &ElgamalCipher) -> ElgamalCipher {
        self.combine_with(other, |left, right| left - right)
    }
}

impl Sub for ElgamalCipher {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        &self - &other
    }
}

impl SubAssign for ElgamalCipher {
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl Mul<&JubJubScalar> for &ElgamalCipher {
    type Output = ElgamalCipher;

    fn mul(self, rhs: &JubJubScalar) -> ElgamalCipher {
        ElgamalCipher::new(self.gamma * rhs, self.delta * rhs)
    }
}

impl Mul<JubJubScalar> for &ElgamalCipher {
    type Output = ElgamalCipher;

    fn mul(self, rhs: JubJubScalar) -> ElgamalCipher {
        self * &rhs
    }
}

impl MulAssign<JubJubScalar> for ElgamalCipher {
    fn mul_assign(&mut self, rhs: JubJubScalar) {
        *self = &*self * &rhs;
    }
}

impl<'b> MulAssign<&'b JubJubScalar> for ElgamalCipher {
    fn mul_assign(&mut self, rhs: &'b JubJubScalar) {
        *self = &*self * rhs;
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {

    use super::ElgamalCipher;
    use crate::{JubJubExtended, JubJubScalar, GENERATOR_EXTENDED};
    use coset_bytes::Serializable;
    use rand_core::OsRng;

    /// 采样固定数量的随机标量消息。
    fn sample_scalars<const N: usize>() -> [JubJubScalar; N] {
        let mut scalars = [JubJubScalar::zero(); N];
        scalars
            .iter_mut()
            .for_each(|scalar| *scalar = JubJubScalar::random(&mut OsRng));
        scalars
    }

    /// 将标量消息映射到 JubJub 点消息。
    fn map_scalars_to_points<const N: usize>(
        scalars: &[JubJubScalar; N],
    ) -> [JubJubExtended; N] {
        let mut points = [JubJubExtended::default(); N];
        points
            .iter_mut()
            .zip(scalars.iter())
            .for_each(|(point, scalar)| *point = GENERATOR_EXTENDED * scalar);
        points
    }

    /// 使用同一公钥批量加密点消息。
    fn encrypt_points<const N: usize>(
        secret: &JubJubScalar,
        public_key: &JubJubExtended,
        points: &[JubJubExtended; N],
    ) -> [ElgamalCipher; N] {
        let mut ciphers = [ElgamalCipher::default(); N];
        ciphers.iter_mut().zip(points.iter()).for_each(|(cipher, point)| {
            *cipher =
                ElgamalCipher::encrypt(secret, public_key, &GENERATOR_EXTENDED, point)
        });
        ciphers
    }

    fn sample_keypairs() -> (JubJubScalar, JubJubExtended, JubJubScalar, JubJubExtended) {
        let sender_secret = JubJubScalar::random(&mut OsRng);
        let sender_public = GENERATOR_EXTENDED * sender_secret;

        let receiver_secret = JubJubScalar::random(&mut OsRng);
        let receiver_public = GENERATOR_EXTENDED * receiver_secret;

        (
            sender_secret,
            sender_public,
            receiver_secret,
            receiver_public,
        )
    }

    #[test]
    fn encrypt() {
        let (sender_secret, _, receiver_secret, receiver_public) =
            sample_keypairs();

        let message_scalar = JubJubScalar::random(&mut OsRng);
        let message_point = GENERATOR_EXTENDED * message_scalar;

        let cipher = ElgamalCipher::encrypt(
            &sender_secret,
            &receiver_public,
            &GENERATOR_EXTENDED,
            &message_point,
        );
        let decrypted_point = cipher.decrypt(&receiver_secret);

        assert_eq!(message_point, decrypted_point);
    }

    #[test]
    fn wrong_key() {
        let (sender_secret, _, receiver_secret, receiver_public) =
            sample_keypairs();

        let message_scalar = JubJubScalar::random(&mut OsRng);
        let message_point = GENERATOR_EXTENDED * message_scalar;

        let cipher = ElgamalCipher::encrypt(
            &sender_secret,
            &receiver_public,
            &GENERATOR_EXTENDED,
            &message_point,
        );

        let wrong_secret = receiver_secret - JubJubScalar::one();
        let decrypted_point = cipher.decrypt(&wrong_secret);

        assert_ne!(message_point, decrypted_point);
    }

    #[test]
    fn homomorphic_add() {
        let (sender_secret, _, receiver_secret, receiver_public) =
            sample_keypairs();

        let message_scalars = sample_scalars::<4>();
        let message_points = map_scalars_to_points(&message_scalars);

        let expected_scalar = message_scalars[0]
            + message_scalars[1]
            + message_scalars[2]
            + message_scalars[3];
        let expected_point = GENERATOR_EXTENDED * expected_scalar;

        let cipher_texts =
            encrypt_points(&sender_secret, &receiver_public, &message_points);

        let mut homomorphic_cipher = cipher_texts[0] + cipher_texts[1];
        homomorphic_cipher += cipher_texts[2];
        homomorphic_cipher = &homomorphic_cipher + &cipher_texts[3];

        let homomorphic_decrypt = homomorphic_cipher.decrypt(&receiver_secret);

        assert_eq!(expected_point, homomorphic_decrypt);
    }

    #[test]
    fn homomorphic_sub() {
        let (sender_secret, _, receiver_secret, receiver_public) =
            sample_keypairs();

        let message_scalars = sample_scalars::<4>();
        let message_points = map_scalars_to_points(&message_scalars);

        let expected_scalar = message_scalars[0]
            - message_scalars[1]
            - message_scalars[2]
            - message_scalars[3];
        let expected_point = GENERATOR_EXTENDED * expected_scalar;

        let cipher_texts =
            encrypt_points(&sender_secret, &receiver_public, &message_points);

        let mut homomorphic_cipher = cipher_texts[0] - cipher_texts[1];
        homomorphic_cipher -= cipher_texts[2];
        homomorphic_cipher = &homomorphic_cipher - &cipher_texts[3];

        let homomorphic_decrypt = homomorphic_cipher.decrypt(&receiver_secret);

        assert_eq!(expected_point, homomorphic_decrypt);
    }

    #[test]
    fn homomorphic_mul() {
        let (sender_secret, _, receiver_secret, receiver_public) =
            sample_keypairs();

        let message_scalars = sample_scalars::<4>();
        let message_points = map_scalars_to_points(&message_scalars);

        let expected_scalar = message_scalars[0]
            * message_scalars[1]
            * message_scalars[2]
            * message_scalars[3];
        let expected_point = GENERATOR_EXTENDED * expected_scalar;

        let mut cipher_text = ElgamalCipher::encrypt(
            &sender_secret,
            &receiver_public,
            &GENERATOR_EXTENDED,
            &message_points[0],
        );

        cipher_text = &cipher_text * &message_scalars[1];
        cipher_text = &cipher_text * message_scalars[2];
        cipher_text *= message_scalars[3];

        let decrypted_point = cipher_text.decrypt(&receiver_secret);

        assert_eq!(expected_point, decrypted_point);
    }

    #[test]
    fn to_bytes() {
        let (sender_secret, _, receiver_secret, receiver_public) =
            sample_keypairs();

        let message_scalar = JubJubScalar::random(&mut OsRng);
        let message_point = GENERATOR_EXTENDED * message_scalar;

        let cipher = ElgamalCipher::encrypt(
            &sender_secret,
            &receiver_public,
            &GENERATOR_EXTENDED,
            &message_point,
        );
        let cipher_bytes = cipher.to_bytes();
        let recovered_cipher = ElgamalCipher::from_bytes(&cipher_bytes).unwrap();

        let decrypted_point = recovered_cipher.decrypt(&receiver_secret);

        assert_eq!(message_point, decrypted_point);
    }
}
