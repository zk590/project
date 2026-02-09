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
        let gamma = JubJubAffine::from_slice(&bytes[..32])?;
        let delta = JubJubAffine::from_slice(&bytes[32..])?;
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
}

impl Add for &ElgamalCipher {
    type Output = ElgamalCipher;

    fn add(self, other: &ElgamalCipher) -> ElgamalCipher {
        ElgamalCipher::new(self.gamma + other.gamma, self.delta + other.delta)
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
        ElgamalCipher::new(self.gamma - other.gamma, self.delta - other.delta)
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

    fn sample_keypairs() -> (JubJubScalar, JubJubExtended, JubJubScalar, JubJubExtended) {
        let a = JubJubScalar::random(&mut OsRng);
        let a_g = GENERATOR_EXTENDED * a;

        let b = JubJubScalar::random(&mut OsRng);
        let b_g = GENERATOR_EXTENDED * b;

        (a, a_g, b, b_g)
    }

    #[test]
    fn encrypt() {
        let (a, _, b, b_g) = sample_keypairs();

        let m = JubJubScalar::random(&mut OsRng);
        let m = GENERATOR_EXTENDED * m;

        let cipher = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, &m);
        let decrypt = cipher.decrypt(&b);

        assert_eq!(m, decrypt);
    }

    #[test]
    fn wrong_key() {
        let (a, _, b, b_g) = sample_keypairs();

        let m = JubJubScalar::random(&mut OsRng);
        let m = GENERATOR_EXTENDED * m;

        let cipher = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, &m);

        let wrong = b - JubJubScalar::one();
        let decrypt = cipher.decrypt(&wrong);

        assert_ne!(m, decrypt);
    }

    #[test]
    fn homomorphic_add() {
        let (a, _, b, b_g) = sample_keypairs();

        let mut m = [JubJubScalar::zero(); 4];
        m.iter_mut()
            .for_each(|x| *x = JubJubScalar::random(&mut OsRng));

        let mut m_g = [JubJubExtended::default(); 4];
        m_g.iter_mut()
            .zip(m.iter())
            .for_each(|(x, y)| *x = GENERATOR_EXTENDED * y);

        let result = m[0] + m[1] + m[2] + m[3];
        let result = GENERATOR_EXTENDED * result;

        let mut cipher = [ElgamalCipher::default(); 4];
        cipher.iter_mut().zip(m_g.iter()).for_each(|(x, y)| {
            *x = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, y)
        });

        let mut hom_cipher = cipher[0] + cipher[1];
        hom_cipher += cipher[2];
        hom_cipher = &hom_cipher + &cipher[3];

        let hom_decrypt = hom_cipher.decrypt(&b);

        assert_eq!(result, hom_decrypt);
    }

    #[test]
    fn homomorphic_sub() {
        let (a, _, b, b_g) = sample_keypairs();

        let mut m = [JubJubScalar::zero(); 4];
        m.iter_mut()
            .for_each(|x| *x = JubJubScalar::random(&mut OsRng));

        let mut m_g = [JubJubExtended::default(); 4];
        m_g.iter_mut()
            .zip(m.iter())
            .for_each(|(x, y)| *x = GENERATOR_EXTENDED * y);

        let result = m[0] - m[1] - m[2] - m[3];
        let result = GENERATOR_EXTENDED * result;

        let mut cipher = [ElgamalCipher::default(); 4];
        cipher.iter_mut().zip(m_g.iter()).for_each(|(x, y)| {
            *x = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, y)
        });

        let mut hom_cipher = cipher[0] - cipher[1];
        hom_cipher -= cipher[2];
        hom_cipher = &hom_cipher - &cipher[3];

        let hom_decrypt = hom_cipher.decrypt(&b);

        assert_eq!(result, hom_decrypt);
    }

    #[test]
    fn homomorphic_mul() {
        let (a, _, b, b_g) = sample_keypairs();

        let mut m = [JubJubScalar::zero(); 4];
        m.iter_mut()
            .for_each(|x| *x = JubJubScalar::random(&mut OsRng));

        let mut m_g = [JubJubExtended::default(); 4];
        m_g.iter_mut()
            .zip(m.iter())
            .for_each(|(x, y)| *x = GENERATOR_EXTENDED * y);

        let result = m[0] * m[1] * m[2] * m[3];
        let result = GENERATOR_EXTENDED * result;

        let mut cipher =
            ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, &m_g[0]);

        cipher = &cipher * &m[1];
        cipher = &cipher * m[2];
        cipher *= m[3];

        let decrypt = cipher.decrypt(&b);

        assert_eq!(result, decrypt);
    }

    #[test]
    fn to_bytes() {
        let (a, _, b, b_g) = sample_keypairs();

        let m = JubJubScalar::random(&mut OsRng);
        let m = GENERATOR_EXTENDED * m;

        let cipher = ElgamalCipher::encrypt(&a, &b_g, &GENERATOR_EXTENDED, &m);
        let cipher = cipher.to_bytes();
        let cipher = ElgamalCipher::from_bytes(&cipher).unwrap();

        let decrypt = cipher.decrypt(&b);

        assert_eq!(m, decrypt);
    }
}
