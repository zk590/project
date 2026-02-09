// 模块说明：本文件实现 PLONK 组件（src/commitment_scheme/kzg10/srs.rs）。

//

use super::key::{CommitKey, OpeningKey};
use crate::{error::Error, util};
use alloc::vec::Vec;
use coset_bls12_381::{BlsScalar, G1Affine, G1Projective, G2Affine};
use coset_bytes::{DeserializableSlice, Serializable};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Sized + Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]

pub struct PublicParameters {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) commit_key: CommitKey,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) opening_key: OpeningKey,
}

impl PublicParameters {
    const ADDED_BLINDING_DEGREE: usize = 6;

    pub fn setup<R: RngCore + CryptoRng>(
        mut max_degree: usize,
        mut rng: &mut R,
    ) -> Result<PublicParameters, Error> {
        if max_degree < 1 {
            return Err(Error::DegreeIsZero);
        }

        max_degree += Self::ADDED_BLINDING_DEGREE;

        let x = BlsScalar::random(&mut rng);

        let powers_of_x = util::powers_of(&x, max_degree);

        let g = util::random_g1_point(&mut rng);
        let powers_of_g: Vec<G1Projective> =
            util::slow_multiscalar_mul_single_base(&powers_of_x, g);
        assert_eq!(powers_of_g.len(), max_degree + 1);

        let mut normalized_g = vec![G1Affine::identity(); max_degree + 1];
        G1Projective::batch_normalize(&powers_of_g, &mut normalized_g);

        let h: G2Affine = util::random_g2_point(&mut rng).into();
        let x_2: G2Affine = (h * x).into();

        Ok(PublicParameters {
            commit_key: CommitKey {
                powers_of_g: normalized_g,
            },
            opening_key: OpeningKey::new(g.into(), h, x_2),
        })
    }

    pub fn to_raw_var_bytes(&self) -> Vec<u8> {
        let mut bytes = self.opening_key.to_bytes().to_vec();
        bytes.extend(&self.commit_key.to_raw_var_bytes());

        bytes
    }

    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let opening_key = &bytes[..OpeningKey::SIZE];
        let opening_key = OpeningKey::from_slice(opening_key)
            .expect("Error at OpeningKey deserialization");

        let commit_key = &bytes[OpeningKey::SIZE..];
        let commit_key = CommitKey::from_slice_unchecked(commit_key);

        Self {
            commit_key,
            opening_key,
        }
    }

    pub fn to_var_bytes(&self) -> Vec<u8> {
        let mut bytes = self.opening_key.to_bytes().to_vec();
        bytes.extend(self.commit_key.to_var_bytes().iter());
        bytes
    }

    pub fn from_slice(bytes: &[u8]) -> Result<PublicParameters, Error> {
        if bytes.len() <= OpeningKey::SIZE {
            return Err(Error::NotEnoughBytes);
        }
        let mut byte_reader = bytes;
        let opening_key = OpeningKey::from_reader(&mut byte_reader)?;
        let commit_key = CommitKey::from_slice(byte_reader)?;

        let public_parameters = PublicParameters {
            commit_key,
            opening_key,
        };

        Ok(public_parameters)
    }

    pub(crate) fn trim(
        &self,
        truncated_degree: usize,
    ) -> Result<(CommitKey, OpeningKey), Error> {
        let truncated_prover_key = self
            .commit_key
            .truncate(truncated_degree + Self::ADDED_BLINDING_DEGREE)?;
        let opening_key = self.opening_key.clone();
        Ok((truncated_prover_key, opening_key))
    }

    pub fn max_degree(&self) -> usize {
        self.commit_key.max_degree()
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use coset_bls12_381::BlsScalar;
    use rand_core::OsRng;

    #[test]
    fn test_powers_of() {
        let x = BlsScalar::from(10u64);
        let degree = 100u64;

        let powers_of_x = util::powers_of(&x, degree as usize);

        for (power_index, power_value) in powers_of_x.iter().enumerate() {
            assert_eq!(*power_value, x.pow(&[power_index as u64, 0, 0, 0]))
        }

        let last_element = powers_of_x.last().unwrap();
        assert_eq!(*last_element, x.pow(&[degree, 0, 0, 0]))
    }

    #[test]
    fn test_serialize_deserialize_public_parameter() {
        let public_parameters =
            PublicParameters::setup(1 << 7, &mut OsRng).unwrap();

        let deserialized_parameters =
            PublicParameters::from_slice(&public_parameters.to_var_bytes())
                .unwrap();

        assert_eq!(
            deserialized_parameters.commit_key.powers_of_g,
            public_parameters.commit_key.powers_of_g
        );
        assert_eq!(
            deserialized_parameters.opening_key.g,
            public_parameters.opening_key.g
        );
        assert_eq!(
            deserialized_parameters.opening_key.h,
            public_parameters.opening_key.h
        );
        assert_eq!(
            deserialized_parameters.opening_key.x_h,
            public_parameters.opening_key.x_h
        );
    }

    #[test]
    fn public_parameters_bytes_unchecked() {
        let public_parameters =
            PublicParameters::setup(1 << 7, &mut OsRng).unwrap();

        let deserialized_parameters = unsafe {
            let bytes = public_parameters.to_raw_var_bytes();
            PublicParameters::from_slice_unchecked(&bytes)
        };

        assert_eq!(
            public_parameters.commit_key,
            deserialized_parameters.commit_key
        );
        assert_eq!(
            public_parameters.opening_key.g,
            deserialized_parameters.opening_key.g
        );
        assert_eq!(
            public_parameters.opening_key.h,
            deserialized_parameters.opening_key.h
        );
        assert_eq!(
            public_parameters.opening_key.x_h,
            deserialized_parameters.opening_key.x_h
        );
    }
}
