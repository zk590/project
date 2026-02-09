//

use coset_bytes::{Error as BytesError, Serializable};
use subtle::{Choice, ConditionallySelectable, CtOption};

use super::{G2Affine, B};
use crate::fp::Fp;
use crate::fp2::Fp2;

impl G2Affine {
    ///

    ///

    pub fn to_raw_bytes(&self) -> [u8; Self::RAW_SIZE] {
        let mut bytes = [0u8; Self::RAW_SIZE];
        let chunks = bytes.chunks_mut(8);

        self.x
            .c0
            .internal_repr()
            .iter()
            .chain(self.x.c1.internal_repr().iter())
            .chain(self.y.c0.internal_repr().iter())
            .chain(self.y.c1.internal_repr().iter())
            .zip(chunks)
            .for_each(|(n, c)| c.copy_from_slice(&n.to_le_bytes()));

        bytes[Self::RAW_SIZE - 1] = self.infinity.into();

        bytes
    }

    ///

    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut xc0 = [0u64; 6];
        let mut xc1 = [0u64; 6];
        let mut yc0 = [0u64; 6];
        let mut yc1 = [0u64; 6];
        let mut z = [0u8; 8];

        xc0.iter_mut()
            .chain(xc1.iter_mut())
            .chain(yc0.iter_mut())
            .chain(yc1.iter_mut())
            .zip(bytes.chunks_exact(8))
            .for_each(|(n, c)| {
                z.copy_from_slice(c);
                *n = u64::from_le_bytes(z);
            });

        let c0 = Fp::from_raw_unchecked(xc0);
        let c1 = Fp::from_raw_unchecked(xc1);
        let x = Fp2 { c0, c1 };

        let c0 = Fp::from_raw_unchecked(yc0);
        let c1 = Fp::from_raw_unchecked(yc1);
        let y = Fp2 { c0, c1 };

        let infinity = if bytes.len() >= Self::RAW_SIZE {
            bytes[Self::RAW_SIZE - 1].into()
        } else {
            0u8.into()
        };

        Self { x, y, infinity }
    }
}

impl Serializable<96> for G2Affine {
    type Error = BytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let infinity = self.infinity.into();

        let x = Fp2::conditional_select(&self.x, &Fp2::zero(), infinity);

        let mut res = [0; Self::SIZE];

        (res[0..48]).copy_from_slice(&x.c1.to_bytes()[..]);
        (res[48..96]).copy_from_slice(&x.c0.to_bytes()[..]);

        res[0] |= 1u8 << 7;

        res[0] |= u8::conditional_select(&0u8, &(1u8 << 6), infinity);

        res[0] |= u8::conditional_select(
            &0u8,
            &(1u8 << 5),
            (!infinity) & self.y.lexicographically_largest(),
        );

        res
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let compression_flag_set = Choice::from((buf[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((buf[0] >> 6) & 1);
        let sort_flag_set = Choice::from((buf[0] >> 5) & 1);

        let xc1 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&buf[0..48]);

            tmp[0] &= 0b0001_1111;

            Fp::from_bytes(&tmp)
        };
        let xc0 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&buf[48..96]);

            Fp::from_bytes(&tmp)
        };

        let x: Option<Self> = xc1
            .and_then(|xc1| {
                xc0.and_then(|xc0| {
                    let x = Fp2 { c0: xc0, c1: xc1 };

                    //

                    CtOption::new(
                        G2Affine::identity(),
                        infinity_flag_set
                            & compression_flag_set
                            & (!sort_flag_set)
                            & x.is_zero(),
                    )
                    .or_else(|| {
                        ((x.square() * x) + B).sqrt().and_then(|y| {
                            let y = Fp2::conditional_select(
                                &y,
                                &-y,
                                y.lexicographically_largest() ^ sort_flag_set,
                            );

                            CtOption::new(
                                G2Affine {
                                    x,
                                    y,
                                    infinity: infinity_flag_set.into(),
                                },
                                (!infinity_flag_set) & compression_flag_set,
                            )
                        })
                    })
                })
            })
            .into();

        match x {
            Some(x) if x.is_torsion_free().unwrap_u8() == 1 => Ok(x),
            _ => Err(BytesError::InvalidData),
        }
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    extern crate alloc;

    use alloc::format;
    use alloc::string::{String, ToString};

    use serde::de::Error as SerdeError;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for G2Affine {
        fn serialize<S: Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let s = hex::encode(self.to_bytes());
            s.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for G2Affine {
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            let s = String::deserialize(deserializer)?;
            let decoded = hex::decode(&s).map_err(SerdeError::custom)?;
            let decoded_len = decoded.len();
            let bytes: [u8; G2Affine::SIZE] =
                decoded.try_into().map_err(|_| {
                    SerdeError::invalid_length(
                        decoded_len,
                        &G2Affine::SIZE.to_string().as_str(),
                    )
                })?;
            let affine = G2Affine::from_bytes(&bytes)
                .map_err(|err| SerdeError::custom(format!("{err:?}")))?;
            Ok(affine)
        }
    }

    #[cfg(test)]
    mod tests {
        use alloc::boxed::Box;

        use super::*;
        use crate::coset::test_utils;

        #[test]
        fn serde_g2_affine() -> Result<(), Box<dyn std::error::Error>> {
            let gen = G2Affine::generator();
            let ser = test_utils::assert_canonical_json(
                &gen,
                "\"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8\""
            )?;
            let deser: G2Affine = serde_json::from_str(&ser).unwrap();
            assert_eq!(gen, deser);
            Ok(())
        }

        #[test]
        fn serde_g2_affine_too_short_encoded() {
            let length_95_enc: &str = "\"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bd\"";

            let g2_affine: Result<G2Affine, _> =
                serde_json::from_str(&length_95_enc);
            assert!(g2_affine.is_err());
        }

        #[test]
        fn serde_g2_affine_too_long_encoded() {
            let length_97_enc = "\"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb800\"";

            let g2_affine: Result<G2Affine, _> =
                serde_json::from_str(&length_97_enc);
            assert!(g2_affine.is_err());
        }
    }
}

#[test]
fn g2_affine_bytes_unchecked() {
    let gen = G2Affine::generator();
    let ident = G2Affine::identity();

    let gen_p = gen.to_raw_bytes();
    let gen_p = unsafe { G2Affine::from_slice_unchecked(&gen_p) };

    let ident_p = ident.to_raw_bytes();
    let ident_p = unsafe { G2Affine::from_slice_unchecked(&ident_p) };

    assert_eq!(gen, gen_p);
    assert_eq!(ident, ident_p);
}
