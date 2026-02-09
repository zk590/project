// 模块说明：本文件实现 PLONK
// 组件（src/commitment_scheme/kzg10/commitment.rs）。

//

use coset_bls12_381::{G1Affine, G1Projective};
use coset_bytes::{DeserializableSlice, Serializable};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct Commitment(
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)] pub(crate) G1Affine,
);

impl From<G1Affine> for Commitment {
    fn from(point: G1Affine) -> Commitment {
        Commitment(point)
    }
}

impl From<G1Projective> for Commitment {
    fn from(point: G1Projective) -> Commitment {
        Commitment(point.into())
    }
}

impl Serializable<{ G1Affine::SIZE }> for Commitment {
    type Error = coset_bytes::Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let g1 = G1Affine::from_slice(buf)?;
        Ok(Self(g1))
    }
}

impl Commitment {
    fn identity() -> Commitment {
        Commitment(G1Affine::identity())
    }
}

impl Default for Commitment {
    fn default() -> Commitment {
        Commitment::identity()
    }
}

#[cfg(test)]
mod commitment_tests {
    use super::*;

    #[test]
    fn commitment_coset_bytes_serde() {
        let commitment = Commitment(coset_bls12_381::G1Affine::generator());
        let bytes = commitment.to_bytes();
        let obtained_comm = Commitment::from_slice(&bytes)
            .expect("Error on the deserialization");
        assert_eq!(commitment, obtained_comm);
    }
}
