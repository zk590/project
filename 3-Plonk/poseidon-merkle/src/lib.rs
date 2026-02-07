


//



#![no_std]
#![deny(clippy::pedantic)]

#[cfg(feature = "zk")]
pub mod zk;

use coset_bls12_381::BlsScalar;
use coset_bytes::Serializable;
use coset_merkle::Aggregate;
use coset_poseidon::{Domain, Hash};

pub const ARITY: usize = 4;


pub type Tree<T, const H: usize> = coset_merkle::Tree<Item<T>, H, ARITY>;


pub type Opening<T, const H: usize> = coset_merkle::Opening<Item<T>, H, ARITY>;



///



///



///




///

///




/// }
///





/// }
///





///     };
///


///




///                 }



///             };



///                 }



///             }
///         }
///

///     }
/// }
///



///



/// };
///





///     },
/// };

/// ```
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Item<T> {
    pub hash: BlsScalar,
    pub data: T,
}

impl<T> Item<T> {

    pub fn new(hash: BlsScalar, data: T) -> Self {
        Self { hash, data }
    }
}

impl<T> Aggregate<ARITY> for Item<T>
where
    T: Aggregate<ARITY>,
{
    const EMPTY_SUBTREE: Self = Item {
        hash: BlsScalar::zero(),
        data: T::EMPTY_SUBTREE,
    };

    fn aggregate(items: [&Self; ARITY]) -> Self {
        let empty_data = &T::EMPTY_SUBTREE;

        let mut level_hashes = [BlsScalar::zero(); ARITY];
        let mut level_data = [empty_data; ARITY];


        items
            .into_iter()
            .enumerate()
            .for_each(|(item_index, item)| {
                level_hashes[item_index] = item.hash;
                level_data[item_index] = &item.data;
            });



        Item {
            hash: Hash::digest(Domain::Merkle4, &level_hashes)[0],
            data: T::aggregate(level_data),
        }
    }
}

impl Serializable<32> for Item<()> {
    type Error = <BlsScalar as Serializable<32>>::Error;

    fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Item {
            hash: <BlsScalar as Serializable<32>>::from_bytes(bytes)?,
            data: (),
        })
    }

    fn to_bytes(&self) -> [u8; 32] {
        self.hash.to_bytes()
    }
}
