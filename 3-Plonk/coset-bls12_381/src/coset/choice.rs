use core::convert::Infallible;

use coset_bytes::Serializable;
use subtle::ConditionallySelectable;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize,
};

#[derive(Copy, Clone, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, RkyvSerialize, RkyvDeserialize),
    archive_attr(derive(CheckBytes))
)]
pub struct Choice(u8);

impl Choice {
    pub fn unwrap_u8(&self) -> u8 {
        self.0
    }
}

impl ConditionallySelectable for Choice {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        Self(u8::conditional_select(&a.0, &b.0, choice))
    }
}

impl Serializable<1> for Choice {
    type Error = Infallible;

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self(bytes[0]))
    }

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        [self.0; Self::SIZE]
    }
}

impl From<u8> for Choice {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<Choice> for u8 {
    fn from(choice_value: Choice) -> Self {
        choice_value.0
    }
}

impl From<subtle::Choice> for Choice {
    fn from(subtle_choice: subtle::Choice) -> Self {
        Self(subtle_choice.unwrap_u8())
    }
}

impl From<Choice> for subtle::Choice {
    fn from(choice_value: Choice) -> Self {
        subtle::Choice::from(choice_value.0)
    }
}

impl From<Choice> for bool {
    fn from(choice_value: Choice) -> Self {
        subtle::Choice::from(choice_value.0).into()
    }
}
