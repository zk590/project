use core::ops::Add;

use subtle::Choice;

pub(crate) mod chain;

mod expand_msg;
pub use self::expand_msg::{
    ExpandMessage, ExpandMessageState, ExpandMsgXmd, ExpandMsgXof,
    InitExpandMessage,
};

mod map_g1;
mod map_g2;
mod map_scalar;

use crate::generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

///

///

pub trait HashToField: Sized {
    ///

    type InputLength: ArrayLength<u8>;

    fn from_okm(okm: &GenericArray<u8, Self::InputLength>) -> Self;

    ///

    ///

    fn hash_to_field<X: ExpandMessage>(
        message: &[u8],
        dst: &[u8],
        output: &mut [Self],
    ) {
        let len_per_elm = Self::InputLength::to_usize();
        let len_in_bytes = output.len() * len_per_elm;
        let mut expander = X::init_expand(message, dst, len_in_bytes);

        let mut buf = GenericArray::<u8, Self::InputLength>::default();
        output.iter_mut().for_each(|item| {
            expander.read_into(&mut buf[..]);
            *item = Self::from_okm(&buf);
        });
    }
}

pub trait MapToCurve: Sized {
    type Field: Copy + Default + HashToField;

    fn map_to_curve(elt: &Self::Field) -> Self;

    fn clear_h(&self) -> Self;
}

pub trait HashToCurve<X: ExpandMessage>:
    MapToCurve + for<'a> Add<&'a Self, Output = Self>
{
    ///

    fn hash_to_curve(message: impl AsRef<[u8]>, dst: &[u8]) -> Self {
        let mut u = [Self::Field::default(); 2];
        Self::Field::hash_to_field::<X>(message.as_ref(), dst, &mut u);
        let p1 = Self::map_to_curve(&u[0]);
        let p2 = Self::map_to_curve(&u[1]);
        (p1 + &p2).clear_h()
    }

    ///

    ///

    fn encode_to_curve(message: impl AsRef<[u8]>, dst: &[u8]) -> Self {
        let mut u = [Self::Field::default(); 1];
        Self::Field::hash_to_field::<X>(message.as_ref(), dst, &mut u);
        let p = Self::map_to_curve(&u[0]);
        p.clear_h()
    }
}

impl<G, X> HashToCurve<X> for G
where
    G: MapToCurve + for<'a> Add<&'a Self, Output = Self>,
    X: ExpandMessage,
{
}

pub(crate) trait Sgn0 {
    fn sgn0(&self) -> Choice;
}
