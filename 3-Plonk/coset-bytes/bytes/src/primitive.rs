use crate::{Error, Serializable};

/// 为基础整数类型批量实现 `Serializable`（小端编码）。
macro_rules! impl_primitive_serializable {
    ($ty:ty) => {
        impl Serializable<{ core::mem::size_of::<$ty>() }> for $ty {
            type Error = Error;

            fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
                Ok(Self::from_le_bytes(*bytes))
            }

            fn to_bytes(&self) -> [u8; Self::SIZE] {
                <$ty>::to_le_bytes(*self)
            }
        }
    };
}

impl_primitive_serializable!(u8);
impl_primitive_serializable!(u16);
impl_primitive_serializable!(u32);
impl_primitive_serializable!(u64);
impl_primitive_serializable!(u128);

impl_primitive_serializable!(i8);
impl_primitive_serializable!(i16);
impl_primitive_serializable!(i32);
impl_primitive_serializable!(i64);
impl_primitive_serializable!(i128);
