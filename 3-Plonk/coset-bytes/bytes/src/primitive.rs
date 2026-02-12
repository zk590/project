use crate::{Error, Serializable};

/// 为基础整数类型批量实现 `Serializable`（小端编码）。
macro_rules! impl_primitive_serializable {
    ($ty:ty) => {
        impl Serializable<{ core::mem::size_of::<$ty>() }> for $ty {
            type Error = Error;

            /// 按小端字节序将固定长度字节数组解析为基础整数类型。
            /// 该实现直接复用 Rust 标准库的 `from_le_bytes`，避免手工拼装出错。
            /// 由于长度在类型层已经固定，运行时不会出现长度不匹配问题。
            fn from_bytes(
                bytes: &[u8; Self::SIZE],
            ) -> Result<Self, Self::Error> {
                Ok(Self::from_le_bytes(*bytes))
            }

            /// 按小端字节序将基础整数类型编码为固定长度字节数组。
            /// 该输出可与 `from_bytes` 形成稳定可逆的二进制表示。
            /// 统一使用 LE 规则可减少跨平台或跨语言接入时的歧义。
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
