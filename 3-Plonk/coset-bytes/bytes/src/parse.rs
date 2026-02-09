
use super::errors::{BadLength, InvalidChar};
use super::serialize::Serializable;

/// 从十六进制字符串解析为定长字节结构。
pub trait ParseHexStr<const N: usize>: Serializable<N> {

    /// 解析长度为 `2*N` 的十六进制字符串并反序列化为目标类型。
    fn from_hex_str(hex_str: &str) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: BadLength + InvalidChar,
    {
        let expected = N * 2;
        if hex_str.len() < expected {
            return Err(Self::Error::bad_length(hex_str.len(), expected));
        }

        let mut bytes = [0u8; N];
        let hex_bytes = hex_str.as_bytes();

        for hex_index in (0..expected).step_by(2) {
            let parsed_byte: u8 = match (
                parse_hex_nibble(hex_bytes[hex_index]),
                parse_hex_nibble(hex_bytes[hex_index + 1]),
            ) {
                (Some(high_nibble), Some(low_nibble)) => {
                    (high_nibble << 4) + low_nibble
                }
                (None, _) => {
                    return Err(Self::Error::invalid_char(
                        hex_bytes[hex_index].into(),
                        hex_index,
                    ))
                }
                (_, None) => {
                    return Err(Self::Error::invalid_char(
                        hex_bytes[hex_index + 1].into(),
                        hex_index + 1,
                    ))
                }
            };
            bytes[hex_index / 2] = parsed_byte;
        }

        Self::from_bytes(&bytes)
    }
}

/// 将 ASCII 十六进制字节数组转换为原始二进制字节数组。

pub const fn hex<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u8; M] {
    let mut buffer = [0u8; M];

    let mut source_index = 0;
    let mut destination_index = 0;
    while source_index < N && destination_index < M {
        let parsed_byte = match (
            parse_hex_nibble(bytes[source_index]),
            parse_hex_nibble(bytes[source_index + 1]),
        ) {
            (Some(high_nibble), Some(low_nibble)) => {
                (high_nibble << 4) + low_nibble
            }
            (_, _) => panic!("hex(): failed to parse the input as hex number"),
        };

        buffer[destination_index] = parsed_byte;
        source_index += 2;
        destination_index += 1;
    }
    buffer
}

const fn parse_hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'0'..=b'9' => Some(c - b'0'),
        _ => None,
    }
}


impl<T, const N: usize> ParseHexStr<N> for T where T: Serializable<N> {}
