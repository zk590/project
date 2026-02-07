
use super::errors::{BadLength, InvalidChar};
use super::serialize::Serializable;

/// An optional trait used to parse a string slice for types that implements
/// the [`Serializable`] trait.
/// The default implementation makes use of [`Serializable`] trait to provide
/// the necessary parsing functionality without additional code from the
/// consumer.
pub trait ParseHexStr<const N: usize>: Serializable<N> {
    /// Parse a string slice as bytes hex representation and returns `
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
                val(hex_bytes[hex_index]),
                val(hex_bytes[hex_index + 1]),
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

/// A constant funtion to parse a bytes string representing hexadecimals
/// (e.g. `b"fe12c6"` ) into bytes (e.g `[0xfe, 0x12, 0xc6]`).
/// If a smaller destination buffer is provided, the value will be truncated
/// (e.g `[0xfe, 0x12]`); if a bigger destination buffer is provided, it will
/// be padded with zeroes (e.g. `[0xfe, 0x12, 0xc6, 0x0, 0x0])
///
/// If an invalid character is given, it will panic at compile time.
pub const fn hex<const N: usize, const M: usize>(bytes: &[u8; N]) -> [u8; M] {
    let mut buffer = [0u8; M];

    let mut source_index = 0;
    let mut destination_index = 0;
    while source_index < N && destination_index < M {
        let parsed_byte = match (
            val(bytes[source_index]),
            val(bytes[source_index + 1]),
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

const fn val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'0'..=b'9' => Some(c - b'0'),
        _ => None,
    }
}

// Auto trait [`ParseHexStr`] for any type that implements [`Serializable`]
impl<T, const N: usize> ParseHexStr<N> for T where T: Serializable<N> {}
