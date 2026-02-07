
/// 长度不匹配错误构造接口。
pub trait BadLength {

    /// 按实际长度与期望长度构造错误。
    fn bad_length(found: usize, expected: usize) -> Self;
}


/// 非法字符错误构造接口。
pub trait InvalidChar {

    /// 按非法字符与其索引位置构造错误。
    fn invalid_char(ch: char, index: usize) -> Self;
}

/// `coset-bytes` 通用错误类型。
#[derive(Copy, Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {

    /// 输入数据语义不合法。
    InvalidData,


    /// 输入长度与预期不一致。
    BadLength {

        found: usize,

        expected: usize,
    },


    /// 输入中含非法字符。
    InvalidChar {

        ch: char,

        index: usize,
    },
}

impl BadLength for Error {
    fn bad_length(found: usize, expected: usize) -> Self {
        Self::BadLength { found, expected }
    }
}

impl InvalidChar for Error {
    fn invalid_char(ch: char, index: usize) -> Self {
        Self::InvalidChar { ch, index }
    }
}
