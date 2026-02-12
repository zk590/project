/// 长度不匹配错误构造接口。
pub trait BadLength {
    /// 按实际长度与期望长度构造错误。
    /// 该接口抽象了长度错误的构造方式，使通用逻辑不依赖具体错误类型。
    /// 对外可以保留丰富上下文，便于调用方快速定位输入与协议不一致的问题。
    fn bad_length(found: usize, expected: usize) -> Self;
}

/// 非法字符错误构造接口。
pub trait InvalidChar {
    /// 按非法字符与其索引位置构造错误。
    /// 该接口用于字符级解析场景，让错误能够精确指向失败位置。
    /// 对诊断十六进制输入、命令行参数或配置文本错误尤为有用。
    fn invalid_char(ch: char, index: usize) -> Self;
}

/// `coset-bytes` 通用错误类型。
#[derive(Copy, Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {
    /// 输入数据语义不合法。
    InvalidData,

    /// 输入长度与预期不一致。
    BadLength { found: usize, expected: usize },

    /// 输入中含非法字符。
    InvalidChar { ch: char, index: usize },
}

impl BadLength for Error {
    /// 构造长度不匹配错误并保留实际值与期望值。
    /// 该实现将输入校验失败统一映射到 `Error::BadLength`。
    /// 调用方可据此决定重试、回退或直接终止流程。
    fn bad_length(found: usize, expected: usize) -> Self {
        Self::BadLength { found, expected }
    }
}

impl InvalidChar for Error {
    /// 构造非法字符错误并保留字符内容与位置索引。
    /// 该实现将文本解析失败统一映射到 `Error::InvalidChar`。
    /// 保留索引后可在上层输出更友好的错误提示信息。
    fn invalid_char(ch: char, index: usize) -> Self {
        Self::InvalidChar { ch, index }
    }
}
