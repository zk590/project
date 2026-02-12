use coset_safe::Error as SafeError;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    IOPatternViolation,

    InvalidIOPattern,

    TooFewInputElements,

    EncryptionFailed,

    DecryptionFailed,

    InvalidPoint,
}

impl From<SafeError> for Error {
    /// 将底层 `coset_safe` 错误映射为当前模块的统一错误类型。
    /// 该转换隔离了外部依赖的错误细节，避免上层接口直接耦合第三方枚举。
    /// 映射保持一一对应，确保调用方可稳定地按语义分支处理失败场景。
    fn from(safe_error: SafeError) -> Self {
        match safe_error {
            SafeError::IOPatternViolation => Self::IOPatternViolation,
            SafeError::InvalidIOPattern => Self::InvalidIOPattern,
            SafeError::TooFewInputElements => Self::TooFewInputElements,
            SafeError::EncryptionFailed => Self::EncryptionFailed,
            SafeError::DecryptionFailed => Self::DecryptionFailed,
        }
    }
}
