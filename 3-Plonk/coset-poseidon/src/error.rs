use coset_safe::Error as SafeError;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    /// IO 模式与域约束不匹配（如 Merkle 固定输入长度被破坏）。
    IOPatternViolation,

    /// IO 模式本身非法，通常由 absorb/squeeze 调用序列不一致触发。
    InvalidIOPattern,

    /// 提供给 sponge 的输入元素数量不足，无法完成当前步骤。
    TooFewInputElements,

    /// 加密流程失败（包含底层 safe 组件返回的加密错误）。
    EncryptionFailed,

    /// 解密流程失败（包含底层 safe 组件返回的解密错误）。
    DecryptionFailed,

    /// 点编码或曲线点合法性检查失败。
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
