use coset_bytes::Error as CosetBytesError;

/// PLONK 模块统一错误枚举。
/// 该类型聚合了域构造、序列化、承诺与验证流程中的关键失败场景，
/// 便于上层调用方用单一错误通道处理不同子模块异常。
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    InvalidEvalDomainSize {
        log_size_of_group: u32,

        adacity: u32,
    },

    ProofVerificationError,

    CircuitInputsNotFound,

    UninitializedPIGenerator,

    InvalidPublicInputBytes,

    CircuitAlreadyPreprocessed,

    InvalidCircuitSize(usize, usize),

    MismatchedPolyLen,

    DegreeIsZero,

    TruncatedDegreeTooLarge,

    TruncatedDegreeIsZero,

    PolynomialDegreeTooLarge,

    PolynomialDegreeIsZero,

    PairingCheckFailure,

    BytesError(CosetBytesError),

    NotEnoughBytes,

    PointMalformed,

    BlsScalarMalformed,

    JubJubScalarMalformed,

    UnsupportedWNAF2k,

    PublicInputNotFound {
        index: usize,
    },

    InconsistentPublicInputsLen {
        expected: usize,

        provided: usize,
    },

    InvalidCompressedCircuit,
}

#[cfg(feature = "std")]
impl std::fmt::Display for Error {
    /// 将错误转换为可读文本描述。
    /// 输出内容尽量保留关键上下文（如期望值与实际值）以便排障。
    /// 该实现主要用于 CLI 输出与日志系统集成。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvalDomainSize {
                log_size_of_group: requested_log_size,
                adacity: max_supported_adacity,
            } => write!(
                f,
                "Log-size of the EvaluationDomain group > TWO_ADACITY\
            Size: {:?} > TWO_ADACITY = {:?}",
                requested_log_size, max_supported_adacity
            ),
            Self::ProofVerificationError => {
                write!(f, "proof verification failed")
            }
            Self::CircuitInputsNotFound => {
                write!(f, "circuit inputs not found")
            }
            Self::UninitializedPIGenerator => {
                write!(f, "PI generator uninitialized")
            }
            Self::InvalidPublicInputBytes => {
                write!(f, "invalid public input bytes")
            }
            Self::MismatchedPolyLen => {
                write!(f, "the length of the wires is not the same")
            }
            Self::CircuitAlreadyPreprocessed => {
                write!(f, "circuit has already been preprocessed")
            }
            Self::InvalidCircuitSize(description_size, circuit_size) => {
                write!(f, "circuit description has a different amount of gates than the circuit for the proof creation: description size = {description_size}, circuit size = {circuit_size}")
            }
            Self::DegreeIsZero => {
                write!(f, "cannot create PublicParameters with max degree 0")
            }
            Self::TruncatedDegreeTooLarge => {
                write!(f, "cannot trim more than the maximum degree")
            }
            Self::TruncatedDegreeIsZero => write!(
                f,
                "cannot trim PublicParameters to a maximum size of zero"
            ),
            Self::PolynomialDegreeTooLarge => write!(
                f,
                "proving key is not large enough to commit to said polynomial"
            ),
            Self::PolynomialDegreeIsZero => {
                write!(f, "cannot commit to polynomial of zero degree")
            }
            Self::PairingCheckFailure => write!(f, "pairing check failed"),
            Self::NotEnoughBytes => write!(f, "not enough bytes left to read"),
            Self::PointMalformed => write!(f, "BLS point bytes malformed"),
            Self::BlsScalarMalformed => write!(f, "BLS scalar bytes malformed"),
            Self::JubJubScalarMalformed => write!(f, "JubJub scalar bytes malformed"),
            Self::BytesError(coset_bytes_error) => {
                write!(f, "{:?}", coset_bytes_error)
            }
            Self::UnsupportedWNAF2k => write!(
                f,
                "WNAF2k cannot hold values not contained in `[-1..1]`"
            ),
            Self::PublicInputNotFound {
                index: public_input_index,
            } => write!(
                f,
                "The public input of index {} is defined in the circuit description, but wasn't declared in the prove instance",
                public_input_index
            ),
            Self::InconsistentPublicInputsLen {
                expected: expected_len,
                provided: provided_len,
            } => write!(
                f,
                "The provided public inputs set of length {} doesn't match the processed verifier: {}",
                provided_len, expected_len
            ),
            Self::InvalidCompressedCircuit => write!(f, "invalid compressed circuit"),
        }
    }
}

impl From<CosetBytesError> for Error {
    /// 将 `coset-bytes` 错误适配为 PLONK 统一错误类型。
    /// 该转换用于序列化/反序列化路径，把底层错误透传到上层流程。
    /// 这样可在不暴露底层模块细节的前提下保留错误语义。
    fn from(bytes_err: CosetBytesError) -> Self {
        Self::BytesError(bytes_err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
