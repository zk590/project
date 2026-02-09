// 模块说明：本文件实现 PLONK 组件（src/error.rs）。


use coset_bytes::Error as CosetBytesError;

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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvalDomainSize {
                log_size_of_group,
                adacity,
            } => write!(
                f,
                "Log-size of the EvaluationDomain group > TWO_ADACITY\
            Size: {:?} > TWO_ADACITY = {:?}",
                log_size_of_group, adacity
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
            Self::BytesError(err) => write!(f, "{:?}", err),
            Self::UnsupportedWNAF2k => write!(
                f,
                "WNAF2k cannot hold values not contained in `[-1..1]`"
            ),
            Self::PublicInputNotFound {
                index
            } => write!(f, "The public input of index {} is defined in the circuit description, but wasn't declared in the prove instance", index),
            Self::InconsistentPublicInputsLen {
                expected, provided,
            } => write!(f, "The provided public inputs set of length {} doesn't match the processed verifier: {}", provided, expected),
            Self::InvalidCompressedCircuit => write!(f, "invalid compressed circuit"),
        }
    }
}

impl From<CosetBytesError> for Error {
    fn from(bytes_err: CosetBytesError) -> Self {
        Self::BytesError(bytes_err)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
