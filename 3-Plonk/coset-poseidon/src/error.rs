


//


use dusk_safe::Error as SafeError;


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
