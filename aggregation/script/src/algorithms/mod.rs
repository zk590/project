pub mod errors;
pub mod utils;
pub mod fibonacci;
pub mod fibonacci_mul;
pub mod sha2;
pub mod keccak;
pub mod sha3;
pub mod algorithm_trait;
pub mod coset;
pub mod signature;

// 重新导出errors和utils模块，方便内部使用
// pub use crate::errors;
// pub use crate::utils;

pub use self::algorithm_trait::AlgorithmHandler;
//pub use self::hash::HashAlgorithmHandler;
pub use self::signature::{RSAHandler, ECDSAHandler, SchnorrHandler};
// pub use self::fibonacci::FibonacciHandler;
// pub use self::fibonacci_mul::FibonacciMulHandler;
// pub use self::sha2::SHA2Handler;
// pub use self::dusk::DuskHandler;
// pub use self::keccak::KeccakHandler;
// pub use self::sha3::SHA3Handler;