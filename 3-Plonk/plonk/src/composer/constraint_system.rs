


//







pub(crate) mod constraint;
pub(crate) mod ecc;
pub(crate) mod witness;

pub(crate) use constraint::{Selector, WiredWitness};
pub(crate) use witness::WireData;

pub use constraint::Constraint;
pub use ecc::WitnessPoint;
pub use witness::Witness;
