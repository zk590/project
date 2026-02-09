// 模块说明：本文件实现 PLONK 组件（src/composer/constraint_system.rs）。

//

pub(crate) mod constraint;
pub(crate) mod ecc;
pub(crate) mod witness;

pub(crate) use constraint::{Selector, WiredWitness};
pub(crate) use witness::WireData;

pub use constraint::Constraint;
pub use ecc::WitnessPoint;
pub use witness::Witness;
