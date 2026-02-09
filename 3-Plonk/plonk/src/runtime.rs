//

use coset_bls12_381::BlsScalar;

use crate::prelude::{Constraint, Witness};

#[cfg(feature = "debug")]
use crate::debugger::Debugger;

#[derive(Debug, Clone, Copy)]
#[allow(clippy::large_enum_variant)]
pub enum RuntimeEvent {
    WitnessAppended { w: Witness, v: BlsScalar },

    ConstraintAppended { c: Constraint },

    ProofFinished,
}

#[derive(Debug, Clone)]
pub struct Runtime {
    #[cfg(feature = "debug")]
    debugger: Debugger,
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    #[allow(unused_variables)]
    /// 创建运行时事件收集器（在 `debug` 特性下启用调试器）。
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "debug")]
            debugger: Debugger::new(),
        }
    }

    #[allow(unused_variables)]
    /// 记录一次运行时事件（无 `debug` 时为空操作）。
    pub(crate) fn event(&mut self, event: RuntimeEvent) {
        #[cfg(feature = "debug")]
        self.debugger.event(event);
    }
}
