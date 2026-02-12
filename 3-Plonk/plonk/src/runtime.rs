use coset_bls12_381::BlsScalar;

use crate::prelude::{Constraint, Witness};

#[cfg(feature = "debug")]
use crate::debugger::Debugger;

#[derive(Debug, Clone, Copy)]
#[allow(clippy::large_enum_variant)]
#[allow(dead_code)]
pub enum RuntimeEvent {
    WitnessAppended { witness: Witness, value: BlsScalar },

    ConstraintAppended { constraint: Constraint },

    ProofFinished,
}

#[derive(Debug, Clone)]
pub struct Runtime {
    #[cfg(feature = "debug")]
    debugger: Debugger,
}

impl Default for Runtime {
    /// 返回默认运行时实例。
    /// 语义等价于 `Runtime::new()`，便于在上层结构体中直接派生默认值。
    /// 在启用 `debug` 特性时会连同调试器一并初始化。
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
