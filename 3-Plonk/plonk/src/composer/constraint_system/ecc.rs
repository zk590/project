// 模块说明：本文件实现 PLONK 组件（src/composer/constraint_system/ecc.rs）。

//

use crate::prelude::Witness;
use coset_bls12_381::BlsScalar;

#[derive(Debug, Clone, Copy)]
pub struct WitnessPoint {
    x: Witness,
    y: Witness,
}

impl WitnessPoint {
    #[allow(dead_code)]
    pub(crate) const fn new(x: Witness, y: Witness) -> Self {
        Self { x, y }
    }

    pub const fn x(&self) -> &Witness {
        &self.x
    }

    pub const fn y(&self) -> &Witness {
        &self.y
    }
}

#[derive(Debug, Clone, Copy)]

pub(crate) struct WnafRound<T: Into<Witness>> {
    pub acc_x: T,

    pub acc_y: T,

    pub accumulated_bit: T,

    pub xy_alpha: T,

    pub x_beta: BlsScalar,

    pub y_beta: BlsScalar,

    pub xy_beta: BlsScalar,
}
