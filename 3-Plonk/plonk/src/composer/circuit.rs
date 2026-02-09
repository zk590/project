// 模块说明：本文件实现 PLONK 组件（src/composer/circuit.rs）。

//

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::prelude::{Composer, Error};

use super::compress::CompressedCircuit;

pub trait Circuit: Default {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error>;

    fn size(&self) -> usize {
        let mut composer = Composer::initialized();
        match self.circuit(&mut composer) {
            Ok(_) => composer.constraints(),
            Err(_) => 0,
        }
    }

    #[cfg(feature = "alloc")]
    fn compress() -> Result<Vec<u8>, Error> {
        let mut composer = Composer::initialized();
        Self::default().circuit(&mut composer)?;

        let hades_optimization = true;
        Ok(CompressedCircuit::from_composer(
            hades_optimization,
            composer,
        ))
    }
}
