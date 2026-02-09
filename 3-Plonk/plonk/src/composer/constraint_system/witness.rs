// 模块说明：本文件实现 PLONK
// 组件（src/composer/constraint_system/witness.rs）。

//

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum WireData {
    Left(usize),

    Right(usize),

    Output(usize),

    Fourth(usize),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Witness {
    index: usize,
}

impl Default for Witness {
    fn default() -> Self {
        crate::composer::Composer::ZERO
    }
}

impl Witness {
    pub const ZERO: Witness = Witness::new(0);

    pub const ONE: Witness = Witness::new(1);

    pub(crate) const fn new(index: usize) -> Self {
        Self { index }
    }

    pub const fn index(&self) -> usize {
        self.index
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for Witness {}
