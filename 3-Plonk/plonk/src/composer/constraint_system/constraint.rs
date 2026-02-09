// 模块说明：本文件实现 PLONK
// 组件（src/composer/constraint_system/constraint.rs）。

//

use crate::prelude::{Composer, Witness};
use coset_bls12_381::BlsScalar;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Selector {
    Multiplication = 0x00,

    Left = 0x01,

    Right = 0x02,

    Output = 0x03,

    Fourth = 0x04,

    Constant = 0x05,

    PublicInput = 0x06,

    Arithmetic = 0x07,

    Range = 0x08,

    Logic = 0x09,

    GroupAddFixedBase = 0x0a,

    GroupAddVariableBase = 0x0b,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WiredWitness {
    A = 0x00,

    B = 0x01,

    C = 0x02,

    D = 0x03,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Constraint {
    coefficients: [BlsScalar; Self::COEFFICIENTS],
    witnesses: [Witness; Self::WITNESSES],

    //

    //

    //

    //

    //
    has_public_input: bool,
}

impl Default for Constraint {
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<[BlsScalar]> for Constraint {
    fn as_ref(&self) -> &[BlsScalar] {
        &self.coefficients
    }
}

impl Constraint {
    pub const COEFFICIENTS: usize = 12;

    pub const WITNESSES: usize = 4;

    pub const fn new() -> Self {
        Self {
            coefficients: [BlsScalar::zero(); Self::COEFFICIENTS],
            witnesses: [Composer::ZERO; Self::WITNESSES],
            has_public_input: false,
        }
    }

    fn from_external(constraint: &Self) -> Self {
        const EXTERNAL: usize = Selector::Arithmetic as usize;

        let mut s = Self::default();

        let src = &constraint.coefficients[..EXTERNAL];
        let dst = &mut s.coefficients[..EXTERNAL];

        dst.copy_from_slice(src);

        s.has_public_input = constraint.has_public_input();
        s.witnesses.copy_from_slice(&constraint.witnesses);

        s
    }

    pub(crate) fn set<T: Into<BlsScalar>>(mut self, r: Selector, s: T) -> Self {
        self.coefficients[r as usize] = s.into();

        self
    }

    pub(crate) fn set_witness(&mut self, index: WiredWitness, w: Witness) {
        self.witnesses[index as usize] = w;
    }

    pub(crate) const fn coeff(&self, r: Selector) -> &BlsScalar {
        &self.coefficients[r as usize]
    }

    pub(crate) const fn witness(&self, w: WiredWitness) -> Witness {
        self.witnesses[w as usize]
    }

    pub fn mult<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Multiplication, s)
    }

    pub fn left<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Left, s)
    }

    pub fn right<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Right, s)
    }

    pub fn output<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Output, s)
    }

    pub fn fourth<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Fourth, s)
    }

    pub fn constant<T: Into<BlsScalar>>(self, s: T) -> Self {
        self.set(Selector::Constant, s)
    }

    pub fn public<T: Into<BlsScalar>>(mut self, s: T) -> Self {
        self.has_public_input = true;

        self.set(Selector::PublicInput, s)
    }

    pub fn a(mut self, w: Witness) -> Self {
        self.set_witness(WiredWitness::A, w);

        self
    }

    pub fn b(mut self, w: Witness) -> Self {
        self.set_witness(WiredWitness::B, w);

        self
    }

    pub fn c(mut self, w: Witness) -> Self {
        self.set_witness(WiredWitness::C, w);

        self
    }

    pub fn d(mut self, w: Witness) -> Self {
        self.set_witness(WiredWitness::D, w);

        self
    }

    pub(crate) const fn has_public_input(&self) -> bool {
        self.has_public_input
    }

    pub(crate) fn arithmetic(s: &Self) -> Self {
        Self::from_external(s).set(Selector::Arithmetic, 1)
    }

    #[allow(dead_code)]

    pub(crate) fn range(s: &Self) -> Self {
        Self::from_external(s).set(Selector::Range, 1)
    }

    #[allow(dead_code)]

    pub(crate) fn logic(s: &Self) -> Self {
        Self::from_external(s)
            .set(Selector::Constant, 1)
            .set(Selector::Logic, 1)
    }

    #[allow(dead_code)]

    pub(crate) fn logic_xor(s: &Self) -> Self {
        Self::from_external(s)
            .set(Selector::Constant, -BlsScalar::one())
            .set(Selector::Logic, -BlsScalar::one())
    }

    #[allow(dead_code)]

    pub(crate) fn group_add_fixed_base(s: &Self) -> Self {
        Self::from_external(s).set(Selector::GroupAddFixedBase, 1)
    }

    #[allow(dead_code)]

    pub(crate) fn group_add_variable_base(s: &Self) -> Self {
        Self::from_external(s).set(Selector::GroupAddVariableBase, 1)
    }
}
