// 模块说明：本文件实现 PLONK 组件（src/composer/permutation/constants.rs）。

//

use coset_bls12_381::BlsScalar;

pub(crate) const K1: BlsScalar = BlsScalar::from_raw([7, 0, 0, 0]);
pub(crate) const K2: BlsScalar = BlsScalar::from_raw([13, 0, 0, 0]);
pub(crate) const K3: BlsScalar = BlsScalar::from_raw([17, 0, 0, 0]);
