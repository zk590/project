// 模块说明：本文件实现 PLONK 组件（src/lib.rs）。

//

#![allow(clippy::suspicious_arithmetic_impl)]
#![allow(clippy::suspicious_op_assign_impl)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::match_bool)]
#![allow(clippy::too_many_arguments)]
#![deny(rustdoc::broken_intra_doc_links)]
#![allow(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

cfg_if::cfg_if!(
if #[cfg(feature = "alloc")] {

    #[cfg_attr(not(feature = "std"), macro_use)]
    extern crate alloc;

    mod bit_iterator;
    mod compiler;
    mod composer;
    mod runtime;
    mod util;
    mod transcript;

});

#[cfg(feature = "debug")]
pub(crate) mod debugger;

mod commitment_scheme;
mod error;
mod fft;
mod proof_system;

pub mod prelude;
