//

use alloc::vec::Vec;

use coset_safe::Sponge;
use plonk::prelude::{Composer, Witness};

use crate::hades::GadgetPermutation;
use crate::Domain;

use super::build_sponge_io_pattern;

pub struct HashGadget<'a> {
    domain: Domain,
    input: Vec<&'a [Witness]>,
    output_len: usize,
}

impl<'a> HashGadget<'a> {
    /// 创建约束系统中的 Poseidon 哈希 gadget 上下文。
    pub fn new(domain: Domain) -> Self {
        Self {
            domain,
            input: Vec::new(),
            output_len: 1,
        }
    }

    /// 设置输出 witness 个数（仅 `Domain::Other` 生效）。
    pub fn output_len(&mut self, output_len: usize) {
        if self.domain == Domain::Other && output_len > 0 {
            self.output_len = output_len;
        }
    }

    /// 追加一段输入 witness。
    pub fn update(&mut self, input: &'a [Witness]) {
        self.input.push(input);
    }

    /// 在电路中执行 Poseidon sponge 并返回输出 witness。
    pub fn finalize(&self, composer: &mut Composer) -> Vec<Witness> {
        let mut poseidon_sponge = Sponge::start(
            GadgetPermutation::new(composer),
            build_sponge_io_pattern(self.domain, &self.input, self.output_len)
                .expect("io-pattern should be valid"),
            self.domain.into(),
        )
        .expect("at this point the io-pattern is valid");

        for segment in self.input.iter() {
            poseidon_sponge
                .absorb(segment.len(), segment)
                .expect("at this point the io-pattern is valid");
        }

        poseidon_sponge
            .squeeze(self.output_len)
            .expect("at this point the io-pattern is valid");

        poseidon_sponge
            .finish()
            .expect("at this point the io-pattern is valid")
    }

    /// 对输出做位宽截断，得到 JubJub 标量语义的 witness。
    pub fn finalize_truncated(&self, composer: &mut Composer) -> Vec<Witness> {
        let field_witnesses = self.finalize(composer);

        field_witnesses
            .iter()
            .map(|witness| {
                composer.append_logic_xor::<125>(*witness, Composer::ZERO)
            })
            .collect()
    }

    /// 便捷接口：一次性计算 `digest`。
    pub fn digest(
        composer: &mut Composer,
        domain: Domain,
        input: &'a [Witness],
    ) -> Vec<Witness> {
        let mut poseidon_hash = Self::new(domain);
        poseidon_hash.update(input);
        poseidon_hash.finalize(composer)
    }

    /// 便捷接口：一次性计算截断后的 `digest`。
    pub fn digest_truncated(
        composer: &mut Composer,
        domain: Domain,
        input: &'a [Witness],
    ) -> Vec<Witness> {
        let mut poseidon_hash = Self::new(domain);
        poseidon_hash.update(input);
        poseidon_hash.finalize_truncated(composer)
    }
}
