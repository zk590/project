//

use alloc::vec::Vec;

use coset_bls12_381::BlsScalar;
use coset_jubjub::JubJubScalar;
use coset_safe::{Call, Sponge};

use crate::hades::ScalarPermutation;
use crate::Error;

#[cfg(feature = "zk")]
pub(crate) mod gadget;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Domain {
    Merkle4,

    Merkle2,

    Encryption,

    Other,
}

impl From<Domain> for u64 {
    fn from(domain: Domain) -> Self {
        match domain {
            // 2^4 - 1
            Domain::Merkle4 => 0x0000_0000_0000_000f,
            // 2^2 - 1
            Domain::Merkle2 => 0x0000_0000_0000_0003,
            // 2^32
            Domain::Encryption => 0x0000_0001_0000_0000,
            // 0
            Domain::Other => 0x0000_0000_0000_0000,
        }
    }
}

/// 根据输入分段和输出长度构造 sponge 的 IO 模式，并执行域约束检查。
fn build_sponge_io_pattern<T>(
    domain: Domain,
    input_segments: &[&[T]],
    output_len: usize,
) -> Result<Vec<Call>, Error> {
    let mut io_calls = Vec::new();

    let total_input_len = input_segments
        .iter()
        .fold(0, |accumulator, segment| accumulator + segment.len());
    match domain {
        Domain::Merkle2 if total_input_len != 2 || output_len != 1 => {
            return Err(Error::IOPatternViolation);
        }
        Domain::Merkle4 if total_input_len != 4 || output_len != 1 => {
            return Err(Error::IOPatternViolation);
        }
        _ => {}
    }
    for segment in input_segments.iter() {
        io_calls.push(Call::Absorb(segment.len()));
    }
    io_calls.push(Call::Squeeze(output_len));

    Ok(io_calls)
}

pub struct Hash<'a> {
    domain: Domain,
    input: Vec<&'a [BlsScalar]>,
    output_len: usize,
}

impl<'a> Hash<'a> {
    /// 创建指定域分离标签的 Poseidon 哈希上下文。
    pub fn new(domain: Domain) -> Self {
        Self {
            domain,
            input: Vec::new(),
            output_len: 1,
        }
    }

    /// 设置输出域元素个数（仅 `Domain::Other` 生效）。
    pub fn output_len(&mut self, output_len: usize) {
        if self.domain == Domain::Other && output_len > 0 {
            self.output_len = output_len;
        }
    }

    /// 追加一段输入数据。
    pub fn update(&mut self, input: &'a [BlsScalar]) {
        self.input.push(input);
    }

    /// 执行 sponge 并返回完整域元素输出。
    pub fn finalize(&self) -> Vec<BlsScalar> {
        let mut poseidon_sponge = Sponge::start(
            ScalarPermutation::new(),
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

    /// 执行哈希并将结果截断到 JubJub 标量位宽。
    pub fn finalize_truncated(&self) -> Vec<JubJubScalar> {
        const TRUNCATION_MASK: BlsScalar = BlsScalar::from_raw([
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x03ff_ffff_ffff_ffff,
        ]);

        let field_elements = self.finalize();

        field_elements
            .iter()
            .map(|field_element| {
                JubJubScalar::from_raw(
                    (field_element & &TRUNCATION_MASK).reduce().0,
                )
            })
            .collect()
    }

    /// 便捷接口：一次性计算 `digest`。
    pub fn digest(domain: Domain, input: &'a [BlsScalar]) -> Vec<BlsScalar> {
        let mut poseidon_hash = Self::new(domain);
        poseidon_hash.update(input);
        poseidon_hash.finalize()
    }

    /// 便捷接口：一次性计算截断后的 `digest`。
    pub fn digest_truncated(
        domain: Domain,
        input: &'a [BlsScalar],
    ) -> Vec<JubJubScalar> {
        let mut poseidon_hash = Self::new(domain);
        poseidon_hash.update(input);
        poseidon_hash.finalize_truncated()
    }
}
