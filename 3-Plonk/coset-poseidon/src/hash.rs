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
    /// 将哈希域标签编码为常量域分离值。
    /// 这些常量会作为 sponge 初始化标签输入，避免不同业务域碰撞。
    /// 约束域值后，可在同一置换上安全复用 Merkle、加密等多种场景。
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
/// 该函数会在构建 `Sponge` 前静态化吸收/挤出步骤，防止调用序列不一致。
/// 对 Merkle 专用域会强制输入长度与输出长度，保证协议约束可验证。
/// 返回的 `Call` 序列会被后续 `absorb/squeeze` 严格消费。
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
    /// 上下文以“延迟执行”方式收集输入段，最终在 `finalize` 时统一计算。
    /// 默认输出长度为 1 个域元素，适配最常见的哈希摘要场景。
    pub fn new(domain: Domain) -> Self {
        Self {
            domain,
            input: Vec::new(),
            output_len: 1,
        }
    }

    /// 设置输出域元素个数（仅 `Domain::Other` 生效）。
    /// 为避免破坏约束域协议，Merkle 等固定域不允许任意扩展输出长度。
    /// 仅在通用域 `Other` 下可配置多输出，满足扩展摘要需求。
    pub fn output_len(&mut self, output_len: usize) {
        if self.domain == Domain::Other && output_len > 0 {
            self.output_len = output_len;
        }
    }

    /// 追加一段输入数据。
    /// 输入按“段”保留，可表达多次 absorb 的业务语义边界。
    /// 该接口只记录引用，不做拷贝，适合在 no_std 环境下降低内存开销。
    pub fn update(&mut self, input: &'a [BlsScalar]) {
        self.input.push(input);
    }

    /// 执行 sponge 并返回完整域元素输出。
    /// 该流程包括：构建 IO 模式、按段 absorb、按约定次数 squeeze、最终 finish。
    /// 若前置模式构建通过，则后续步骤按相同约束执行，不应再触发模式错误。
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
    /// 截断通过固定掩码完成，再转入 JubJub 标量域，常用于签名电路输入。
    /// 该变换保持确定性，但会丢弃高位信息，不应视作双向可逆映射。
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
    /// 该函数封装了 `new + update + finalize` 的常见调用链。
    /// 适用于单段输入且不需要复用上下文状态的快速哈希场景。
    pub fn digest(domain: Domain, input: &'a [BlsScalar]) -> Vec<BlsScalar> {
        let mut poseidon_hash = Self::new(domain);
        poseidon_hash.update(input);
        poseidon_hash.finalize()
    }

    /// 便捷接口：一次性计算截断后的 `digest`。
    /// 该函数封装 `new + update + finalize_truncated`，用于标量域兼容输出。
    /// 典型用途是把 Poseidon 输出直接对接 JubJub 相关协议模块。
    pub fn digest_truncated(
        domain: Domain,
        input: &'a [BlsScalar],
    ) -> Vec<JubJubScalar> {
        let mut poseidon_hash = Self::new(domain);
        poseidon_hash.update(input);
        poseidon_hash.finalize_truncated()
    }
}
