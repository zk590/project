use core::mem;

use coset_bls12_381::BlsScalar;
use coset_bytes::Serializable;
use merlin::Transcript;

use crate::commitment_scheme::Commitment;
use crate::proof_system::VerifierKey;

pub(crate) trait TranscriptProtocol {
    /// 向 transcript 追加承诺点消息。
    /// 该步骤将群元素编码后绑定到指定标签，参与后续挑战派生。
    /// 证明者与验证者必须保持完全一致的追加顺序与标签。
    fn append_commitment(
        &mut self,
        label: &'static [u8],
        commitment: &Commitment,
    );

    /// 向 transcript 追加标量消息。
    /// 该接口用于把中间评估值等标量状态纳入 Fiat-Shamir 上下文。
    /// 追加后会影响后续挑战值，因此调用时机必须协议固定。
    fn append_scalar(&mut self, label: &'static [u8], scalar: &BlsScalar);

    /// 从 transcript 派生一个挑战标量。
    /// 内部先提取 64 字节挑战熵，再映射到标量域元素。
    /// 该挑战值应视为只读随机预言机输出，不应重复手工改写。
    fn challenge_scalar(&mut self, label: &'static [u8]) -> BlsScalar;

    /// 追加电路域分离信息。
    /// 该步骤用于绑定电路规模，防止跨电路上下文重放挑战。
    /// 一般在 transcript 初始化阶段尽早调用。
    fn circuit_domain_sep(&mut self, circuit_size: u64);

    /// 构造协议基础 transcript。
    /// 该函数会完成标签初始化、电路域分离以及验证键承诺注入。
    /// 返回值是可直接用于证明/验证流程的统一 transcript 起点。
    fn base(
        label: &[u8],
        verifier_key: &VerifierKey,
        constraints: usize,
    ) -> Self;
}

impl TranscriptProtocol for Transcript {
    /// 将承诺序列化后追加到 transcript。
    /// 使用静态标签可避免调用方传入临时生命周期标签导致 API 复杂化。
    /// 底层调用 Merlin 的 `append_message` 完成状态吸收。
    fn append_commitment(
        &mut self,
        label: &'static [u8],
        commitment: &Commitment,
    ) {
        self.append_message(label, &commitment.0.to_bytes());
    }

    /// 将标量按固定字节表示写入 transcript。
    /// 该表示与曲线标量序列化规则一致，确保跨端一致性。
    /// 写入后 transcript 状态发生变化，会影响后续挑战输出。
    fn append_scalar(&mut self, label: &'static [u8], scalar: &BlsScalar) {
        self.append_message(label, &scalar.to_bytes())
    }

    /// 从 transcript 派生挑战并映射为标量。
    /// 使用宽字节映射可降低偏差风险，提升挑战分布质量。
    /// 每次调用都会消费 transcript 当前状态，输出与调用顺序强相关。
    fn challenge_scalar(&mut self, label: &'static [u8]) -> BlsScalar {
        let mut challenge_buffer = [0u8; 64];
        self.challenge_bytes(label, &mut challenge_buffer);

        BlsScalar::from_bytes_wide(&challenge_buffer)
    }

    /// 注入电路规模域分离消息。
    /// 该消息把电路维度固定到 transcript，防止不同规模电路混用挑战。
    /// 标签和值均为协议常量，调用双方需严格一致。
    fn circuit_domain_sep(&mut self, circuit_size: u64) {
        self.append_message(b"dom-sep", b"circuit_size");
        self.append_u64(b"n", circuit_size);
    }

    /// 初始化基础 transcript 并注入验证键上下文。
    /// 该实现对标签做生命周期转换以匹配 Merlin 构造器签名。
    /// 初始化后 transcript 已绑定电路规模与验证键，可直接开始挑战流程。
    fn base(
        label: &[u8],
        verifier_key: &VerifierKey,
        constraints: usize,
    ) -> Self {
        let static_label = unsafe { mem::transmute(label) };

        let mut transcript = Transcript::new(static_label);

        transcript.circuit_domain_sep(constraints as u64);

        verifier_key.seed_transcript(&mut transcript);

        transcript
    }
}
