// 模块说明：本文件实现 PLONK 组件（src/transcript.rs）。

//

use core::mem;

use coset_bls12_381::BlsScalar;
use coset_bytes::Serializable;
use merlin::Transcript;

use crate::commitment_scheme::Commitment;
use crate::proof_system::VerifierKey;

pub(crate) trait TranscriptProtocol {
    fn append_commitment(&mut self, label: &'static [u8], comm: &Commitment);

    fn append_scalar(&mut self, label: &'static [u8], s: &BlsScalar);

    fn challenge_scalar(&mut self, label: &'static [u8]) -> BlsScalar;

    fn circuit_domain_sep(&mut self, n: u64);

    fn base(
        label: &[u8],
        verifier_key: &VerifierKey,
        constraints: usize,
    ) -> Self;
}

impl TranscriptProtocol for Transcript {
    fn append_commitment(&mut self, label: &'static [u8], comm: &Commitment) {
        self.append_message(label, &comm.0.to_bytes());
    }

    fn append_scalar(&mut self, label: &'static [u8], s: &BlsScalar) {
        self.append_message(label, &s.to_bytes())
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> BlsScalar {
        let mut challenge_buffer = [0u8; 64];
        self.challenge_bytes(label, &mut challenge_buffer);

        BlsScalar::from_bytes_wide(&challenge_buffer)
    }

    fn circuit_domain_sep(&mut self, n: u64) {
        self.append_message(b"dom-sep", b"circuit_size");
        self.append_u64(b"n", n);
    }

    fn base(
        label: &[u8],
        verifier_key: &VerifierKey,
        constraints: usize,
    ) -> Self {
        let label = unsafe { mem::transmute(label) };

        let mut transcript = Transcript::new(label);

        transcript.circuit_domain_sep(constraints as u64);

        verifier_key.seed_transcript(&mut transcript);

        transcript
    }
}
