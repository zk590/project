use crate::hades::{FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH};

#[cfg(feature = "zk")]
pub(crate) mod gadget;

pub(crate) mod scalar;

/// Hades 置换抽象：定义轮常量、S-Box 与 MDS 混合步骤。
/// 该 trait 将“置换骨架”与“具体域运算”解耦，便于标量态和电路态复用。
/// 具体实现只需提供原子操作，通用轮调度逻辑由默认方法统一维护。
/// 这种设计能降低参数漂移风险，保证不同实现的轮结构一致。
pub(crate) trait Hades<T> {
    const ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

    /// 为当前轮的 state 向量叠加轮常量。
    /// 常量由轮索引与状态索引共同决定，是 Hades 安全参数的重要组成。
    /// 实现需保证索引映射稳定，否则会破坏置换可复现性。
    fn add_round_constants(
        &mut self,
        round_index: usize,
        state: &mut [T; WIDTH],
    );

    /// 对单个状态元素应用五次 S-Box。
    /// quintic 形式在保持代数结构可用性的同时，提供必要的非线性扩散。
    /// 该步骤通常是抵抗线性分析与差分分析的核心来源之一。
    fn quintic_s_box(&mut self, value: &mut T);

    /// 对整条 state 施加 MDS 线性混合。
    /// MDS 矩阵保证单点扰动在若干轮后快速扩散到全部状态位。
    /// `round_index` 参数保留扩展空间，支持未来轮依赖矩阵策略。
    fn apply_mds_matrix(&mut self, round_index: usize, state: &mut [T; WIDTH]);

    /// 执行一轮部分轮：常量注入 + 单元素 S-Box + 矩阵混合。
    fn run_partial_round(
        &mut self,
        round_index: usize,
        state: &mut [T; WIDTH],
    ) {
        self.add_round_constants(round_index, state);

        self.quintic_s_box(&mut state[WIDTH - 1]);

        self.apply_mds_matrix(round_index, state);
    }

    /// 执行一轮全轮：常量注入 + 全元素 S-Box + 矩阵混合。
    fn run_full_round(&mut self, round_index: usize, state: &mut [T; WIDTH]) {
        self.add_round_constants(round_index, state);

        state
            .iter_mut()
            .for_each(|state_value| self.quintic_s_box(state_value));

        self.apply_mds_matrix(round_index, state);
    }

    /// 执行完整 Hades 置换流程（前半全轮 + 部分轮 + 后半全轮）。
    fn apply_permutation(&mut self, state: &mut [T; WIDTH]) {
        let half_full_rounds = FULL_ROUNDS / 2;
        let partial_round_start = half_full_rounds;
        let final_full_round_start = Self::ROUNDS - half_full_rounds;

        for full_round_index in 0..half_full_rounds {
            self.run_full_round(full_round_index, state);
        }

        for partial_round_index in 0..PARTIAL_ROUNDS {
            self.run_partial_round(
                partial_round_index + partial_round_start,
                state,
            );
        }

        for full_round_index in 0..half_full_rounds {
            self.run_full_round(
                full_round_index + final_full_round_start,
                state,
            );
        }
    }
}
