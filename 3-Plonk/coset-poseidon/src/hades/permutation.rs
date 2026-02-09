//

use crate::hades::{FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH};

#[cfg(feature = "zk")]
pub(crate) mod gadget;

pub(crate) mod scalar;

/// Hades 置换抽象：定义轮常量、S-Box 与 MDS 混合步骤。
pub(crate) trait Hades<T> {
    const ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

    /// 为当前轮的 state 向量叠加轮常量。
    fn add_round_constants(
        &mut self,
        round_index: usize,
        state: &mut [T; WIDTH],
    );

    /// 对单个状态元素应用五次 S-Box。
    fn quintic_s_box(&mut self, value: &mut T);

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

        state.iter_mut().for_each(|w| self.quintic_s_box(w));

        self.apply_mds_matrix(round_index, state);
    }

    /// 执行完整 Hades 置换流程（前半全轮 + 部分轮 + 后半全轮）。
    fn apply_permutation(&mut self, state: &mut [T; WIDTH]) {
        for full_round_index in 0..FULL_ROUNDS / 2 {
            self.run_full_round(full_round_index, state);
        }

        for partial_round_index in 0..PARTIAL_ROUNDS {
            self.run_partial_round(
                partial_round_index + FULL_ROUNDS / 2,
                state,
            );
        }

        for full_round_index in 0..FULL_ROUNDS / 2 {
            self.run_full_round(
                full_round_index + FULL_ROUNDS / 2 + PARTIAL_ROUNDS,
                state,
            );
        }
    }
}
