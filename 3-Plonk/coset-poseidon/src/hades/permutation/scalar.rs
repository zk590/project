use coset_bls12_381::BlsScalar;
use coset_safe::Safe;

use super::Hades;
use crate::hades::{MDS_MATRIX, ROUND_CONSTANTS, WIDTH};

#[derive(Default)]
pub(crate) struct ScalarPermutation();

impl ScalarPermutation {
    /// 创建标量域下的 Hades 置换实例。
    /// 该类型不持有运行时状态，构造开销极低，可按需临时创建。
    /// 在哈希与加密流程中，它作为 `Safe` 后端提供具体域运算实现。
    pub fn new() -> Self {
        Self()
    }
}

impl Safe<BlsScalar, WIDTH> for ScalarPermutation {
    /// 对给定状态执行完整 Hades 置换。
    /// 内部流程严格遵循“全轮-部分轮-全轮”的轮次布局。
    /// 调用后 `state` 原位更新，不会分配额外输出缓冲区。
    fn permute(&mut self, state: &mut [BlsScalar; WIDTH]) {
        self.apply_permutation(state);
    }

    /// 将原始字节标签映射为标量域元素。
    /// 该映射用于 sponge 域分离初始化，确保协议上下文可区分。
    /// 输出值由哈希到标量算法确定，具备确定性与跨平台一致性。
    fn tag(&mut self, input: &[u8]) -> BlsScalar {
        BlsScalar::hash_to_scalar(input.as_ref())
    }

    /// 执行标量加法，作为 sponge 组合算子的“加”运算实现。
    /// 该操作在域内闭合，满足后续轮函数的代数要求。
    /// 保持独立接口可让 `Safe` 在不同后端复用统一流程。
    fn add(&mut self, right: &BlsScalar, left: &BlsScalar) -> BlsScalar {
        right + left
    }
}

impl Hades<BlsScalar> for ScalarPermutation {
    /// 为当前轮的每个状态位叠加对应轮常量。
    /// 常量取自预计算表 `ROUND_CONSTANTS[round][index]`。
    /// 该步骤引入轮依赖偏移，防止轮函数退化为可逆线性结构。
    fn add_round_constants(
        &mut self,
        round_index: usize,
        state: &mut [BlsScalar; WIDTH],
    ) {
        state
            .iter_mut()
            .enumerate()
            .for_each(|(state_index, state_value)| {
                *state_value += ROUND_CONSTANTS[round_index][state_index]
            });
    }

    /// 对单个状态元素执行五次幂 S-Box 变换。
    /// 具体实现采用平方链 `x^5 = x^4 * x`，减少乘法次数。
    /// 该非线性步骤是提升抗分析能力的关键组件。
    fn quintic_s_box(&mut self, value: &mut BlsScalar) {
        *value = value.square().square() * *value;
    }

    /// 使用 MDS 矩阵对整条状态向量做线性混合。
    /// 每个输出行与全部输入列相乘累加，保证高扩散性。
    /// 计算在临时数组中完成，最后整体回写，避免覆盖输入造成污染。
    fn apply_mds_matrix(
        &mut self,
        _round_index: usize,
        state: &mut [BlsScalar; WIDTH],
    ) {
        let mut mixed_state = [BlsScalar::zero(); WIDTH];

        for (column_index, state_value) in state.iter().enumerate() {
            for row_index in 0..WIDTH {
                mixed_state[row_index] +=
                    MDS_MATRIX[row_index][column_index] * state_value;
            }
        }

        state.copy_from_slice(&mixed_state);
    }
}

#[cfg(feature = "encryption")]
impl coset_safe::Encryption<BlsScalar, WIDTH> for ScalarPermutation {
    /// 在字段上执行减法，用于解密恢复明文分量。
    /// 运算遵循域模数规则，不会产生越界未定义行为。
    /// 与 `add` 共同构成加解密中可逆的代数操作对。
    fn subtract(
        &mut self,
        minuend: &BlsScalar,
        subtrahend: &BlsScalar,
    ) -> BlsScalar {
        minuend - subtrahend
    }

    /// 判断两个标量是否相等。
    /// 该接口用于加解密流程中的一致性检查与条件分支。
    /// 返回布尔值语义直接，便于上层协议处理失败路径。
    fn is_equal(&mut self, lhs: &BlsScalar, rhs: &BlsScalar) -> bool {
        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hades_det() {
        let mut first_state = [BlsScalar::from(17u64); WIDTH];
        let mut second_state = [BlsScalar::from(17u64); WIDTH];
        let mut different_state = [BlsScalar::from(19u64); WIDTH];

        ScalarPermutation::new().permute(&mut first_state);
        ScalarPermutation::new().permute(&mut second_state);
        ScalarPermutation::new().permute(&mut different_state);

        assert_eq!(first_state, second_state);
        assert_ne!(first_state, different_state);
    }
}
