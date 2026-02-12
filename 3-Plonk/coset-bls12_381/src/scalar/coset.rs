//! 标量类型 `Scalar` 的扩展 trait 与序列化适配实现。
//! 本文件补充排序、哈希、位运算及字节编解码接口。
//! 这些能力主要服务工程层集成，不改变标量域代数语义。

use core::cmp::{Ord, Ordering, PartialOrd};
use core::convert::TryFrom;
use core::hash::{Hash, Hasher};
use core::ops::{BitAnd, BitXor};
use coset_bytes::{Error as BytesError, Serializable};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use super::Scalar;
#[cfg(test)]
use super::R2;

impl PartialOrd for Scalar {
    /// 提供 `Scalar` 的偏序比较接口，实现上直接复用全序 `cmp`。
    /// 对有限域标量而言，底层按整数表示比较可得到稳定、确定的顺序。
    /// 该实现主要服务于容器排序与测试断言，不参与代数语义本身。
    fn partial_cmp(&self, other: &Scalar) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Scalar {
    /// 定义 `Scalar` 的全序比较规则，按 256 位表示的高位到低位逐段比较。
    /// 这里比较的是内部 limb 的字典序，可用于排序、去重和映射键结构。
    /// 该顺序不改变域运算性质，仅提供工程层面的可比较能力。
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..4).rev() {
            #[allow(clippy::comparison_chain)]
            if self.0[i] > other.0[i] {
                return Ordering::Greater;
            } else if self.0[i] < other.0[i] {
                return Ordering::Less;
            }
        }
        Ordering::Equal
    }
}

impl Serializable<32> for Scalar {
    type Error = BytesError;

    /// 将标量编码为固定 32 字节的小端表示。
    /// 固定长度编码便于跨语言协议对接，也降低了解析复杂度。
    /// 该方法与 `Scalar::to_bytes` 保持一致，确保序列化结果可逆。
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.to_bytes()
    }

    /// 从固定 32 字节表示恢复标量，并执行合法性检查。
    /// 若输入不在标量域范围内，则返回 `InvalidData` 错误。
    /// 这种边界检查可防止无效编码进入后续密码学计算路径。
    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        Self::from_bytes(buf)
            .into_option()
            .ok_or(BytesError::InvalidData)
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    extern crate alloc;

    use alloc::string::{String, ToString};

    use serde::de::Error as SerdeError;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for Scalar {
        /// 将 `Scalar` 序列化为十六进制字符串，便于 JSON 传输与人工阅读。
        /// 十六进制形式对二进制数据友好，且在调试日志中更容易定位问题。
        /// 该实现遵循固定长度字节编码，避免文本层面的歧义。
        fn serialize<S: Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let s = hex::encode(self.to_bytes());
            s.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Scalar {
        /// 从十六进制字符串反序列化 `Scalar` 并验证字段合法性。
        /// 流程包括：hex 解码、长度校验、域元素有效性校验。
        /// 任何一步失败都会返回 serde 错误，防止脏数据向下游传播。
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            let s = String::deserialize(deserializer)?;
            let decoded = hex::decode(&s).map_err(SerdeError::custom)?;
            let decoded_len = decoded.len();
            let bytes: [u8; Scalar::SIZE] =
                decoded.try_into().map_err(|_| {
                    SerdeError::invalid_length(
                        decoded_len,
                        &Scalar::SIZE.to_string().as_str(),
                    )
                })?;
            let scalar = Scalar::from_bytes(&bytes).into_option().ok_or(
                SerdeError::custom(
                    "Failed to deserialize Scalar: invalid Scalar",
                ),
            )?;
            Ok(scalar)
        }
    }

    #[cfg(test)]
    mod tests {
        use alloc::boxed::Box;

        use ff::Field;
        use rand::rngs::StdRng;
        use rand_core::SeedableRng;

        use super::*;
        use crate::coset::test_utils;

        #[test]
        /// 验证 `Scalar` 的 serde 往返一致性（serialize -> deserialize）。
        /// 该测试同时检查 canonical JSON 表达，保证输出格式稳定。
        /// 在协议升级时，它可作为兼容性回归的第一道防线。
        fn serde_scalar() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = StdRng::seed_from_u64(0xc0b);
            let scalar = Scalar::random(&mut rng);
            let ser = test_utils::assert_canonical_json(
                &scalar,
                "\"fe9a9c1876745ca351435dec31217662ff1fcf67287de6fd9b6c7de1d0846b21\"",
            )?;
            let deser = serde_json::from_str(&ser).unwrap();

            assert_eq!(scalar, deser);
            Ok(())
        }

        #[test]
        /// 验证过短编码输入会被正确拒绝。
        /// 该测试覆盖长度约束分支，确保反序列化不会接收截断数据。
        /// 对密码学数据而言，长度异常通常意味着协议错误或数据损坏。
        fn serde_scalar_too_short_encoded() {
            let length_31_enc =
                "\"fe9a9c1876745ca351435dec31217662ff1fcf67287de6fd9b6c7de1d0846b\"";

            let scalar: Result<Scalar, _> =
                serde_json::from_str(&length_31_enc);
            assert!(scalar.is_err());
        }

        #[test]
        /// 验证过长编码输入会被正确拒绝。
        /// 测试目的在于防止冗余字节绕过编码规范并造成歧义。
        /// 严格长度检查有助于减少不同实现间的互操作风险。
        fn serde_scalar_too_long_encoded() {
            let length_33_enc =
                "\"fe9a9c1876745ca351435dec31217662ff1fcf67287de6fd9b6c7de1d0846b2100\"";

            let scalar: Result<Scalar, _> =
                serde_json::from_str(&length_33_enc);
            assert!(scalar.is_err());
        }
    }
}

#[allow(dead_code)]
pub const GEN_X: Scalar = Scalar([
    0x1539098E9CBCC1D5,
    0x0CCC77B0E1804E8D,
    0x6EEF947A6FD0FB2C,
    0xA3D063F54E10DDE9,
]);

#[allow(dead_code)]
pub const GEN_Y: Scalar = Scalar([
    0x6540D21E7007DC60,
    0x3B0D848E832A862F,
    0xB53BB87E05DA8257,
    0xCD482CC3FD6FF4D,
]);

impl<'a, 'b> BitXor<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    /// 对两个标量执行按位异或，操作前先做 Montgomery 归一化。
    /// 归一化可确保比特运算作用于规范表示，避免内部表示差异带来偏差。
    /// 该操作多用于工具逻辑与测试，不对应有限域上的标准代数运算。
    fn bitxor(self, rhs: &'b Scalar) -> Scalar {
        let a_red = self.reduce();
        let b_red = rhs.reduce();
        Scalar::from_raw([
            a_red.0[0] ^ b_red.0[0],
            a_red.0[1] ^ b_red.0[1],
            a_red.0[2] ^ b_red.0[2],
            a_red.0[3] ^ b_red.0[3],
        ])
    }
}

impl BitXor<Scalar> for Scalar {
    type Output = Scalar;

    /// 值语义版本的按位异或，实现委托到引用版本以复用逻辑。
    /// 这种写法可减少重复代码，并保持不同行为入口的一致性。
    /// 对调用方而言，支持 move 与 borrow 两种使用习惯。
    fn bitxor(self, rhs: Scalar) -> Scalar {
        &self ^ &rhs
    }
}

impl BitAnd<Scalar> for Scalar {
    type Output = Scalar;

    /// 值语义版本的按位与，实现委托到引用版本。
    /// 通过委托可统一规范化与位运算细节，避免双份实现漂移。
    /// 在泛型上下文中，这个实现提升了表达式书写的自然性。
    fn bitand(self, rhs: Scalar) -> Scalar {
        &self & &rhs
    }
}

impl<'a, 'b> BitAnd<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    /// 对两个标量执行按位与，先归一化到标准表示。
    /// 与异或实现同理，归一化确保位操作结果具备确定性。
    /// 此函数属于工程辅助能力，而非有限域标准算术运算。
    fn bitand(self, rhs: &'b Scalar) -> Scalar {
        let a_red = self.reduce();
        let b_red = rhs.reduce();
        Scalar::from_raw([
            a_red.0[0] & b_red.0[0],
            a_red.0[1] & b_red.0[1],
            a_red.0[2] & b_red.0[2],
            a_red.0[3] & b_red.0[3],
        ])
    }
}

impl Hash for Scalar {
    #[inline]
    /// 将 `Scalar` 的内部 limb 表示喂入哈希状态。
    /// 该实现使 `Scalar` 可作为哈希映射键使用。
    /// 统一哈希语义依赖内部表示稳定性，因此应避免随意变更 limb 布局。
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Scalar {
    /// 判断标量是否为加法单位元 0（常量时间比较）。
    /// 使用常量时间比较可避免通过时序泄露敏感中间状态。
    /// 在条件分支前可先用该接口进行安全判零。
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Scalar::zero())
    }

    /// 判断标量是否为乘法单位元 1（常量时间比较）。
    /// 与 `is_zero` 类似，该接口用于常见短路路径判断。
    /// 常量时间语义对密码学实现中的分支安全尤为重要。
    pub fn is_one(&self) -> Choice {
        self.ct_eq(&Scalar::one())
    }

    /// 暴露内部 limb 表示的只读引用。
    /// 该接口主要用于调试、序列化桥接和低层优化代码。
    /// 调用方应将其视为内部表示，不应直接依赖其长期稳定 ABI。
    pub const fn internal_repr(&self) -> &[u64; 4] {
        &self.0
    }

    /// 将标量展开为 256 位 bit 数组（按字节内低位到高位顺序）。
    /// 位展开常用于窗口算法、约束系统输入和可视化调试。
    /// 返回固定长度数组有利于避免堆分配和长度不一致问题。
    pub fn to_bits(&self) -> [u8; 256] {
        let mut res = [0u8; 256];
        let bytes = self.to_bytes();
        for (byte, bits) in bytes.iter().zip(res.chunks_mut(8)) {
            bits.iter_mut()
                .enumerate()
                .for_each(|(i, bit)| *bit = (byte >> i) & 1)
        }
        res
    }

    /// 以大端序导出 32 字节规范表示。
    /// 导出前先执行 `reduce`，确保处于域内标准表示区间。
    /// 该编码通常用于跨系统协议与哈希前标准化输入。
    pub fn to_be_bytes(&self) -> [u8; Self::SIZE] {
        let tmp = self.reduce();

        let mut res = [0; Self::SIZE];
        res[0..8].copy_from_slice(&tmp.0[3].to_be_bytes());
        res[8..16].copy_from_slice(&tmp.0[2].to_be_bytes());
        res[16..24].copy_from_slice(&tmp.0[1].to_be_bytes());
        res[24..32].copy_from_slice(&tmp.0[0].to_be_bytes());

        res
    }

    /// 将当前值从 Montgomery 域表示归约到规范标量表示。
    /// 归约过程调用底层 `montgomery_reduce` 完成模约束收敛。
    /// 在需要稳定字节表达或位操作前，建议先执行该步骤。
    pub fn reduce(&self) -> Scalar {
        Scalar::montgomery_reduce(
            self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0,
        )
    }

    /// 计算 `2^by` 对应的标量值。
    /// 实现采用平方-乘框架，并用常量时间条件赋值更新结果。
    /// 该函数常用于测试、位运算验证及窗口参数构造场景。
    pub fn pow_of_2(by: u64) -> Self {
        let two = Scalar::from(2u64);
        let mut res = Self::one();
        for i in (0..64).rev() {
            res = res.square();
            let mut tmp = res;
            tmp *= two;
            res.conditional_assign(&tmp, (((by >> i) & 0x1) as u8).into());
        }
        res
    }

    /// 使用 Blake2b 将任意输入哈希映射到标量域。
    /// 先得到 64 字节摘要，再通过 512 位约简映射到域元素。
    /// 该流程满足“哈希到域”的常见工程需求，可用于 Fiat-Shamir 等场景。
    pub fn hash_to_scalar(input: &[u8]) -> Scalar {
        let state = blake2b_simd::Params::new()
            .hash_length(64)
            .to_state()
            .update(input)
            .finalize();

        let bytes = state.as_bytes();

        Scalar::reduce_u512_words([
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[48..56]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[56..64]).unwrap()),
        ])
    }

    #[inline]
    /// 将标量按位右移 `n` 位（in-place）。
    /// 该函数用于窗口算法中的标量分片，先按 64 位块移动再处理余位。
    /// 若位移超过总宽度则直接归零，行为与固定宽整数语义一致。
    pub fn divn(&mut self, mut n: u32) {
        if n >= 256 {
            *self = Self::from(0);
            return;
        }

        while n >= 64 {
            let mut t = 0;
            for i in self.0.iter_mut().rev() {
                core::mem::swap(&mut t, i);
            }
            n -= 64;
        }

        if n > 0 {
            let mut t = 0;
            for i in self.0.iter_mut().rev() {
                let t2 = *i << (64 - n);
                *i >>= n;
                *i |= t;
                t = t2;
            }
        }
    }
}

#[test]
/// 验证 `Scalar` 的顺序关系实现是否符合预期。
/// 测试选择 `1` 与 `-1` 比较，覆盖跨模数边界的排序行为。
/// 该用例可快速发现 `cmp` 的高位/低位比较方向错误。
fn test_partial_ord() {
    let one = Scalar::one();
    assert!(one < -one);
}

#[test]
/// 验证按位异或接口的基本正确性。
/// 该测试覆盖引用版本 XOR 的核心路径。
/// 对工具型比特操作而言，简单算例可提供稳定回归信号。
fn test_xor() {
    let a = Scalar::from(500u64);
    let b = Scalar::from(499u64);
    let res = Scalar::from(7u64);
    assert_eq!(&a ^ &b, res);
}

#[test]
/// 验证按位与接口的基本正确性。
/// 测试同时覆盖单位元情形与互补情形（`a & -a`）。
/// 该断言有助于保证位运算与规范化步骤协同正确。
fn test_and() {
    let a = Scalar::one();
    let b = Scalar::one();
    let res = Scalar::one();
    assert_eq!(&a & &b, res);
    assert_eq!(a & -a, Scalar::zero());
}

#[test]
/// 验证 `Iterator::sum` 在标量上的实现语义。
/// 测试通过简单样例对照显式加法结果。
/// 该回归可防止 trait 实现变更导致聚合行为偏差。
fn test_iter_sum() {
    let scalars = vec![Scalar::one(), Scalar::one()];
    let res: Scalar = scalars.iter().sum();
    assert_eq!(res, Scalar::one() + Scalar::one());
}

#[test]
/// 验证 `Iterator::product` 在标量上的实现语义。
/// 使用小样例校验乘法聚合结果与手算一致。
/// 该测试确保通用迭代器接口在代数结构上可正确复用。
fn test_iter_prod() {
    let scalars =
        vec![Scalar::one() + Scalar::one(), Scalar::one() + Scalar::one()];
    let res: Scalar = scalars.iter().product();
    assert_eq!(res, Scalar::from(4u64));
}

#[test]
/// 验证 `to_bits` 的位展开规则是否与预期一致。
/// 用 `2^128` 与 `2^128-rand` 两个样例覆盖典型和借位情形。
/// 该测试对窗口算法的正确性很关键，因为其依赖准确位布局。
fn bit_repr() {
    let two_pow_128 = Scalar::from(2u64).pow(&[128, 0, 0, 0]);
    let two_pow_128_bits = [
        0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(&two_pow_128.to_bits()[..], &two_pow_128_bits[..]);

    let two_pow_128_minus_rand =
        Scalar::from(2u64).pow(&[128, 0, 0, 0]) - Scalar::from(7568589u64);
    let two_pow_128_bits = [
        1u8, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1,
    ];
    assert_eq!(
        &two_pow_128_minus_rand.to_bits()[..128],
        &two_pow_128_bits[..]
    )
}

#[test]
/// 验证 `pow_of_2` 与通用幂运算结果一致。
/// 在较大范围内逐点比较可提高对实现细节错误的检出率。
/// 该测试是指数构造函数的系统性回归保障。
fn pow_of_two_test() {
    let two = Scalar::from(2u64);
    for i in 0..1000 {
        assert_eq!(Scalar::pow_of_2(i as u64), two.pow(&[i as u64, 0, 0, 0]));
    }
}

#[test]
/// 验证 `Scalar` 的相等性与哈希行为一致。
/// 若两个值相等，则其字节哈希应相等；反之应尽量不同。
/// 该测试用于保障映射键语义和去重逻辑的基础正确性。
fn test_scalar_eq_and_hash() {
    use sha3::{Digest, Keccak256};

    let r0 = Scalar::from_raw([
        0x1fff_3231_233f_fffd,
        0x4884_b7fa_0003_4802,
        0x998c_4fef_ecbc_4ff3,
        0x1824_b159_acc5_0562,
    ]);
    let r1 = Scalar::from_raw([
        0x1fff_3231_233f_fffd,
        0x4884_b7fa_0003_4802,
        0x998c_4fef_ecbc_4ff3,
        0x1824_b159_acc5_0562,
    ]);
    let r2 = Scalar::from(7);

    assert!(r0 == r1);
    assert!(r0 != r2);

    let hash_r0 = Keccak256::digest(&r0.to_bytes());
    let hash_r1 = Keccak256::digest(&r1.to_bytes());
    let hash_r2 = Keccak256::digest(&r2.to_bytes());

    assert_eq!(hash_r0, hash_r1);
    assert_ne!(hash_r0, hash_r2);
}

#[test]
/// 验证大端编码输出符合预定义样例。
/// 覆盖 0、1、常量 `R2` 与 `-1` 等关键边界值。
/// 该测试可确保跨系统字节序约定不会在重构中被破坏。
fn test_to_be_bytes() {
    assert_eq!(
        Scalar::zero().to_be_bytes(),
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    );

    assert_eq!(
        Scalar::one().to_be_bytes(),
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]
    );

    assert_eq!(
        R2.to_be_bytes(),
        [
            24, 36, 177, 89, 172, 197, 5, 111, 153, 140, 79, 239, 236, 188, 79,
            245, 88, 132, 183, 250, 0, 3, 72, 2, 0, 0, 0, 1, 255, 255, 255,
            254
        ]
    );

    assert_eq!(
        (-&Scalar::one()).to_be_bytes(),
        [
            115, 237, 167, 83, 41, 157, 125, 72, 51, 57, 216, 8, 9, 161, 216,
            5, 83, 189, 164, 2, 255, 254, 91, 254, 255, 255, 255, 255, 0, 0, 0,
            0
        ]
    );
}

#[cfg(all(test, feature = "alloc"))]
mod fuzz {
    use alloc::vec::Vec;

    use crate::scalar::{Scalar, MODULUS};
    use crate::util::sbb;

    /// 检查输入标量是否落在模数范围内。
    /// 通过减法借位判断可高效判断 `scalar < MODULUS`。
    /// 该辅助函数为随机测试提供统一的合法性谓词。
    fn is_scalar_in_range(scalar: &Scalar) -> bool {
        let borrow = scalar
            .0
            .iter()
            .zip(MODULUS.0.iter())
            .fold(0, |borrow, (&s, &m)| sbb(s, m, borrow).1);

        borrow == u64::MAX
    }

    quickcheck::quickcheck! {
        fn prop_scalar_from_raw_bytes(bytes: Vec<u8>) -> bool {
            let scalar = Scalar::hash_to_scalar(&bytes);

            is_scalar_in_range(&scalar)
        }
    }
}
