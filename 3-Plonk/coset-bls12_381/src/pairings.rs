#[cfg(all(feature = "alloc", feature = "pairing"))]
mod coset;

#[cfg(all(feature = "alloc", feature = "pairing"))]
use crate::choice;
use crate::fp::Fp;
use crate::fp12::Fp12;
use crate::fp2::Fp2;
use crate::fp6::Fp6;
use crate::{
    BlsScalar, G1Affine, G1Projective, G2Affine, G2Projective, BLS_X,
    BLS_X_IS_NEGATIVE,
};

use core::borrow::Borrow;
use core::fmt;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use group::Group;
use pairing::{Engine, PairingCurveAffine};
use rand_core::RngCore;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use pairing::MultiMillerLoop;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize,
};

#[cfg_attr(docsrs, doc(cfg(feature = "pairings")))]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, RkyvSerialize, RkyvDeserialize),
    archive_attr(derive(CheckBytes))
)]
pub struct MillerLoopResult(pub(crate) Fp12);

impl Default for MillerLoopResult {
    /// 返回 Miller 循环结果类型的单位元默认值。
    /// 配对计算中，Miller 累乘的单位元是 Fp12 乘法单位 `1`。
    /// 该默认值使聚合与迭代折叠流程可从统一初值启动。
    fn default() -> Self {
        MillerLoopResult(Fp12::one())
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for MillerLoopResult {}

impl ConditionallySelectable for MillerLoopResult {
    /// 在常量时间语义下选择两个 Miller 循环结果之一。
    /// 该实现避免通过普通分支泄露条件位，符合密码学常量时间要求。
    /// 在批处理验证与分支规约中可安全复用该选择原语。
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        MillerLoopResult(Fp12::conditional_select(&a.0, &b.0, choice))
    }
}

impl MillerLoopResult {
    /// 对 Miller 循环结果做最终指数化，映射到 GT 群。
    /// 该过程包含 easy/hard part 分解，是配对计算的收敛步骤。
    /// 输出位于目标群子结构中，可直接用于协议比较与聚合。
    pub fn final_exponentiation(&self) -> Gt {
        #[must_use]
        /// 在 Fp4 子结构上执行专用平方，减少通用乘法数量。
        /// 该步骤把 `(a + bu)^2` 展开为结构化表达，复用中间项降低成本。
        /// 它是 cyclotomic 平方过程中的基础子例程。
        fn fp4_square(a: Fp2, b: Fp2) -> (Fp2, Fp2) {
            // 将 `(a + bu)^2` 在 Fp4 子结构上展开，减少通用乘法次数。
            let t0 = a.square();
            let t1 = b.square();
            let mut t2 = t1.mul_by_nonresidue();
            let c0 = t2 + t0;
            t2 = a + b;
            t2 = t2.square();
            t2 -= t0;
            let c1 = t2 - t1;

            (c0, c1)
        }

        #[must_use]
        /// 在 cyclotomic 子群中执行专用平方。
        /// 与通用 Fp12 平方相比，该公式利用子群结构显著降低运算量。
        /// 最终指数化 hard part 会多次调用该优化路径。
        fn cyclotomic_square(f: Fp12) -> Fp12 {
            // 在 cyclotomic 子群内使用专用平方公式，比通用 Fp12
            // 平方更省约束/乘法。
            let mut z0 = f.c0.c0;
            let mut z4 = f.c0.c1;
            let mut z3 = f.c0.c2;
            let mut z2 = f.c1.c0;
            let mut z1 = f.c1.c1;
            let mut z5 = f.c1.c2;

            let (t0, t1) = fp4_square(z0, z1);

            z0 = t0 - z0;
            z0 = z0 + z0 + t0;

            z1 = t1 + z1;
            z1 = z1 + z1 + t1;

            let (mut t0, t1) = fp4_square(z2, z3);
            let (t2, t3) = fp4_square(z4, z5);

            z4 = t0 - z4;
            z4 = z4 + z4 + t0;

            z5 = t1 + z5;
            z5 = z5 + z5 + t1;

            t0 = t3.mul_by_nonresidue();
            z2 = t0 + z2;
            z2 = z2 + z2 + t0;

            z3 = t2 - z3;
            z3 = z3 + z3 + t2;

            Fp12 {
                c0: Fp6 {
                    c0: z0,
                    c1: z4,
                    c2: z3,
                },
                c1: Fp6 {
                    c0: z2,
                    c1: z1,
                    c2: z5,
                },
            }
        }
        #[must_use]
        /// 计算 `f^x`（x 为 BLS 参数常量）在 cyclotomic 子群内的幂。
        /// 该函数使用固定比特扫描，属于最终指数化 hard part 的核心构件。
        /// 常量指数让实现可做更激进优化且保持结果确定性。
        fn cyclotomic_exp_by_x(f: Fp12) -> Fp12 {
            // 固定常量 x 的幂运算，作为最终指数化 hard part 的核心步骤。
            let bls_x = BLS_X;
            let mut accumulator = Fp12::one();
            let mut found_one = false;
            for bit_is_set in (0..64)
                .rev()
                .map(|bit_index| ((bls_x >> bit_index) & 1) == 1)
            {
                if found_one {
                    accumulator = cyclotomic_square(accumulator)
                } else {
                    found_one = bit_is_set;
                }

                if bit_is_set {
                    accumulator *= f;
                }
            }

            accumulator.conjugate()
        }

        let mut final_exponentiation_value = self.0;
        let mut t0 = final_exponentiation_value
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map()
            .frobenius_map();
        Gt(final_exponentiation_value
            .invert()
            .map(|mut t1| {
                let mut t2 = t0 * t1;
                t1 = t2;
                t2 = t2.frobenius_map().frobenius_map();
                t2 *= t1;
                t1 = cyclotomic_square(t2).conjugate();
                let mut t3 = cyclotomic_exp_by_x(t2);
                let mut t4 = cyclotomic_square(t3);
                let mut t5 = t1 * t3;
                t1 = cyclotomic_exp_by_x(t5);
                t0 = cyclotomic_exp_by_x(t1);
                let mut t6 = cyclotomic_exp_by_x(t0);
                t6 *= t4;
                t4 = cyclotomic_exp_by_x(t6);
                t5 = t5.conjugate();
                t4 *= t5 * t2;
                t5 = t2.conjugate();
                t1 *= t2;
                t1 = t1.frobenius_map().frobenius_map().frobenius_map();
                t6 *= t5;
                t6 = t6.frobenius_map();
                t3 *= t0;
                t3 = t3.frobenius_map().frobenius_map();
                t3 *= t1;
                t3 *= t6;
                final_exponentiation_value = t3 * t4;

                final_exponentiation_value
            })
            .unwrap())
    }
}

impl<'a, 'b> Add<&'b MillerLoopResult> for &'a MillerLoopResult {
    type Output = MillerLoopResult;

    #[inline]
    /// 将两个 Miller 循环结果相乘（在该类型语义下记作加法）。
    /// `MillerLoopResult` 代表 Fp12 乘法群元素，因此“相加”即底层相乘。
    /// 这种加法重载便于和 `Sum`/折叠接口统一配合。
    fn add(self, rhs: &'b MillerLoopResult) -> MillerLoopResult {
        MillerLoopResult(self.0 * rhs.0)
    }
}

impl_add_binop_specify_output!(
    MillerLoopResult,
    MillerLoopResult,
    MillerLoopResult
);

impl AddAssign<MillerLoopResult> for MillerLoopResult {
    #[inline]
    /// 原地累加（语义上为底层乘法）另一个 Miller 结果。
    /// 该接口用于迭代聚合，避免构造过多临时值。
    /// 与 `Add` 保持一致语义，确保代数行为闭合。
    fn add_assign(&mut self, rhs: MillerLoopResult) {
        *self = *self + rhs;
    }
}

impl<'b> AddAssign<&'b MillerLoopResult> for MillerLoopResult {
    #[inline]
    /// 原地累加引用版本，避免调用方显式拷贝参数。
    /// 在批量聚合场景中可降低不必要的 move 和临时分配。
    /// 行为与值语义版本完全一致。
    fn add_assign(&mut self, rhs: &'b MillerLoopResult) {
        *self = *self + rhs;
    }
}

/// `Gt` 表示配对目标群（target group）元素。
/// 其底层为 Fp12 子群元素，群运算采用乘法群语义。
/// 该类型承载签名验证、双线性关系检查等配对协议核心值。

#[cfg_attr(docsrs, doc(cfg(feature = "pairings")))]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, RkyvDeserialize, RkyvSerialize)
)]
#[cfg_attr(feature = "rkyv-impl", archive_attr(derive(CheckBytes)))]
pub struct Gt(pub(crate) Fp12);

impl Default for Gt {
    /// 返回 GT 群的默认值（单位元）。
    /// 单位元在目标群中对应 Fp12 的乘法单位 `1`。
    /// 默认实现使该类型可自然参与通用容器与 trait 生态。
    fn default() -> Self {
        Self::identity()
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for Gt {}

impl fmt::Display for Gt {
    /// 将 GT 元素以调试格式输出。
    /// 当前实现直接委托 `Debug`，便于开发阶段快速定位状态。
    /// 若未来引入标准编码输出，可在此替换展示语义。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl ConstantTimeEq for Gt {
    /// 常量时间比较两个 GT 元素是否相等。
    /// 常量时间语义可避免比较路径泄露数据相关时序信息。
    /// 该能力是安全实现等值判断的基础接口。
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Gt {
    /// 常量时间选择两个 GT 元素之一。
    /// 该原语常用于不希望产生数据相关分支的密码学流程。
    /// 底层委托到 Fp12 的常量时间选择实现。
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Gt(Fp12::conditional_select(&a.0, &b.0, choice))
    }
}

impl Eq for Gt {}
impl PartialEq for Gt {
    #[inline]
    /// 提供常规布尔相等比较，内部复用常量时间比较结果。
    /// 这样既兼容 Rust 标准比较接口，又保留密码学实现习惯。
    /// 返回值通过 `Choice -> bool` 转换得到。
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Gt {
    /// 返回 GT 群单位元。
    /// 在乘法群记法下，单位元用于聚合初始化与空积语义。
    /// 对应底层 Fp12 的 `one()`。
    pub fn identity() -> Gt {
        Gt(Fp12::one())
    }

    /// 计算群元素自乘（在乘法群语义下等价于“倍加”）。
    /// 对 GT 而言，常见“double”语义映射为平方运算。
    /// 该接口主要用于标量乘法中的逐位迭代步骤。
    pub fn double(&self) -> Gt {
        Gt(self.0.square())
    }
}

impl<'a> Neg for &'a Gt {
    type Output = Gt;

    #[inline]
    /// 计算 GT 元素的逆元（通过共轭实现）。
    /// 对单位ary 子群元素，共轭可高效得到乘法逆。
    /// 这比通用求逆算法更快，是配对目标群常用优化。
    fn neg(self) -> Gt {
        Gt(self.0.conjugate())
    }
}

impl Neg for Gt {
    type Output = Gt;

    #[inline]
    /// 值语义版本的“取负”（群逆），委托到引用实现。
    /// 保持两种调用风格语义一致，减少重复实现。
    /// 对调用方而言可按需选择 move 或 borrow 风格。
    fn neg(self) -> Gt {
        -&self
    }
}

impl<'a, 'b> Add<&'b Gt> for &'a Gt {
    type Output = Gt;

    #[inline]
    /// GT 群“加法”重载，实际执行底层乘法。
    /// 该记法与群抽象接口保持一致，便于泛型算法复用。
    /// 在配对协议中，多个 GT 元素聚合通常通过此运算完成。
    fn add(self, rhs: &'b Gt) -> Gt {
        Gt(self.0 * rhs.0)
    }
}

impl<'a, 'b> Sub<&'b Gt> for &'a Gt {
    type Output = Gt;

    #[inline]
    /// GT 群“减法”重载，语义为左值乘以右值逆元。
    /// 实现通过 `self + (-rhs)` 复用已有运算定义。
    /// 这种写法保持群代数语义清晰且减少代码分叉。
    fn sub(self, rhs: &'b Gt) -> Gt {
        self + (-rhs)
    }
}

impl<'a, 'b> Mul<&'b BlsScalar> for &'a Gt {
    type Output = Gt;

    /// 对 GT 元素做标量乘（群幂），使用二进制双倍-加算法。
    /// 算法按标量位迭代：先平方累积，再按当前位条件乘入基值。
    /// 该实现与群抽象一致，供签名与证明系统中指数运算使用。
    fn mul(self, other: &'b BlsScalar) -> Self::Output {
        let mut accumulated_gt = Gt::identity();
        // 跳过最高位可与“累积器从单位元开始”的约定配套，避免重复一次条件乘入。

        for bit in other
            .to_bytes()
            .iter()
            .rev()
            .flat_map(|byte| {
                (0..8).rev().map(move |i| Choice::from((byte >> i) & 1u8))
            })
            .skip(1)
        {
            accumulated_gt = accumulated_gt.double();
            accumulated_gt = Gt::conditional_select(
                &accumulated_gt,
                &(accumulated_gt + self),
                bit,
            );
        }

        accumulated_gt
    }
}

impl_binops_additive!(Gt, Gt);
impl_binops_multiplicative!(Gt, BlsScalar);

impl<T> Sum<T> for Gt
where
    T: Borrow<Gt>,
{
    /// 将迭代器中的 GT 元素做群聚合求和。
    /// 初值取单位元，逐项应用群“加法”（底层乘法）。
    /// 该实现便于直接使用 `iter.sum()` 语法完成聚合。
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

impl Group for Gt {
    type Scalar = BlsScalar;

    /// 随机采样 GT 元素。
    /// 实现先采样随机 Fp12，再做最终指数化投影到 GT 子群。
    /// 跳过零值可避免退化样本，提高样本质量与运算稳定性。
    fn random(mut rng: impl RngCore) -> Self {
        loop {
            let inner = Fp12::random(&mut rng);

            if !bool::from(inner.is_zero()) {
                return MillerLoopResult(inner).final_exponentiation();
            }
        }
    }

    /// 返回 GT 群单位元（Group trait 语义）。
    /// 该方法与 `Gt::identity()` 对齐，保证接口一致性。
    /// 作为 trait 实现，它服务通用群算法的初始化需求。
    fn identity() -> Self {
        Self::identity()
    }

    /// 返回 GT 的固定生成元。
    /// 该常量用于测试与协议构造中需要确定基点的场景。
    /// 生成元坐标来自标准参数，确保跨实现一致。
    fn generator() -> Self {
        Gt(Fp12 {
            c0: Fp6 {
                c0: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x1972_e433_a01f_85c5,
                        0x97d3_2b76_fd77_2538,
                        0xc8ce_546f_c96b_cdf9,
                        0xcef6_3e73_66d4_0614,
                        0xa611_3427_8184_3780,
                        0x13f3_448a_3fc6_d825,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0xd263_31b0_2e9d_6995,
                        0x9d68_a482_f779_7e7d,
                        0x9c9b_2924_8d39_ea92,
                        0xf480_1ca2_e131_07aa,
                        0xa16c_0732_bdbc_b066,
                        0x083c_a4af_ba36_0478,
                    ]),
                },
                c1: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x59e2_61db_0916_b641,
                        0x2716_b6f4_b23e_960d,
                        0xc8e5_5b10_a0bd_9c45,
                        0x0bdb_0bd9_9c4d_eda8,
                        0x8cf8_9ebf_57fd_aac5,
                        0x12d6_b792_9e77_7a5e,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x5fc8_5188_b0e1_5f35,
                        0x34a0_6e3a_8f09_6365,
                        0xdb31_26a6_e02a_d62c,
                        0xfc6f_5aa9_7d9a_990b,
                        0xa12f_55f5_eb89_c210,
                        0x1723_703a_926f_8889,
                    ]),
                },
                c2: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x9358_8f29_7182_8778,
                        0x43f6_5b86_11ab_7585,
                        0x3183_aaf5_ec27_9fdf,
                        0xfa73_d7e1_8ac9_9df6,
                        0x64e1_76a6_a64c_99b0,
                        0x179f_a78c_5838_8f1f,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x672a_0a11_ca2a_ef12,
                        0x0d11_b9b5_2aa3_f16b,
                        0xa444_12d0_699d_056e,
                        0xc01d_0177_221a_5ba5,
                        0x66e0_cede_6c73_5529,
                        0x05f5_a71e_9fdd_c339,
                    ]),
                },
            },
            c1: Fp6 {
                c0: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0xd30a_88a1_b062_c679,
                        0x5ac5_6a5d_35fc_8304,
                        0xd0c8_34a6_a81f_290d,
                        0xcd54_30c2_da37_07c7,
                        0xf0c2_7ff7_8050_0af0,
                        0x0924_5da6_e2d7_2eae,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0x9f2e_0676_791b_5156,
                        0xe2d1_c823_4918_fe13,
                        0x4c9e_459f_3c56_1bf4,
                        0xa3e8_5e53_b9d3_e3c1,
                        0x820a_121e_21a7_0020,
                        0x15af_6183_41c5_9acc,
                    ]),
                },
                c1: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x7c95_658c_2499_3ab1,
                        0x73eb_3872_1ca8_86b9,
                        0x5256_d749_4774_34bc,
                        0x8ba4_1902_ea50_4a8b,
                        0x04a3_d3f8_0c86_ce6d,
                        0x18a6_4a87_fb68_6eaa,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0xbb83_e71b_b920_cf26,
                        0x2a52_77ac_92a7_3945,
                        0xfc0e_e59f_94f0_46a0,
                        0x7158_cdf3_7860_58f7,
                        0x7cc1_061b_82f9_45f6,
                        0x03f8_47aa_9fdb_e567,
                    ]),
                },
                c2: Fp2 {
                    c0: Fp::from_raw_unchecked([
                        0x8078_dba5_6134_e657,
                        0x1cd7_ec9a_4399_8a6e,
                        0xb1aa_599a_1a99_3766,
                        0xc9a0_f62f_0842_ee44,
                        0x8e15_9be3_b605_dffa,
                        0x0c86_ba0d_4af1_3fc2,
                    ]),
                    c1: Fp::from_raw_unchecked([
                        0xe80f_f2a0_6a52_ffb1,
                        0x7694_ca48_721a_906c,
                        0x7583_183e_03b0_8514,
                        0xf567_afdd_40ce_e4e2,
                        0x9a6d_96d2_e526_a5fc,
                        0x197e_9f49_861f_2242,
                    ]),
                },
            },
        })
    }

    /// 判断当前 GT 元素是否为单位元。
    /// 该判断在群算法中常用于快速短路与边界处理。
    /// 内部复用常量时间等值比较，保持密码学实现风格一致。
    fn is_identity(&self) -> Choice {
        self.ct_eq(&Self::identity())
    }

    /// Group trait 语义下的“倍加”操作。
    /// 对 GT（乘法群）而言，倍加对应元素平方。
    /// 该接口服务于通用群算法对 `double` 的依赖。
    fn double(&self) -> Self {
        self.double()
    }
}

/// `G2Prepared` 保存 G2 点用于 Miller 循环的预计算线函数系数。
/// 预处理后可在多次配对中复用，显著降低重复计算成本。
/// 该结构是 multi-pairing（批量配对）性能优化的核心载体。

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "pairings", feature = "alloc"))))]
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, RkyvSerialize, RkyvDeserialize),
    archive_attr(derive(CheckBytes))
)]
pub struct G2Prepared {
    infinity: choice::Choice,
    coeffs: Vec<(Fp2, Fp2, Fp2)>,
}

#[cfg(feature = "alloc")]
impl From<G2Affine> for G2Prepared {
    /// 将 `G2Affine` 预处理为 `G2Prepared`。
    /// 过程会执行完整 Miller 路径并缓存每轮线函数系数。
    /// 对无穷点输入会替换为生成元计算并记录 infinity 标记，保证后续安全跳过。
    fn from(g2_point: G2Affine) -> G2Prepared {
        struct Adder {
            cur: G2Projective,
            base: G2Affine,
            coeffs: Vec<(Fp2, Fp2, Fp2)>,
        }

        impl MillerLoopDriver for Adder {
            type Output = ();

            /// 预处理阶段的倍点步骤：只收集系数，不累乘目标值。
            /// 系数来自 Jacobian 倍点公式，与正式 Miller 循环共享数学定义。
            /// 该路径用于构建 `coeffs` 表供后续快速消费。
            fn doubling_step(&mut self, _: Self::Output) -> Self::Output {
                let coeffs = doubling_step(&mut self.cur);
                self.coeffs.push(coeffs);
            }

            /// 预处理阶段的加点步骤：同样仅缓存线函数系数。
            /// 与倍点步骤交替构成完整 BLS 参数驱动的 Miller 调度。
            /// 缓存后可在多输入配对中避免重复几何运算。
            fn addition_step(&mut self, _: Self::Output) -> Self::Output {
                let coeffs = addition_step(&mut self.cur, &self.base);
                self.coeffs.push(coeffs);
            }

            /// 预处理模式下无需对输出做平方。
            /// 因输出类型为 `()`，该函数仅满足 trait 形状约束。
            /// 真正平方逻辑在正式 Miller 路径中执行。
            fn square_output(_: Self::Output) -> Self::Output {}

            /// 预处理模式下无需共轭操作。
            /// 该空实现用于复用统一的 Miller 驱动框架。
            /// 保持 trait 结构一致可降低维护复杂度。
            fn conjugate(_: Self::Output) -> Self::Output {}

            /// 预处理模式下的单位元占位实现。
            /// 因输出不承载数值，该函数语义为空。
            /// 它使同一驱动接口可同时服务“计算”与“预处理”两种模式。
            fn one() -> Self::Output {}
        }

        let is_identity = g2_point.is_identity();
        let selected_point = G2Affine::conditional_select(
            &g2_point,
            &G2Affine::generator(),
            is_identity,
        );

        let mut adder = Adder {
            cur: G2Projective::from(selected_point),
            base: selected_point,
            coeffs: Vec::with_capacity(68),
        };

        miller_loop(&mut adder);

        assert_eq!(adder.coeffs.len(), 68);

        G2Prepared {
            infinity: is_identity.into(),
            coeffs: adder.coeffs,
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(all(feature = "pairings", feature = "alloc"))))]

/// 对多组 `(G1, G2Prepared)` 同时执行 Miller 循环并合并结果。
/// 该接口用于批量配对场景，可复用预处理系数显著降低总成本。
/// 返回的是 Miller 中间值，调用方可按需延迟最终指数化。
pub fn multi_miller_loop(
    terms: &[(&G1Affine, &G2Prepared)],
) -> MillerLoopResult {
    struct Adder<'a, 'b, 'c> {
        terms: &'c [(&'a G1Affine, &'b G2Prepared)],
        index: usize,
    }

    impl<'a, 'b, 'c> MillerLoopDriver for Adder<'a, 'b, 'c> {
        type Output = Fp12;

        /// 多项配对下的 Miller 倍点轮次。
        /// 对每一项应用对应线函数，并在任一输入无穷点时常量时间跳过该项贡献。
        /// 最后推进系数索引，进入下一轮。
        fn doubling_step(&mut self, mut f: Self::Output) -> Self::Output {
            let index = self.index;
            for term in self.terms {
                // 任一端为无穷点时该项对乘积单位元无贡献，跳过线函数应用。
                let either_identity =
                    term.0.is_identity() | Choice::from(term.1.infinity);

                let new_f =
                    apply_line_function(f, &term.1.coeffs[index], term.0);
                f = Fp12::conditional_select(&new_f, &f, either_identity);
            }
            self.index += 1;

            f
        }

        /// 多项配对下的 Miller 加点轮次。
        /// 逻辑与倍点轮次类似，但使用加点系数序列。
        /// 该实现保证批量路径与单项路径在代数上严格一致。
        fn addition_step(&mut self, mut f: Self::Output) -> Self::Output {
            let index = self.index;
            for term in self.terms {
                let either_identity =
                    term.0.is_identity() | Choice::from(term.1.infinity);

                let new_f =
                    apply_line_function(f, &term.1.coeffs[index], term.0);
                f = Fp12::conditional_select(&new_f, &f, either_identity);
            }
            self.index += 1;

            f
        }

        /// 对累乘值执行平方（Miller 迭代必需步骤）。
        /// 平方在每个比特轮次后执行，用于推进 Miller 累乘状态。
        /// 单独抽象为 driver 接口便于复用通用调度器。
        fn square_output(f: Self::Output) -> Self::Output {
            f.square()
        }

        /// 在负参数分支下执行共轭修正。
        /// BLS12-381 的参数符号会影响最终 Miller 值方向。
        /// 共轭操作是该修正的标准实现方式。
        fn conjugate(f: Self::Output) -> Self::Output {
            f.conjugate()
        }

        /// 返回 Miller 累乘初始单位元。
        /// 对 Fp12 乘法群而言单位元是 `1`。
        /// 该初值与数学定义保持一致。
        fn one() -> Self::Output {
            Fp12::one()
        }
    }

    let mut adder = Adder { terms, index: 0 };

    let miller_value = miller_loop(&mut adder);

    MillerLoopResult(miller_value)
}

#[cfg_attr(docsrs, doc(cfg(feature = "pairings")))]
/// 计算最优 Ate 配对并返回 GT 元素。
/// 该函数会自动处理无穷点边界并保证结果与群语义一致。
/// 内部流程为 Miller 循环 + 最终指数化，是单对输入的标准入口。
pub fn pairing(p: &G1Affine, q: &G2Affine) -> Gt {
    struct Adder {
        cur: G2Projective,
        base: G2Affine,
        p: G1Affine,
    }

    impl MillerLoopDriver for Adder {
        type Output = Fp12;

        /// 单项配对路径中的倍点步骤。
        /// 每轮先更新 G2 当前点，再把线函数作用到累乘值。
        /// 该实现与批量路径保持同一线函数定义。
        fn doubling_step(&mut self, f: Self::Output) -> Self::Output {
            let coeffs = doubling_step(&mut self.cur);
            apply_line_function(f, &coeffs, &self.p)
        }

        /// 单项配对路径中的加点步骤。
        /// 使用固定基点 `base` 进行加法并提取线函数系数。
        /// 结果继续作用于 Miller 累乘值。
        fn addition_step(&mut self, f: Self::Output) -> Self::Output {
            let coeffs = addition_step(&mut self.cur, &self.base);
            apply_line_function(f, &coeffs, &self.p)
        }

        /// Miller 轮次中的平方操作。
        /// 每次位迭代后执行一次平方推进状态。
        /// 与多项路径共享完全一致的代数语义。
        fn square_output(f: Self::Output) -> Self::Output {
            f.square()
        }

        /// 负参数情况下的共轭修正。
        /// 用于统一处理 BLS 参数符号差异。
        /// 该步骤由通用 Miller 调度器在尾部触发。
        fn conjugate(f: Self::Output) -> Self::Output {
            f.conjugate()
        }

        /// 返回单项配对 Miller 累乘初值。
        /// 单位元选取与 Fp12 乘法群定义一致。
        /// 为后续 fold 迭代提供中性起点。
        fn one() -> Self::Output {
            Fp12::one()
        }
    }

    let either_identity = p.is_identity() | q.is_identity();
    let selected_p = G1Affine::conditional_select(
        p,
        &G1Affine::generator(),
        either_identity,
    );
    let selected_q = G2Affine::conditional_select(
        q,
        &G2Affine::generator(),
        either_identity,
    );

    let mut adder = Adder {
        cur: G2Projective::from(selected_q),
        base: selected_q,
        p: selected_p,
    };

    let miller_value = miller_loop(&mut adder);
    let miller_result = MillerLoopResult(Fp12::conditional_select(
        &miller_value,
        &Fp12::one(),
        either_identity,
    ));
    miller_result.final_exponentiation()
}

trait MillerLoopDriver {
    type Output;

    /// 驱动一次倍点轮次并返回更新后的累乘值。
    /// 该接口抽象了几何更新与线函数应用的组合行为。
    /// 单项与多项路径可通过不同实现复用同一调度器。
    fn doubling_step(&mut self, f: Self::Output) -> Self::Output;

    /// 驱动一次加点轮次并返回更新后的累乘值。
    /// 在 BLS 参数位为 1 的轮次中，该步骤与倍点轮次配套执行。
    /// 抽象接口有助于隔离调度逻辑与具体系数来源。
    fn addition_step(&mut self, f: Self::Output) -> Self::Output;

    /// 对当前累乘值执行平方变换。
    /// Miller 算法每轮都会进行该操作以推进指数结构。
    /// 抽象此步骤可使输出类型保持泛型。
    fn square_output(f: Self::Output) -> Self::Output;

    /// 对输出执行共轭修正。
    /// 当参数符号为负时，该步骤用于得到正确方向的 Miller 结果。
    /// 在部分驱动实现中它可能是空操作。
    fn conjugate(f: Self::Output) -> Self::Output;

    /// 返回驱动输出类型的乘法单位元。
    /// 该单位元用于初始化 Miller 累乘状态。
    /// 一致的单位元定义是通用调度可复用的前提。
    fn one() -> Self::Output;
}

/// 通用 Miller 循环驱动，支持单对和多对输入。
/// 调度器只依赖 `MillerLoopDriver` 抽象，因此可复用在计算与预处理两类流程。
/// 该设计把“位调度逻辑”与“线函数来源”解耦，降低实现复杂度。
fn miller_loop<D: MillerLoopDriver>(driver: &mut D) -> D::Output {
    let mut miller_value = D::one();

    // 按 BLS 参数 x 的二进制位（从高到低）执行双线性 Miller 累乘。
    let mut found_one = false;
    for bit_is_set in (0..64)
        .rev()
        .map(|bit_index| (((BLS_X >> 1) >> bit_index) & 1) == 1)
    {
        if !found_one {
            found_one = bit_is_set;
            continue;
        }

        miller_value = driver.doubling_step(miller_value);

        if bit_is_set {
            miller_value = driver.addition_step(miller_value);
        }

        miller_value = D::square_output(miller_value);
    }

    miller_value = driver.doubling_step(miller_value);

    if BLS_X_IS_NEGATIVE {
        miller_value = D::conjugate(miller_value);
    }

    miller_value
}

/// 将一条切线/割线系数作用到累乘值 `f` 上。
/// 过程会把 G1 仿射点坐标并入线函数三元组，再执行稀疏乘法更新。
/// 这是 Miller 每一轮更新目标域元素的核心步骤。
fn apply_line_function(
    f: Fp12,
    coeffs: &(Fp2, Fp2, Fp2),
    p: &G1Affine,
) -> Fp12 {
    let mut c0 = coeffs.0;
    let mut c1 = coeffs.1;

    c0.c0 *= p.y;
    c0.c1 *= p.y;

    c1.c0 *= p.x;
    c1.c1 *= p.x;

    f.mul_by_014(&coeffs.2, &c1, &c0)
}

/// Miller 循环中的 G2 倍点步骤，返回线函数系数。
/// 在 Jacobian 坐标下同步完成“点更新 + 系数提取”，避免重复计算。
/// 返回的三元组会立刻用于 `apply_line_function` 更新累乘值。
fn doubling_step(r: &mut G2Projective) -> (Fp2, Fp2, Fp2) {
    // Jacobian 坐标倍点；同时返回本轮线函数在 Fp2 上的三个系数。
    let tmp0 = r.x.square();
    let tmp1 = r.y.square();
    let tmp2 = tmp1.square();
    let tmp3 = (tmp1 + r.x).square() - tmp0 - tmp2;
    let tmp3 = tmp3 + tmp3;
    let tmp4 = tmp0 + tmp0 + tmp0;
    let tmp6 = r.x + tmp4;
    let tmp5 = tmp4.square();
    let zsquared = r.z.square();
    r.x = tmp5 - tmp3 - tmp3;
    r.z = (r.z + r.y).square() - tmp1 - zsquared;
    r.y = (tmp3 - r.x) * tmp4;
    let tmp2 = tmp2 + tmp2;
    let tmp2 = tmp2 + tmp2;
    let tmp2 = tmp2 + tmp2;
    r.y -= tmp2;
    let tmp3 = tmp4 * zsquared;
    let tmp3 = tmp3 + tmp3;
    let tmp3 = -tmp3;
    let tmp6 = tmp6.square() - tmp0 - tmp5;
    let tmp1 = tmp1 + tmp1;
    let tmp1 = tmp1 + tmp1;
    let tmp6 = tmp6 - tmp1;
    let tmp0 = r.z * zsquared;
    let tmp0 = tmp0 + tmp0;

    (tmp0, tmp3, tmp6)
}

/// Miller 循环中的 G2 加点步骤，返回线函数系数。
/// 该步骤使用 `Jacobian + Affine` 混合加法，兼顾效率与实现简洁性。
/// 系数输出与倍点步骤同构，便于统一接入线函数应用逻辑。
fn addition_step(r: &mut G2Projective, q: &G2Affine) -> (Fp2, Fp2, Fp2) {
    // Jacobian + Affine 混合加法；同样返回线函数系数供 Miller 累乘使用。
    let zsquared = r.z.square();
    let ysquared = q.y.square();
    let t0 = zsquared * q.x;
    let t1 = ((q.y + r.z).square() - ysquared - zsquared) * zsquared;
    let t2 = t0 - r.x;
    let t3 = t2.square();
    let t4 = t3 + t3;
    let t4 = t4 + t4;
    let t5 = t4 * t2;
    let t6 = t1 - r.y - r.y;
    let t9 = t6 * q.x;
    let t7 = t4 * r.x;
    r.x = t6.square() - t5 - t7 - t7;
    r.z = (r.z + t2).square() - zsquared - t3;
    let t10 = q.y + r.z;
    let t8 = (t7 - r.x) * t6;
    let t0 = r.y * t5;
    let t0 = t0 + t0;
    r.y = t8 - t0;
    let t10 = t10.square() - ysquared;
    let ztsquared = r.z.square();
    let t10 = t10 - ztsquared;
    let t9 = t9 + t9 - t10;
    let t10 = r.z + r.z;
    let t6 = -t6;
    let t1 = t6 + t6;

    (t10, t1, t9)
}

impl PairingCurveAffine for G1Affine {
    type Pair = G2Affine;
    type PairingResult = Gt;

    /// 以 `G1Affine` 为左输入执行配对。
    /// 该方法是 trait 适配层，直接委托到库内 `pairing` 实现。
    /// 通过该接口可与通用 pairing trait 生态无缝集成。
    fn pairing_with(&self, other: &Self::Pair) -> Self::PairingResult {
        pairing(self, other)
    }
}

impl PairingCurveAffine for G2Affine {
    type Pair = G1Affine;
    type PairingResult = Gt;

    /// 以 `G2Affine` 为左输入执行配对（参数顺序做适配）。
    /// 该实现交换参数后委托给统一 `pairing` 函数。
    /// 目的在于满足 trait 接口同时保持内部实现单一来源。
    fn pairing_with(&self, other: &Self::Pair) -> Self::PairingResult {
        pairing(other, self)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "pairings")))]
#[derive(Clone, Debug)]
pub struct Bls12;

impl Engine for Bls12 {
    type Fr = BlsScalar;
    type G1 = G1Projective;
    type G1Affine = G1Affine;
    type G2 = G2Projective;
    type G2Affine = G2Affine;
    type Gt = Gt;

    /// 引擎层标准配对入口。
    /// 该方法把 trait 调用桥接到本模块优化实现。
    /// 对外提供与 `pairing::Engine` 兼容的统一接口。
    fn pairing(p: &Self::G1Affine, q: &Self::G2Affine) -> Self::Gt {
        pairing(p, q)
    }
}

impl pairing::MillerLoopResult for MillerLoopResult {
    type Gt = Gt;

    /// 将 Miller 中间结果完成最终指数化并转换到 GT。
    /// 这是 trait 适配函数，语义与本类型固有方法一致。
    /// 暴露该接口后可接入通用配对框架流程。
    fn final_exponentiation(&self) -> Self::Gt {
        self.final_exponentiation()
    }
}

#[cfg(feature = "alloc")]
impl MultiMillerLoop for Bls12 {
    type G2Prepared = G2Prepared;
    type Result = MillerLoopResult;

    /// 执行多项 Miller 循环并返回中间结果。
    /// 调用方可在外层决定是否立即最终指数化。
    /// 这种分层设计有利于批量验证中的延迟优化策略。
    fn multi_miller_loop(
        terms: &[(&Self::G1Affine, &Self::G2Prepared)],
    ) -> Self::Result {
        multi_miller_loop(terms)
    }
}

#[test]
/// 验证 GT 生成元等于对两侧标准生成元做配对的结果。
/// 该测试确保 `Gt::generator` 常量与配对定义保持一致。
/// 对参数初始化与跨版本兼容有基础保障作用。
fn test_gt_generator() {
    assert_eq!(
        Gt::generator(),
        pairing(&G1Affine::generator(), &G2Affine::generator())
    );
}

#[test]
/// 验证配对双线性性质。
/// 用随机样式标量构造 `e(aP, bQ) == e(P, Q)^{ab}` 的等式回归。
/// 该性质是配对密码学协议正确性的核心公理之一。
fn test_bilinearity() {
    use crate::BlsScalar;

    let left_scalar =
        BlsScalar::from_raw([1, 2, 3, 4]).invert().unwrap().square();
    let right_scalar =
        BlsScalar::from_raw([5, 6, 7, 8]).invert().unwrap().square();
    let product_scalar = left_scalar * right_scalar;

    let g1_point = G1Affine::from(G1Affine::generator() * left_scalar);
    let g2_point = G2Affine::from(G2Affine::generator() * right_scalar);
    let pairing_result = pairing(&g1_point, &g2_point);

    assert!(pairing_result != Gt::identity());

    let expected_g1_point =
        G1Affine::from(G1Affine::generator() * product_scalar);

    assert_eq!(
        pairing_result,
        pairing(&expected_g1_point, &G2Affine::generator())
    );
    assert_eq!(
        pairing_result,
        pairing(&G1Affine::generator(), &G2Affine::generator())
            * product_scalar
    );
}

#[test]
/// 验证配对在取逆（负元）下的相容性。
/// 检查 `-e(P,Q) == e(P,-Q) == e(-P,Q)` 等关系。
/// 该测试可捕获符号处理或共轭路径的实现偏差。
fn test_unitary() {
    let g1_generator = G1Affine::generator();
    let g2_generator = G2Affine::generator();
    let negated_pairing = -pairing(&g1_generator, &g2_generator);
    let negated_g2_pairing = pairing(&g1_generator, &-g2_generator);
    let negated_g1_pairing = pairing(&-g1_generator, &g2_generator);

    assert_eq!(negated_pairing, negated_g2_pairing);
    assert_eq!(negated_g2_pairing, negated_g1_pairing);
}

#[cfg(feature = "alloc")]
#[test]
/// 验证批量 Miller 路径与逐项 pairing 聚合结果一致。
/// 测试同时覆盖无穷点输入，确保“跳过项”逻辑正确。
/// 这是 multi-pairing 优化正确性的关键回归用例。
fn test_multi_miller_loop() {
    let a1 = G1Affine::generator();
    let b1 = G2Affine::generator();

    let a2 = G1Affine::from(
        G1Affine::generator()
            * BlsScalar::from_raw([1, 2, 3, 4]).invert().unwrap().square(),
    );
    let b2 = G2Affine::from(
        G2Affine::generator()
            * BlsScalar::from_raw([4, 2, 2, 4]).invert().unwrap().square(),
    );

    let a3 = G1Affine::identity();
    let b3 = G2Affine::from(
        G2Affine::generator()
            * BlsScalar::from_raw([9, 2, 2, 4]).invert().unwrap().square(),
    );

    let a4 = G1Affine::from(
        G1Affine::generator()
            * BlsScalar::from_raw([5, 5, 5, 5]).invert().unwrap().square(),
    );
    let b4 = G2Affine::identity();

    let a5 = G1Affine::from(
        G1Affine::generator()
            * BlsScalar::from_raw([323, 32, 3, 1])
                .invert()
                .unwrap()
                .square(),
    );
    let b5 = G2Affine::from(
        G2Affine::generator()
            * BlsScalar::from_raw([4, 2, 2, 9099])
                .invert()
                .unwrap()
                .square(),
    );

    let b1_prepared = G2Prepared::from(b1);
    let b2_prepared = G2Prepared::from(b2);
    let b3_prepared = G2Prepared::from(b3);
    let b4_prepared = G2Prepared::from(b4);
    let b5_prepared = G2Prepared::from(b5);

    let expected = pairing(&a1, &b1)
        + pairing(&a2, &b2)
        + pairing(&a3, &b3)
        + pairing(&a4, &b4)
        + pairing(&a5, &b5);

    let test = multi_miller_loop(&[
        (&a1, &b1_prepared),
        (&a2, &b2_prepared),
        (&a3, &b3_prepared),
        (&a4, &b4_prepared),
        (&a5, &b5_prepared),
    ])
    .final_exponentiation();

    assert_eq!(expected, test);
}

#[test]
/// 验证 `MillerLoopResult::default()` 最终指数化后为 GT 单位元。
/// 该性质保证默认值可安全作为累乘中性初值。
/// 对聚合初始化逻辑具有基础保障意义。
fn test_miller_loop_result_default() {
    assert_eq!(
        MillerLoopResult::default().final_exponentiation(),
        Gt::identity(),
    );
}

#[cfg(feature = "zeroize")]
#[test]
/// 验证开启 zeroize 时 Miller 结果可被安全清零。
/// 测试关注敏感中间值在显式擦除后的状态是否符合预期。
/// 该能力用于降低内存残留带来的侧信道风险。
fn test_miller_loop_result_zeroize() {
    use zeroize::Zeroize;

    let mut miller_result = multi_miller_loop(&[
        (&G1Affine::generator(), &G2Affine::generator().into()),
        (&-G1Affine::generator(), &G2Affine::generator().into()),
    ]);
    miller_result.zeroize();
    assert_eq!(miller_result.0, MillerLoopResult::default().0);
}

#[test]
/// 验证 `multi_miller_loop` 对无穷点与抵消项的处理语义。
/// 无穷点应对中间乘积无贡献，而相反项应在最终指数化后回到单位元。
/// 该测试覆盖了批量路径中最易出错的边界组合。
fn tricking_miller_loop_result() {
    assert_eq!(
        multi_miller_loop(&[(
            &G1Affine::identity(),
            &G2Affine::generator().into()
        )])
        .0,
        Fp12::one()
    );
    assert_eq!(
        multi_miller_loop(&[(
            &G1Affine::generator(),
            &G2Affine::identity().into()
        )])
        .0,
        Fp12::one()
    );
    assert_ne!(
        multi_miller_loop(&[
            (&G1Affine::generator(), &G2Affine::generator().into()),
            (&-G1Affine::generator(), &G2Affine::generator().into())
        ])
        .0,
        Fp12::one()
    );
    assert_eq!(
        multi_miller_loop(&[
            (&G1Affine::generator(), &G2Affine::generator().into()),
            (&-G1Affine::generator(), &G2Affine::generator().into())
        ])
        .final_exponentiation(),
        Gt::identity()
    );
}
