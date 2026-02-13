use crate::prelude::{Composer, Witness};
use coset_bls12_381::BlsScalar;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Selector {
    Multiplication = 0x00,

    Left = 0x01,

    Right = 0x02,

    Output = 0x03,

    Fourth = 0x04,

    Constant = 0x05,

    PublicInput = 0x06,

    Arithmetic = 0x07,

    Range = 0x08,

    Logic = 0x09,

    GroupAddFixedBase = 0x0a,

    GroupAddVariableBase = 0x0b,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WiredWitness {
    A = 0x00,

    B = 0x01,

    C = 0x02,

    D = 0x03,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Constraint {
    coefficients: [BlsScalar; Self::COEFFICIENTS],
    witnesses: [Witness; Self::WITNESSES],
    has_public_input: bool,
}

impl Default for Constraint {
    /// 返回默认约束对象。
    /// 默认值等价于 `Constraint::new()`，所有系数为 0，witness 指向常量 0。
    /// 适用于链式构造前的空白约束初始化。
    fn default() -> Self {
        Self::new()
    }
}

impl AsRef<[BlsScalar]> for Constraint {
    /// 以切片视图暴露内部系数数组。
    /// 该接口便于通用序列化与调试组件按批量方式读取系数。
    /// 返回值不包含 witness 信息，仅覆盖 selector 相关系数。
    fn as_ref(&self) -> &[BlsScalar] {
        &self.coefficients
    }
}

impl Constraint {
    pub const COEFFICIENTS: usize = 12;

    pub const WITNESSES: usize = 4;

    /// 创建一个空约束。
    /// 初始状态下所有 selector 系数为 0，所有 witness 绑定到 `Composer::ZERO`。
    /// 后续可通过链式 API 逐步填充系数与 witness 映射。
    pub const fn new() -> Self {
        Self {
            coefficients: [BlsScalar::zero(); Self::COEFFICIENTS],
            witnesses: [Composer::ZERO; Self::WITNESSES],
            has_public_input: false,
        }
    }

    /// 从外部约束拷贝基础系数与 witness 信息。
    /// 该函数会保留外部输入的线性/乘法/常量等字段，但重置扩展 selector 区域。
    /// 常用于在现有约束基础上派生特定组件门类型。
    fn from_external(constraint: &Self) -> Self {
        const BASE_SELECTOR_COUNT: usize = Selector::Arithmetic as usize;

        let mut cloned_constraint = Self::default();

        let source_coefficients =
            &constraint.coefficients[..BASE_SELECTOR_COUNT];
        let target_coefficients =
            &mut cloned_constraint.coefficients[..BASE_SELECTOR_COUNT];

        target_coefficients.copy_from_slice(source_coefficients);

        cloned_constraint.has_public_input = constraint.has_public_input();
        cloned_constraint
            .witnesses
            .copy_from_slice(&constraint.witnesses);

        cloned_constraint
    }

    /// 设置指定 selector 系数。
    /// 接口采用消费式链式风格，便于一行内完成多项配置。
    /// 输入会被转换为标量后写入对应位置。
    pub(crate) fn set<T: Into<BlsScalar>>(
        mut self,
        selector: Selector,
        value: T,
    ) -> Self {
        self.coefficients[selector as usize] = value.into();

        self
    }

    /// 为指定线位写入 witness。
    /// 该函数为可变引用版本，常用于链式 API 内部复用。
    /// 写入后会覆盖该线位先前绑定的 witness。
    pub(crate) fn set_witness(
        &mut self,
        witness_index: WiredWitness,
        witness: Witness,
    ) {
        self.witnesses[witness_index as usize] = witness;
    }

    /// 以消费式接口绑定指定线位 witness。
    /// 该辅助函数用于统一 `a/b/c/d` 的实现，减少重复样板代码。
    /// 不改变外部 API，仅改善内部可维护性。
    fn bind_witness(mut self, wire: WiredWitness, witness: Witness) -> Self {
        self.set_witness(wire, witness);
        self
    }

    /// 读取指定 selector 的系数引用。
    /// 该方法为 `const` 访问器，便于在验证逻辑中高频读取。
    /// 返回不可变引用，防止外部绕过构造 API 修改约束。
    pub(crate) const fn coeff(&self, selector: Selector) -> &BlsScalar {
        &self.coefficients[selector as usize]
    }

    /// 读取指定线位绑定的 witness。
    /// 用于 gate 展开与置换映射阶段获取线位连接关系。
    /// 返回值按值复制，不产生借用生命周期负担。
    pub(crate) const fn witness(&self, witness_index: WiredWitness) -> Witness {
        self.witnesses[witness_index as usize]
    }

    /// 设置乘法 selector 系数 `q_m`。
    /// 该字段控制约束中的双线性项权重。
    /// 接口返回新约束，支持链式拼接。
    pub fn mult<T: Into<BlsScalar>>(self, value: T) -> Self {
        self.set(Selector::Multiplication, value)
    }

    /// 设置左输入线系数 `q_l`。
    /// 该系数作用于 A 线 witness。
    /// 返回新约束以支持链式配置。
    pub fn left<T: Into<BlsScalar>>(self, value: T) -> Self {
        self.set(Selector::Left, value)
    }

    /// 设置右输入线系数 `q_r`。
    /// 该系数作用于 B 线 witness。
    /// 返回新约束以支持链式配置。
    pub fn right<T: Into<BlsScalar>>(self, value: T) -> Self {
        self.set(Selector::Right, value)
    }

    /// 设置输出线系数 `q_o`。
    /// 该系数作用于 C 线 witness。
    /// 返回新约束以支持链式配置。
    pub fn output<T: Into<BlsScalar>>(self, value: T) -> Self {
        self.set(Selector::Output, value)
    }

    /// 设置第四线系数 `q_f`。
    /// 该系数作用于 D 线 witness，常用于扩展门约束。
    /// 返回新约束以支持链式配置。
    pub fn fourth<T: Into<BlsScalar>>(self, value: T) -> Self {
        self.set(Selector::Fourth, value)
    }

    /// 设置常量项系数 `q_c`。
    /// 常用于引入偏置项或实现等式右侧常量迁移。
    /// 返回新约束以支持链式配置。
    pub fn constant<T: Into<BlsScalar>>(self, value: T) -> Self {
        self.set(Selector::Constant, value)
    }

    /// 标记并设置公开输入系数。
    /// 调用后该约束会被 runtime 识别为含公开输入的 gate。
    /// 返回新约束以支持链式配置。
    pub fn public<T: Into<BlsScalar>>(mut self, value: T) -> Self {
        self.has_public_input = true;

        self.set(Selector::PublicInput, value)
    }

    /// 绑定 A 线 witness。
    /// 该方法用于把电路变量接入约束左线位置。
    /// 返回新约束以支持链式配置。
    pub fn a(self, witness: Witness) -> Self {
        self.bind_witness(WiredWitness::A, witness)
    }

    /// 绑定 B 线 witness。
    /// 该方法用于把电路变量接入约束右线位置。
    /// 返回新约束以支持链式配置。
    pub fn b(self, witness: Witness) -> Self {
        self.bind_witness(WiredWitness::B, witness)
    }

    /// 绑定 C 线 witness。
    /// 该方法用于把电路变量接入约束输出线位置。
    /// 返回新约束以支持链式配置。
    pub fn c(self, witness: Witness) -> Self {
        self.bind_witness(WiredWitness::C, witness)
    }

    /// 绑定 D 线 witness。
    /// 该方法用于扩展门场景中的第四输入线绑定。
    /// 返回新约束以支持链式配置。
    pub fn d(self, witness: Witness) -> Self {
        self.bind_witness(WiredWitness::D, witness)
    }

    /// 判断当前约束是否包含公开输入项。
    /// 该标志用于后续编译阶段提取公开输入向量。
    /// 返回值由 `public()` 调用路径维护。
    pub(crate) const fn has_public_input(&self) -> bool {
        self.has_public_input
    }

    /// 派生算术门约束。
    /// 在保留基础系数与 witness 的同时，将 `q_arith` 置为 1。
    /// 用于通用算术关系约束构造。
    pub(crate) fn arithmetic(constraint: &Self) -> Self {
        Self::from_external(constraint).set(Selector::Arithmetic, 1)
    }

    #[allow(dead_code)]
    /// 派生范围检查门约束。
    /// 该函数复制基础约束并激活 `q_range` selector。
    /// 主要用于 range 组件约束表达。
    pub(crate) fn range(constraint: &Self) -> Self {
        Self::from_external(constraint).set(Selector::Range, 1)
    }

    #[allow(dead_code)]
    /// 派生逻辑门约束（AND 路径）。
    /// 该函数会设置逻辑相关 selector 以切换到逻辑组件语义。
    /// 常与 `append_logic_component` 配合使用。
    pub(crate) fn logic(constraint: &Self) -> Self {
        Self::from_external(constraint)
            .set(Selector::Constant, 1)
            .set(Selector::Logic, 1)
    }

    #[allow(dead_code)]
    /// 派生逻辑门约束（XOR 路径）。
    /// 与 `logic` 相比，该函数通过符号差异编码 XOR 行为。
    /// 用于逻辑组件中 XOR 约束的门类型切换。
    pub(crate) fn logic_xor(constraint: &Self) -> Self {
        Self::from_external(constraint)
            .set(Selector::Constant, -BlsScalar::one())
            .set(Selector::Logic, -BlsScalar::one())
    }

    #[allow(dead_code)]
    /// 派生固定基点群加法门约束。
    /// 该函数在保留基础线位关系的同时激活固定基点 selector。
    /// 用于固定基点标量乘相关电路部件。
    pub(crate) fn group_add_fixed_base(constraint: &Self) -> Self {
        Self::from_external(constraint).set(Selector::GroupAddFixedBase, 1)
    }

    #[allow(dead_code)]
    /// 派生可变基点群加法门约束。
    /// 该函数激活可变基点 selector 以表达曲线点加法关系。
    /// 常用于通用椭圆曲线运算组件。
    pub(crate) fn group_add_variable_base(constraint: &Self) -> Self {
        Self::from_external(constraint).set(Selector::GroupAddVariableBase, 1)
    }
}
