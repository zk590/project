#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum WireData {
    Left(usize),

    Right(usize),

    Output(usize),

    Fourth(usize),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Witness {
    index: usize,
}

impl Default for Witness {
    /// 返回默认 witness（约定映射到常量 0）。
    /// 该实现让 `Witness` 可参与 `Default` 生态，便于数组与结构体初始化。
    /// 语义上等价于 `Composer::ZERO`。
    fn default() -> Self {
        crate::composer::Composer::ZERO
    }
}

impl Witness {
    /// 表示常量 0 的 witness 索引。
    /// 该值在 composer 初始化阶段被固定写入 witness 表。
    /// 后续约束可直接复用该索引表达常量零。
    pub const ZERO: Witness = Witness::new(0);

    /// 表示常量 1 的 witness 索引。
    /// 与 `ZERO` 一样由初始化流程预置，避免重复分配常量 witness。
    /// 常用于布尔约束和仿射变换中的单位项构造。
    pub const ONE: Witness = Witness::new(1);

    /// 从底层索引构造 witness。
    /// 该函数仅封装索引，不检查其是否在当前 composer 中有效。
    /// 主要供内部模块在受控路径下创建 witness 句柄。
    pub(crate) const fn new(index: usize) -> Self {
        Self { index }
    }

    /// 返回 witness 的底层索引值。
    /// 调用方可据此访问 witness 表或执行序列化映射。
    /// 该接口为 `const fn`，可在编译期常量上下文中使用。
    pub const fn index(&self) -> usize {
        self.index
    }

    /// 判断当前 witness 是否为预置常量（0 或 1）。
    /// 该辅助函数可用于约束构造中的快速分支优化。
    /// 不依赖 composer 实例，纯索引判定。
    pub const fn is_predefined_constant(&self) -> bool {
        self.index <= Self::ONE.index
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::DefaultIsZeroes for Witness {}
