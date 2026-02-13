use crate::prelude::Witness;
use coset_bls12_381::BlsScalar;

#[derive(Debug, Clone, Copy)]
pub struct WitnessPoint {
    x: Witness,
    y: Witness,
}

impl WitnessPoint {
    #[allow(dead_code)]
    /// 由 x/y 两个 witness 构造曲线点句柄。
    /// 该类型仅保存 witness 引用关系，不直接保存具体曲线坐标值。
    /// 常用于 composer 中的点运算组件接口传递。
    pub(crate) const fn new(x: Witness, y: Witness) -> Self {
        Self { x, y }
    }

    /// 返回点的 x 坐标 witness。
    /// 调用方可据此继续构造算术或群运算约束。
    /// 返回引用可避免不必要复制。
    pub const fn x(&self) -> &Witness {
        &self.x
    }

    /// 返回点的 y 坐标 witness。
    /// 与 `x()` 对称，用于读取点句柄的另一坐标通道。
    /// 返回引用可避免不必要复制。
    pub const fn y(&self) -> &Witness {
        &self.y
    }

    /// 以值拷贝方式返回 (x, y) 两个 witness。
    /// 适合在需要一次性解包坐标的调用点，减少重复 `x()/y()` 访问。
    /// 不影响现有按引用访问接口。
    pub const fn coordinates(&self) -> (Witness, Witness) {
        (self.x, self.y)
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WnafRound<T: Into<Witness>> {
    pub accumulator_x: T,
    pub accumulator_y: T,
    pub accumulated_scalar: T,
    pub addend_xy_product: T,
    pub precomputed_x: BlsScalar,
    pub precomputed_y: BlsScalar,
    pub precomputed_xy_product: BlsScalar,
}
