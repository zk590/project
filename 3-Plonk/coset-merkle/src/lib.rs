#![no_std]
#![deny(clippy::pedantic)]

extern crate alloc;

use core::mem::MaybeUninit;
use core::ptr;

mod node;
mod opening;
mod tree;
mod walk;

pub use node::*;
pub use opening::*;
pub use tree::*;
pub use walk::*;

/// 定义可聚合数据的统一接口。
/// 在 Merkle 树语境下，`aggregate` 负责把一层子节点值折叠为父节点值。
/// `EMPTY_SUBTREE` 作为空子树哨兵值，保证未填充分支也能参与一致计算。
pub trait Aggregate<const A: usize> {
    const EMPTY_SUBTREE: Self;

    /// 将固定 `A` 个子节点值聚合为当前层父节点值。
    /// 该函数必须满足确定性：相同输入顺序下总是得到相同输出。
    /// 具体聚合规则由实现类型定义，例如求和、哈希或范围合并。
    fn aggregate(items: [&Self; A]) -> Self;
}

/// 为空元组提供 `Aggregate` 实现，便于在无业务负载时复用树结构代码。
/// 该实现常用于占位测试或只关心树形索引结构而不关心聚合值的场景。
/// 由于 `()` 没有可计算数据，聚合结果始终是 `()` 本身。
impl<const A: usize> Aggregate<A> for () {
    const EMPTY_SUBTREE: Self = ();
    fn aggregate(_: [&Self; A]) -> Self {}
}

/// 初始化固定长度数组的内部工具函数。
/// 该函数用闭包按索引逐项构造数组，避免 `T: Copy/Default` 约束。
/// 实现使用 `MaybeUninit` 安全地完成逐元素写入，再整体转回已初始化数组。
pub(crate) fn init_fixed_array<T, F, const N: usize>(closure: F) -> [T; N]
where
    F: Fn(usize) -> T,
{
    let mut array: [MaybeUninit<T>; N] =
        unsafe { MaybeUninit::uninit().assume_init() };

    let mut index = 0;
    while index < N {
        array[index].write(closure(index));
        index += 1;
    }
    let array_ptr = array.as_ptr();

    unsafe { ptr::read(array_ptr.cast()) }
}

/// 计算某一层的节点容量（即该层可容纳的叶子数量分片基数）。
/// 对于 `A` 叉树，该值等于 `A^depth`，并被插入路径定位逻辑复用。
/// 该函数是 `const fn`，可在编译期参与容量相关常量表达式计算。
const fn level_capacity(arity: u64, depth: usize) -> u64 {
    #[allow(clippy::cast_possible_truncation)]
    u64::pow(arity, depth as u32)
}
