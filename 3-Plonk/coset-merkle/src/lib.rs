
#![no_std] //声明该 crate 不使用标准库，适用于嵌入式或资源受限环境
#![deny(clippy::pedantic)] //启用 Clippy 的严格检查规则

extern crate alloc; //导入 alloc crate，用于在无标准库环境中提供内存分配功能

use core::mem::MaybeUninit; //导入 MaybeUninit 类型，用于安全地处理未初始化的内存
use core::ptr; //导入 ptr 模块，用于原始指针操作

mod node; //声明 node 模块，包含节点相关实现
mod opening; //声明 opening 模块，包含 Merkle 证明相关实现
mod tree;   //声明 tree 模块，包含 Merkle 树相关实现
mod walk; //声明 walk 模块，包含 Merkle 树遍历相关实现

pub use node::*;    //将 node 模块中的所有公共项（pub）导出，允许外部代码使用
pub use opening::*; //将 opening 模块中的所有公共项（pub）导出，允许外部代码使用
pub use tree::*; //将 tree 模块中的所有公共项（pub）导出，允许外部代码使用
pub use walk::*; //将 walk 模块中的所有公共项（pub）导出，允许外部代码使用


/// 定义 Aggregate  trait，用于聚合 A 个 Self 类型的实例
pub trait Aggregate<const A: usize> { 

    /// 定义 trait 关联常量 EMPTY_SUBTREE，用于表示空子树的默认值
    const EMPTY_SUBTREE: Self; 


    /// 定义 trait 方法 aggregate，用于聚合 A 个 Self 类型的实例
    fn aggregate(items: [&Self; A]) -> Self; 
}


/// 实现 Aggregate  trait 为 () 类型，用于聚合 0 个实例
impl<const A: usize> Aggregate<A> for () {
    const EMPTY_SUBTREE: Self = ();
    fn aggregate(_: [&Self; A]) -> Self {}
}

/**
 定义内部函数 init_array，用于初始化固定大小的数组
T 是数组元素类型
F 是闭包类型
N 是数组大小的常量泛型
 */
pub(crate) fn init_array<T, F, const N: usize>(closure: F) -> [T; N]
where //开始定义泛型约束
    F: Fn(usize) -> T, //约束闭包 F 接收一个 usize 参数并返回 T 类型
{
    //声明一个 MaybeUninit 类型的数组
    let mut array: [MaybeUninit<T>; N] =  
    // 不安全操作，创建未初始化的数组
        unsafe { MaybeUninit::uninit().assume_init() };

    let mut index = 0;
    while index < N {
        array[index].write(closure(index)); //调用闭包初始化第 i 个元素
        index += 1;
    }
    //获取数组的原始指针
    let array_ptr = array.as_ptr();



    unsafe { ptr::read(array_ptr.cast()) }
}


/// 说明返回树中给定深度的节点容量
/// 输入参数：
/// arity：树的基数，即每个节点的子节点数量，也就是分叉度
/// depth：节点的深度，根节点深度为 0
/// 返回值：
/// 返回树中给定深度的节点容量，即 arity 的 depth 次幂
const fn capacity(arity: u64, depth: usize) -> u64 {


    #[allow(clippy::cast_possible_truncation)]
    u64::pow(arity, depth as u32)
}
