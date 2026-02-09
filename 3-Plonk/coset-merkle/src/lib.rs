
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


/// 定义 Aggregate  trait，用于聚合 A 个 Self 类型的实例
pub trait Aggregate<const A: usize> { 

    
    const EMPTY_SUBTREE: Self; 

    fn aggregate(items: [&Self; A]) -> Self; 
}


/// 实现 Aggregate  trait 为 () 类型，用于聚合 0 个实例
impl<const A: usize> Aggregate<A> for () {
    const EMPTY_SUBTREE: Self = ();
    fn aggregate(_: [&Self; A]) -> Self {}
}

/**
 定义内部函数 init_fixed_array，用于初始化固定大小的数组
T 是数组元素类型
F 是闭包类型
N 是数组大小的常量泛型
 */
pub(crate) fn init_fixed_array<T, F, const N: usize>(closure: F) -> [T; N]
where //开始定义泛型约束
    F: Fn(usize) -> T, //约束闭包 F 接收一个 usize 参数并返回 T 类型
{
    //声明一个 MaybeUninit 类型的数组
    let mut array: [MaybeUninit<T>; N] =  
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
const fn level_capacity(arity: u64, depth: usize) -> u64 {


    #[allow(clippy::cast_possible_truncation)]
    u64::pow(arity, depth as u32)
}
