use core::ops::Add;

use subtle::Choice;

pub(crate) mod chain;

mod expand_msg;
pub use self::expand_msg::{
    ExpandMessage, ExpandMessageState, ExpandMsgXmd, ExpandMsgXof,
    InitExpandMessage,
};

mod map_g1;
mod map_g2;
mod map_scalar;

use crate::generic_array::{typenum::Unsigned, ArrayLength, GenericArray};

/// `HashToField` 定义“字节串到域元素”的标准映射接口。
/// 该接口对应 RFC 9380 中 hash_to_field 的抽象层，负责把扩展消息切片成固定块。
/// 后续 map-to-curve 与 cofactor 清理都会基于这里产出的域元素执行。
pub trait HashToField: Sized {
    /// 每个域元素所需输入块长度（字节）。
    /// 不同曲线/域参数对应不同长度，该类型级常量用于编译期约束缓冲区大小。
    /// 通过 `ArrayLength` 可在无堆分配前提下实现固定长度安全读写。
    type InputLength: ArrayLength<u8>;

    /// 将一段“均匀字节块（OKM）”映射为单个域元素。
    /// 具体实现通常包含字节序处理、模约简以及可能的域特定构造。
    /// 该函数是 hash_to_field 流程中的最小转换单元。
    fn from_okm(okm: &GenericArray<u8, Self::InputLength>) -> Self;

    /// 按标准流程把消息批量映射为域元素数组。
    /// 实现先通过 `ExpandMessage` 生成足够熵字节，再按 `InputLength` 分块喂给
    /// `from_okm`。 这种“扩展 + 分块 + 归约”流程是 hash-to-curve
    /// 安全性的基础前提之一。
    fn hash_to_field<X: ExpandMessage>(
        message: &[u8],
        dst: &[u8],
        output: &mut [Self],
    ) {
        let len_per_elm = Self::InputLength::to_usize();
        let len_in_bytes = output.len() * len_per_elm;
        let mut expander = X::init_expand(message, dst, len_in_bytes);

        let mut buf = GenericArray::<u8, Self::InputLength>::default();
        output.iter_mut().for_each(|item| {
            expander.read_into(&mut buf[..]);
            *item = Self::from_okm(&buf);
        });
    }
}

pub trait MapToCurve: Sized {
    type Field: Copy + Default + HashToField;

    /// 将域元素映射到曲线点（可能仍在扩展群，不一定在目标子群）。
    /// 常见实现包括 Simplified SWU 或 isogeny
    /// 路线，目标是获得确定且近似均匀的点。 该步骤不保证子群安全，
    /// 因此需要后续 `clear_h` 收尾。
    fn map_to_curve(elt: &Self::Field) -> Self;

    /// 对映射结果执行 cofactor 清理，投影到目标素数子群。
    /// 不做这一步会引入小子群点，可能破坏签名验证等协议安全性。
    /// 在 BLS12-381 等曲线上，cofactor 清理是标准规范必选步骤。
    fn clear_h(&self) -> Self;
}

pub trait HashToCurve<X: ExpandMessage>:
    MapToCurve + for<'a> Add<&'a Self, Output = Self>
{
    /// 完整的 `hash_to_curve` 流程：两次 map-to-curve 后相加，再做 cofactor
    /// 清理。 两次采样可改善统计性质并对齐 RFC 推荐流程（random-oracle
    /// 风格）。 该函数通常用于签名消息映射、
    /// 群元素挑战构造等核心密码学路径。
    fn hash_to_curve(message: impl AsRef<[u8]>, dst: &[u8]) -> Self {
        let mut u = [Self::Field::default(); 2];
        Self::Field::hash_to_field::<X>(message.as_ref(), dst, &mut u);
        let p1 = Self::map_to_curve(&u[0]);
        let p2 = Self::map_to_curve(&u[1]);
        (p1 + &p2).clear_h()
    }

    /// `encode_to_curve` 单次采样版本，流程更轻量但随机预言机强度低于
    /// `hash_to_curve`。 它仍包含 cofactor 清理，因此输出点在目标子群内。
    /// 适用于对性能敏感且协议允许 encode-to-curve 语义的场景。
    fn encode_to_curve(message: impl AsRef<[u8]>, dst: &[u8]) -> Self {
        let mut u = [Self::Field::default(); 1];
        Self::Field::hash_to_field::<X>(message.as_ref(), dst, &mut u);
        let p = Self::map_to_curve(&u[0]);
        p.clear_h()
    }
}

impl<G, X> HashToCurve<X> for G
where
    G: MapToCurve + for<'a> Add<&'a Self, Output = Self>,
    X: ExpandMessage,
{
}

pub(crate) trait Sgn0 {
    /// 返回元素的符号位（`sgn0`），用于 map-to-curve 中的符号约定与分支规范化。
    /// 该符号函数必须与域表示保持一致，否则会导致跨实现结果不一致。
    /// 在哈希到曲线算法中，`sgn0` 常用于保证输出点编码的确定性。
    fn sgn0(&self) -> Choice;
}
