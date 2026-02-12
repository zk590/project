use core::convert::Infallible;

use coset_bytes::Serializable;
use subtle::ConditionallySelectable;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize,
};

#[derive(Copy, Clone, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, RkyvSerialize, RkyvDeserialize),
    archive_attr(derive(CheckBytes))
)]
pub struct Choice(u8);

impl Choice {
    /// 返回内部存储的原始 `u8` 比特值。
    /// 该方法主要用于与第三方 API 交互，或在调试时观察底层常量时间布尔位。
    /// 在密码学代码中显式读取底层值时，应注意避免引入数据相关分支。
    pub fn unwrap_u8(&self) -> u8 {
        self.0
    }
}

impl ConditionallySelectable for Choice {
    /// 常量时间地从 `a` 与 `b` 中选择一个值。
    /// 该实现复用 `u8::conditional_select`，避免使用普通 `if` 造成时序侧信道。
    /// 对密码学条件分支而言，常量时间选择是基础安全构件之一。
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        Self(u8::conditional_select(&a.0, &b.0, choice))
    }
}

impl Serializable<1> for Choice {
    type Error = Infallible;

    /// 从固定长度字节数组恢复 `Choice`。
    /// 该类型的序列化大小固定为 1 字节，因此直接取第 0 字节即可。
    /// 由于不存在无效编码，反序列化错误类型使用 `Infallible`。
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self(bytes[0]))
    }

    /// 将 `Choice` 编码为固定长度 1 字节数组。
    /// 该表示与内部存储保持一一对应，适合做跨进程或跨网络传输。
    /// 固定长度编码也便于与 `Serializable` 生态中其他类型统一处理。
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        [self.0; Self::SIZE]
    }
}

impl From<u8> for Choice {
    /// 从原始 `u8` 构造 `Choice` 包装类型。
    /// 该转换不强制约束输入值必须为 `0/1`，由上层语义自行保证。
    /// 保留宽松输入有利于兼容历史数据与外部协议格式。
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<Choice> for u8 {
    /// 将 `Choice` 转回底层 `u8`。
    /// 该转换是零成本读取，不涉及额外分配或格式变换。
    /// 常用于日志、调试输出或需要原始位值的桥接代码。
    fn from(choice_value: Choice) -> Self {
        choice_value.0
    }
}

impl From<subtle::Choice> for Choice {
    /// 将 `subtle::Choice` 适配为本模块定义的 `Choice`。
    /// 两者都承担常量时间布尔语义，此处仅做类型层转换。
    /// 保持这个适配层可降低模块间耦合，便于后续替换底层实现。
    fn from(subtle_choice: subtle::Choice) -> Self {
        Self(subtle_choice.unwrap_u8())
    }
}

impl From<Choice> for subtle::Choice {
    /// 将本地 `Choice` 转换回 `subtle::Choice`。
    /// 该方向转换用于调用 `subtle` 提供的常量时间比较与选择工具。
    /// 通过显式转换可避免在泛型上下文中出现歧义推断。
    fn from(choice_value: Choice) -> Self {
        subtle::Choice::from(choice_value.0)
    }
}

impl From<Choice> for bool {
    /// 将 `Choice` 投影为普通 `bool`。
    /// 该操作会进入非密码学语义空间，可能导致后续分支不是常量时间。
    /// 因此建议仅在测试、日志或业务边界层使用该转换。
    fn from(choice_value: Choice) -> Self {
        subtle::Choice::from(choice_value.0).into()
    }
}
