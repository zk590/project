use coset_bls12_381::{G1Affine, G1Projective};
use coset_bytes::{DeserializableSlice, Serializable};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct Commitment(
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)] pub(crate) G1Affine,
);

impl Commitment {
    /// 由底层仿射点构造承诺包装类型。
    #[inline]
    pub(crate) const fn new(point: G1Affine) -> Self {
        Self(point)
    }
}

impl From<G1Affine> for Commitment {
    /// 从仿射点构造承诺对象。
    /// 该转换不做额外计算，直接封装底层群元素。
    /// 常用于提交流程后将结果统一包装为协议类型。
    fn from(point: G1Affine) -> Commitment {
        Commitment::new(point)
    }
}

impl From<G1Projective> for Commitment {
    /// 从射影点构造承诺对象。
    /// 内部会先转换为仿射表示，再存入 `Commitment`。
    /// 适用于 MSM 累加结果等通常位于射影坐标的场景。
    fn from(point: G1Projective) -> Commitment {
        Commitment::new(point.into())
    }
}

impl Serializable<{ G1Affine::SIZE }> for Commitment {
    type Error = coset_bytes::Error;

    /// 将承诺编码为定长压缩字节。
    /// 输出长度由 `G1Affine::SIZE` 固定，便于网络与文件协议直接拼接。
    /// 编码结果可被 `from_bytes` 无歧义恢复。
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }

    /// 从定长字节恢复承诺对象。
    /// 底层会验证字节是否对应合法曲线点并处于正确子群。
    /// 解析失败返回错误，防止无效承诺进入验证逻辑。
    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let commitment_point = G1Affine::from_slice(buf)?;
        Ok(Self::new(commitment_point))
    }
}

impl Commitment {
    /// 返回群单位元承诺。
    /// 该值常用于初始化累加器或表示“空承诺”占位语义。
    /// 在群运算上它是加法单位，不改变后续叠加结果。
    fn identity() -> Commitment {
        Commitment::new(G1Affine::identity())
    }
}

impl Default for Commitment {
    /// 默认承诺取群单位元。
    /// 该实现让承诺类型可安全参与 `Default` 生态与容器初始化。
    /// 语义上等价于 `Commitment::identity()`。
    fn default() -> Commitment {
        Commitment::identity()
    }
}

#[cfg(test)]
mod commitment_tests {
    use super::*;

    #[test]
    fn commitment_coset_bytes_serde() {
        let commitment = Commitment(coset_bls12_381::G1Affine::generator());
        let bytes = commitment.to_bytes();
        let deserialized_commitment = Commitment::from_slice(&bytes)
            .expect("Error on the deserialization");
        assert_eq!(commitment, deserialized_commitment);
    }
}
