//! G2 点的字节编解码扩展（raw + 压缩格式）。
//! 本文件补充了内部快照用 raw 编码与协议兼容压缩编码。
//! 同时提供 serde 文本序列化桥接，方便 JSON 场景互操作。

use coset_bytes::{Error as BytesError, Serializable};
use subtle::{Choice, ConditionallySelectable, CtOption};

use super::{G2Affine, B};
use crate::fp::Fp;
use crate::fp2::Fp2;

impl G2Affine {
    /// 将 `G2Affine` 按内部原始布局导出为字节数组（含 infinity 标记）。
    /// 该格式强调“可逆与高效”，适合受信边界内的调试快照或本地缓存。
    /// 与标准压缩点编码不同，此格式不面向跨实现协议传输。
    pub fn to_raw_bytes(&self) -> [u8; Self::RAW_SIZE] {
        let mut bytes = [0u8; Self::RAW_SIZE];
        let chunks = bytes.chunks_mut(8);

        self.x
            .c0
            .internal_repr()
            .iter()
            .chain(self.x.c1.internal_repr().iter())
            .chain(self.y.c0.internal_repr().iter())
            .chain(self.y.c1.internal_repr().iter())
            .zip(chunks)
            .for_each(|(n, c)| c.copy_from_slice(&n.to_le_bytes()));

        bytes[Self::RAW_SIZE - 1] = self.infinity.into();

        bytes
    }

    /// 从原始字节切片恢复 `G2Affine`，不执行曲线与子群合法性检查。
    /// 调用者必须确保输入布局、长度和来源可信，否则可能得到无效点。
    /// 该接口以 `unsafe` 暴露，用于高性能内部路径。
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut xc0 = [0u64; 6];
        let mut xc1 = [0u64; 6];
        let mut yc0 = [0u64; 6];
        let mut yc1 = [0u64; 6];
        let mut z = [0u8; 8];

        xc0.iter_mut()
            .chain(xc1.iter_mut())
            .chain(yc0.iter_mut())
            .chain(yc1.iter_mut())
            .zip(bytes.chunks_exact(8))
            .for_each(|(n, c)| {
                z.copy_from_slice(c);
                *n = u64::from_le_bytes(z);
            });

        let c0 = Fp::from_raw_unchecked(xc0);
        let c1 = Fp::from_raw_unchecked(xc1);
        let x = Fp2 { c0, c1 };

        let c0 = Fp::from_raw_unchecked(yc0);
        let c1 = Fp::from_raw_unchecked(yc1);
        let y = Fp2 { c0, c1 };

        let infinity = if bytes.len() >= Self::RAW_SIZE {
            bytes[Self::RAW_SIZE - 1].into()
        } else {
            0u8.into()
        };

        Self { x, y, infinity }
    }
}

impl Serializable<96> for G2Affine {
    type Error = BytesError;

    /// 按 BLS12-381 G2 压缩规范编码为 96 字节。
    /// 输出会设置压缩位、无穷远点位与符号位，并在无穷远点时规范化坐标。
    /// 该表示用于跨实现传输，是推荐的协议级格式。
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let infinity = self.infinity.into();

        let x = Fp2::conditional_select(&self.x, &Fp2::zero(), infinity);

        let mut res = [0; Self::SIZE];

        (res[0..48]).copy_from_slice(&x.c1.to_bytes()[..]);
        (res[48..96]).copy_from_slice(&x.c0.to_bytes()[..]);

        res[0] |= 1u8 << 7;

        res[0] |= u8::conditional_select(&0u8, &(1u8 << 6), infinity);

        res[0] |= u8::conditional_select(
            &0u8,
            &(1u8 << 5),
            (!infinity) & self.y.lexicographically_largest(),
        );

        res
    }

    /// 从 96 字节压缩编码解码 `G2Affine` 并进行安全校验。
    /// 解码流程包括标志位解析、平方根恢复 y、无穷远点规则验证等步骤。
    /// 最终还会校验扭子群条件，不满足则返回 `InvalidData`。
    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let compression_flag_set = Choice::from((buf[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((buf[0] >> 6) & 1);
        let sort_flag_set = Choice::from((buf[0] >> 5) & 1);

        let xc1 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&buf[0..48]);

            tmp[0] &= 0b0001_1111;

            Fp::from_bytes(&tmp)
        };
        let xc0 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&buf[48..96]);

            Fp::from_bytes(&tmp)
        };

        let x: Option<Self> = xc1
            .and_then(|xc1| {
                xc0.and_then(|xc0| {
                    let x = Fp2 { c0: xc0, c1: xc1 };

                    CtOption::new(
                        G2Affine::identity(),
                        infinity_flag_set
                            & compression_flag_set
                            & (!sort_flag_set)
                            & x.is_zero(),
                    )
                    .or_else(|| {
                        ((x.square() * x) + B).sqrt().and_then(|y| {
                            let y = Fp2::conditional_select(
                                &y,
                                &-y,
                                y.lexicographically_largest() ^ sort_flag_set,
                            );

                            CtOption::new(
                                G2Affine {
                                    x,
                                    y,
                                    infinity: infinity_flag_set.into(),
                                },
                                (!infinity_flag_set) & compression_flag_set,
                            )
                        })
                    })
                })
            })
            .into();

        match x {
            Some(x) if x.is_torsion_free().unwrap_u8() == 1 => Ok(x),
            _ => Err(BytesError::InvalidData),
        }
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    extern crate alloc;

    use alloc::format;
    use alloc::string::{String, ToString};

    use serde::de::Error as SerdeError;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for G2Affine {
        /// 将 `G2Affine` 序列化为十六进制字符串。
        /// 文本形式便于 JSON 传输、日志记录与人工排查。
        /// 底层仍复用压缩编码，保证跨实现兼容性。
        fn serialize<S: Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let s = hex::encode(self.to_bytes());
            s.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for G2Affine {
        /// 从十六进制字符串反序列化 `G2Affine`。
        /// 过程包含 hex 解码、固定长度校验和曲线安全解码。
        /// 任一环节失败都会返回错误，防止非法点进入后续流程。
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            let s = String::deserialize(deserializer)?;
            let decoded = hex::decode(&s).map_err(SerdeError::custom)?;
            let decoded_len = decoded.len();
            let bytes: [u8; G2Affine::SIZE] =
                decoded.try_into().map_err(|_| {
                    SerdeError::invalid_length(
                        decoded_len,
                        &G2Affine::SIZE.to_string().as_str(),
                    )
                })?;
            let affine = G2Affine::from_bytes(&bytes)
                .map_err(|err| SerdeError::custom(format!("{err:?}")))?;
            Ok(affine)
        }
    }

    #[cfg(test)]
    mod tests {
        use alloc::boxed::Box;

        use super::*;
        use crate::coset::test_utils;

        #[test]
        /// 验证 G2 点 serde 往返的一致性与 canonical 表示稳定性。
        /// 该测试固定了期望 JSON 字符串，防止序列化格式漂移。
        /// 对跨组件协议兼容而言，稳定编码非常关键。
        fn serde_g2_affine() -> Result<(), Box<dyn std::error::Error>> {
            let gen = G2Affine::generator();
            let ser = test_utils::assert_canonical_json(
                &gen,
                "\"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8\""
            )?;
            let deser: G2Affine = serde_json::from_str(&ser).unwrap();
            assert_eq!(gen, deser);
            Ok(())
        }

        #[test]
        /// 验证过短编码会在反序列化阶段被拒绝。
        /// 该用例覆盖输入长度下界，防止截断数据被误解析。
        /// 固定长度约束是密码学数据边界检查的基本要求。
        fn serde_g2_affine_too_short_encoded() {
            let length_95_enc: &str = "\"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bd\"";

            let g2_affine: Result<G2Affine, _> =
                serde_json::from_str(&length_95_enc);
            assert!(g2_affine.is_err());
        }

        #[test]
        /// 验证过长编码会在反序列化阶段被拒绝。
        /// 该测试防止“合法前缀 + 垃圾尾部”造成语义歧义。
        /// 对点编码协议来说，长度必须是强约束而非建议。
        fn serde_g2_affine_too_long_encoded() {
            let length_97_enc = "\"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb800\"";

            let g2_affine: Result<G2Affine, _> =
                serde_json::from_str(&length_97_enc);
            assert!(g2_affine.is_err());
        }
    }
}

#[test]
/// 测试 raw（unchecked）编解码对生成元与无穷远点的可逆性。
/// 该测试只关注内部布局稳定性，不覆盖曲线合法性约束。
/// 用于保障本地快照格式在重构后的二进制兼容。
fn g2_affine_bytes_unchecked() {
    let gen = G2Affine::generator();
    let ident = G2Affine::identity();

    let gen_p = gen.to_raw_bytes();
    let gen_p = unsafe { G2Affine::from_slice_unchecked(&gen_p) };

    let ident_p = ident.to_raw_bytes();
    let ident_p = unsafe { G2Affine::from_slice_unchecked(&ident_p) };

    assert_eq!(gen, gen_p);
    assert_eq!(ident, ident_p);
}
