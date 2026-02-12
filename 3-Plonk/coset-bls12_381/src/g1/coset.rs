use coset_bytes::{Error as BytesError, Serializable};
use subtle::{Choice, ConditionallySelectable, CtOption};

use super::{G1Affine, B};
use crate::fp::Fp;

impl G1Affine {
    pub const RAW_SIZE: usize = 97;

    /// 将 `G1Affine` 按内部原始表示导出为字节数组（含 infinity 标记）。
    /// 该编码主要面向内部调试、快速快照和不做合法性检查的互操作场景。
    /// 与压缩格式不同，此处直接写出坐标 limb，强调“可逆与高效”而非标准化传输。
    pub fn to_raw_bytes(&self) -> [u8; Self::RAW_SIZE] {
        let mut bytes = [0u8; Self::RAW_SIZE];
        let chunks = bytes.chunks_mut(8);

        self.x
            .internal_repr()
            .iter()
            .chain(self.y.internal_repr().iter())
            .zip(chunks)
            .for_each(|(n, c)| c.copy_from_slice(&n.to_le_bytes()));

        bytes[Self::RAW_SIZE - 1] = self.infinity.into();

        bytes
    }

    /// 从原始字节切片恢复 `G1Affine`，不执行曲线合法性与子群检查。
    /// 调用者必须保证输入布局正确，否则可能构造出无效点并破坏后续安全假设。
    /// 该接口适用于受信边界内的高性能路径，因此以 `unsafe` 暴露前置条件。
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut x = [0u64; 6];
        let mut y = [0u64; 6];
        let mut z = [0u8; 8];

        bytes
            .chunks_exact(8)
            .zip(x.iter_mut().chain(y.iter_mut()))
            .for_each(|(c, n)| {
                z.copy_from_slice(c);
                *n = u64::from_le_bytes(z);
            });

        let x = Fp::from_raw_unchecked(x);
        let y = Fp::from_raw_unchecked(y);

        let infinity = if bytes.len() >= Self::RAW_SIZE {
            bytes[Self::RAW_SIZE - 1].into()
        } else {
            0u8.into()
        };

        Self { x, y, infinity }
    }
}

impl Serializable<48> for G1Affine {
    type Error = BytesError;

    /// 按 BLS12-381 G1 压缩格式编码点到 48 字节。
    /// 编码时会写入压缩位、无穷远点位与符号位，并在无穷远点时规范化 x=0。
    /// 该格式是跨实现通用协议格式，适合网络与磁盘持久化。
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut res =
            Fp::conditional_select(&self.x, &Fp::zero(), self.infinity.into())
                .to_bytes();

        res[0] |= 1u8 << 7;

        res[0] |=
            u8::conditional_select(&0u8, &(1u8 << 6), self.infinity.into());

        res[0] |= u8::conditional_select(
            &0u8,
            &(1u8 << 5),
            (!Choice::from(self.infinity)) & self.y.lexicographically_largest(),
        );

        res
    }

    /// 从 48 字节压缩表示解码 `G1Affine` 并执行完整合法性校验。
    /// 过程包括标志位解析、平方根恢复 y、扭子群过滤（torsion-free）等步骤。
    /// 若任一条件不满足，返回 `InvalidData`，防止无效点进入密码学流程。
    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let compression_flag_set = Choice::from((buf[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((buf[0] >> 6) & 1);
        let sort_flag_set = Choice::from((buf[0] >> 5) & 1);

        let x = {
            let mut tmp = [0; Self::SIZE];
            tmp.copy_from_slice(&buf[..Self::SIZE]);

            tmp[0] &= 0b0001_1111;

            Fp::from_bytes(&tmp)
        };

        let x: Option<Self> = x
            .and_then(|x| {
                // 先匹配“无穷远点压缩编码”，否则按曲线方程恢复 y 并继续校验。

                CtOption::new(
                    G1Affine::identity(),
                    infinity_flag_set
                        & compression_flag_set
                        & (!sort_flag_set)
                        & x.is_zero(),
                )
                .or_else(|| {
                    ((x.square() * x) + B).sqrt().and_then(|y| {
                        let y = Fp::conditional_select(
                            &y,
                            &-y,
                            y.lexicographically_largest() ^ sort_flag_set,
                        );

                        CtOption::new(
                            G1Affine {
                                x,
                                y,
                                infinity: infinity_flag_set.into(),
                            },
                            (!infinity_flag_set) & compression_flag_set,
                        )
                    })
                })
            })
            .and_then(|p| CtOption::new(p, p.is_torsion_free()))
            .into();

        x.ok_or(BytesError::InvalidData)
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

    impl Serialize for G1Affine {
        /// 将 `G1Affine` 序列化为十六进制字符串。
        /// 文本表示便于 JSON 传输和人工审阅，同时保留二进制精确性。
        /// 底层编码复用压缩点格式，确保与其他实现保持兼容。
        fn serialize<S: Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let s = hex::encode(self.to_bytes());
            s.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for G1Affine {
        /// 从十六进制字符串反序列化 `G1Affine`。
        /// 先做 hex 解码与长度校验，再调用曲线安全解码逻辑恢复点。
        /// 该路径会保留所有安全检查，避免接受非法或非子群点。
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            let s = String::deserialize(deserializer)?;
            let decoded = hex::decode(&s).map_err(SerdeError::custom)?;
            let decoded_len = decoded.len();
            let bytes: [u8; G1Affine::SIZE] =
                decoded.try_into().map_err(|_| {
                    SerdeError::invalid_length(
                        decoded_len,
                        &G1Affine::SIZE.to_string().as_str(),
                    )
                })?;
            let affine = G1Affine::from_bytes(&bytes)
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
        /// 验证 `G1Affine` 的 serde 往返一致性。
        /// 测试同时固定了 canonical JSON 字符串，防止输出格式回归漂移。
        /// 对链上/链下协议而言，稳定序列化是兼容性的关键前提。
        fn serde_g1_affine() -> Result<(), Box<dyn std::error::Error>> {
            let gen = G1Affine::generator();
            let ser = test_utils::assert_canonical_json(
                &gen,
                "\"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb\""
            )?;
            let deser: G1Affine = serde_json::from_str(&ser).unwrap();
            assert_eq!(gen, deser);
            Ok(())
        }

        #[test]
        /// 验证过短编码在反序列化阶段会被拒绝。
        /// 该用例确保长度检查路径被覆盖，避免截断数据被误解析。
        /// 严格输入长度是密码学数据边界校验的重要组成部分。
        fn serde_g1_affine_too_short_encoded() {
            let length_47_enc = "\"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6\"";

            let g1_affine: Result<G1Affine, _> =
                serde_json::from_str(&length_47_enc);
            assert!(g1_affine.is_err());
        }

        #[test]
        /// 验证过长编码在反序列化阶段会被拒绝。
        /// 该测试用于防止“多余尾字节”造成协议歧义或兼容问题。
        /// 对固定长度曲线点编码，长度约束必须是强约束而非建议。
        fn serde_g1_affine_too_long_encoded() {
            let length_49_enc = "\"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00\"";

            let g1_affine: Result<G1Affine, _> =
                serde_json::from_str(&length_49_enc);
            assert!(g1_affine.is_err());
        }
    }
}

#[test]
/// 测试原始字节编解码（unchecked）对生成元与无穷远点的可逆性。
/// 该测试不验证曲线合法性，仅验证内部布局读写的一致性。
/// 适合保障内部快照格式在重构后仍保持二进制兼容。
fn g1_affine_bytes_unchecked() {
    let gen = G1Affine::generator();
    let ident = G1Affine::identity();

    let gen_p = gen.to_raw_bytes();
    let gen_p = unsafe { G1Affine::from_slice_unchecked(&gen_p) };

    let ident_p = ident.to_raw_bytes();
    let ident_p = unsafe { G1Affine::from_slice_unchecked(&ident_p) };

    assert_eq!(gen, gen_p);
    assert_eq!(ident, ident_p);
}

#[test]
/// 测试任意字段坐标构造点的 raw 编解码可逆性。
/// 该用例覆盖非生成元输入，确保通用坐标路径不会发生字节错位。
/// 对内部调试工具而言，这种“结构可逆”性质非常关键。
fn g1_affine_bytes_unchecked_field() {
    let x = Fp::from_raw_unchecked([
        0x9af1f35780fffb82,
        0x557416ceeea5a52f,
        0x1e4403e4911a2d97,
        0xb85bfb438316bf2,
        0xa3b716c69a9e5a7b,
        0x1fe9b8ad976dd39,
    ]);

    let y = Fp::from_raw_unchecked([
        0xb4f1cc806acfb4e2,
        0x38c28cba4cf600ed,
        0x3af1c2f54a01a366,
        0x96a75ac708a9eb72,
        0x4253bd59228e50d,
        0x120114fae4294c21,
    ]);

    let infinity = 0u8.into();
    let g = G1Affine { x, y, infinity };

    let g_p = g.to_raw_bytes();
    let g_p = unsafe { G1Affine::from_slice_unchecked(&g_p) };

    assert_eq!(g, g_p);
}
