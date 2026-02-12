//! 配对预处理结构 `G2Prepared` 的扩展编解码支持。
//! 提供原始字节快照接口与 serde 结构化序列化接口。
//! 主要服务于受信缓存、跨进程序列化和测试回归场景。

use crate::fp::Fp;
use crate::fp2::Fp2;

use super::G2Prepared;

use alloc::vec::Vec;

impl G2Prepared {
    /// 将 `G2Prepared` 的 Miller 系数按内部原始布局导出为字节序列。
    /// 每个系数三元组 `(a,b,c)` 展开为多个 `Fp` limb，并统一按 little-endian
    /// 写出。 该格式主要用于受信环境下的快速缓存与回放，
    /// 不等同于标准外部协议编码。
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        let mut bytes = alloc::vec![0u8; 288 * self.coeffs.len()];
        let mut chunks = bytes.chunks_exact_mut(8);

        self.coeffs.iter().for_each(|(a, b, c)| {
            a.c0.internal_repr()
                .iter()
                .chain(a.c1.internal_repr().iter())
                .chain(b.c0.internal_repr().iter())
                .chain(b.c1.internal_repr().iter())
                .chain(c.c0.internal_repr().iter())
                .chain(c.c1.internal_repr().iter())
                .for_each(|n| {
                    if let Some(c) = chunks.next() {
                        c.copy_from_slice(&n.to_le_bytes())
                    }
                })
        });

        bytes
    }

    /// 从原始字节切片恢复 `G2Prepared`，不做数学合法性与结构一致性检查。
    /// 调用者需保证字节长度与字段布局正确，否则结果可能是无效内部状态。
    /// 该接口被标记为 `unsafe`，用于高性能场景下的“已验证输入”快速反序列化。
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let coeffs = bytes
            .chunks_exact(288)
            .map(|c| {
                let mut ac0 = [0u64; 6];
                let mut ac1 = [0u64; 6];
                let mut bc0 = [0u64; 6];
                let mut bc1 = [0u64; 6];
                let mut cc0 = [0u64; 6];
                let mut cc1 = [0u64; 6];
                let mut z = [0u8; 8];

                ac0.iter_mut()
                    .chain(ac1.iter_mut())
                    .chain(bc0.iter_mut())
                    .chain(bc1.iter_mut())
                    .chain(cc0.iter_mut())
                    .chain(cc1.iter_mut())
                    .zip(c.chunks_exact(8))
                    .for_each(|(n, c)| {
                        z.copy_from_slice(c);
                        *n = u64::from_le_bytes(z);
                    });

                let c0 = Fp::from_raw_unchecked(ac0);
                let c1 = Fp::from_raw_unchecked(ac1);
                let a = Fp2 { c0, c1 };

                let c0 = Fp::from_raw_unchecked(bc0);
                let c1 = Fp::from_raw_unchecked(bc1);
                let b = Fp2 { c0, c1 };

                let c0 = Fp::from_raw_unchecked(cc0);
                let c1 = Fp::from_raw_unchecked(cc1);
                let c = Fp2 { c0, c1 };

                (a, b, c)
            })
            .collect();
        let infinity = 0u8.into();

        Self { coeffs, infinity }
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    use serde::de::{Error as SerdeError, MapAccess, Visitor};
    use serde::ser::SerializeStruct;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    use super::*;
    use crate::coset::choice::Choice;

    impl Serialize for G2Prepared {
        /// 将 `G2Prepared` 序列化为结构化对象 `{ infinity, coeffs }`。
        /// 这种字段化表示可读性更好，也便于不同语言实现按键名解码。
        /// 其中 `infinity` 采用基础整数表示，避免常量时间类型跨边界歧义。
        fn serialize<S: Serializer>(
            &self,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let mut ser_struct =
                serializer.serialize_struct("G2Prepared", 2)?;
            ser_struct
                .serialize_field("infinity", &self.infinity.unwrap_u8())?;
            ser_struct.serialize_field("coeffs", &self.coeffs)?;
            ser_struct.end()
        }
    }

    impl<'de> Deserialize<'de> for G2Prepared {
        /// 从结构化对象反序列化 `G2Prepared`。
        /// 实现通过自定义 Visitor 精确控制字段去重、缺失与未知字段错误语义。
        /// 该策略可提升输入鲁棒性，并保证反序列化错误信息可诊断。
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            struct G2PreparedVisitor;

            const FIELDS: &[&str] = &["infinity", "coeffs"];

            impl<'de> Visitor<'de> for G2PreparedVisitor {
                type Value = G2Prepared;

                /// 声明该 Visitor 期望的输入结构描述。
                /// serde 在报错时会引用该描述，帮助调用者快速定位格式问题。
                /// 对复杂结构类型，清晰的 expecting 文本能显著改善可维护性。
                fn expecting(
                    &self,
                    formatter: &mut ::core::fmt::Formatter,
                ) -> ::core::fmt::Result {
                    formatter
                        .write_str("a struct a with fields infinity and coeffs")
                }

                /// 逐字段解析 map 输入并构造 `G2Prepared`。
                /// 该过程显式处理重复字段、未知字段、缺失字段三类常见输入异常。
                /// 解析完成后再统一构造目标对象，保证状态完整性与错误可追踪性。
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut infinity: Option<u8> = None;
                    let mut coeffs = None;
                    while let Some(key) = map.next_key()? {
                        match key {
                            "infinity" => {
                                if infinity.is_some() {
                                    return Err(SerdeError::duplicate_field(
                                        "infinity",
                                    ));
                                } else {
                                    infinity = Some(map.next_value()?);
                                }
                            }
                            "coeffs" => {
                                if coeffs.is_some() {
                                    return Err(SerdeError::duplicate_field(
                                        "coeffs",
                                    ));
                                } else {
                                    coeffs = Some(map.next_value()?);
                                }
                            }
                            field => {
                                return Err(SerdeError::unknown_field(
                                    field, &FIELDS,
                                ))
                            }
                        }
                    }
                    Ok(G2Prepared {
                        infinity: Choice::from(infinity.ok_or_else(|| {
                            SerdeError::missing_field("infinity")
                        })?),
                        coeffs: coeffs.ok_or_else(|| {
                            SerdeError::missing_field("coeffs")
                        })?,
                    })
                }
            }

            deserializer.deserialize_struct(
                "G2Prepared",
                FIELDS,
                G2PreparedVisitor,
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use alloc::boxed::Box;

        use super::*;
        use crate::coset::test_utils;
        use crate::G2Affine;

        #[test]
        /// 验证 `G2Prepared` 的 serde 往返一致性。
        /// 使用固定 JSON 向量可同时验证结构格式和字段内容的稳定性。
        /// 对配对预处理缓存而言，稳定序列化是跨版本兼容的重要保障。
        fn serde_g2_prepared() -> Result<(), Box<dyn std::error::Error>> {
            let g2_prepared = G2Prepared::from(G2Affine::generator());
            let ser = test_utils::assert_canonical_json(
                &g2_prepared,
                include_str!("./g2_prepared.json"),
            )?;
            let deser: G2Prepared = serde_json::from_str(&ser).unwrap();

            assert_eq!(g2_prepared.coeffs, deser.coeffs);
            assert_eq!(
                g2_prepared.infinity.unwrap_u8(),
                deser.infinity.unwrap_u8()
            );
            Ok(())
        }
    }
}

#[test]
/// 验证 `G2Prepared` 原始字节编解码（unchecked）在受信输入下的可逆性。
/// 该测试比较的是系数字段内容，确保内部布局写回后不发生错位。
/// 其目标是守住缓存快照路径的二进制稳定性，而非验证数学合法性。
fn g2_prepared_bytes_unchecked() {
    use crate::G2Affine;

    let g2_prepared = G2Prepared::from(G2Affine::generator());
    let bytes = g2_prepared.to_raw_bytes();

    let g2_prepared_p = unsafe { G2Prepared::from_slice_unchecked(&bytes) };

    assert_eq!(g2_prepared.coeffs, g2_prepared_p.coeffs);
}
