//! Fp2 在 serde 场景下的结构化编解码支持。
//! 本模块将 Fp2 表示为具名字段 `{c0, c1}`，便于 JSON 互操作。
//! 同时通过测试固定 canonical 形式，避免格式漂移。

use super::Fp2;

#[cfg(feature = "serde")]
mod serde_support {
    use serde::de::{Error as SerdeError, MapAccess, Visitor};
    use serde::ser::SerializeStruct;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for Fp2 {
        /// 将 Fp2 序列化为结构体 `{c0, c1}`。
        /// 该格式相比单字符串更直观，便于调试与跨语言映射。
        /// 每个分量仍复用 Fp 的安全序列化逻辑。
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut struct_ser = serializer.serialize_struct("Fp2", 2)?;
            struct_ser.serialize_field("c0", &self.c0)?;
            struct_ser.serialize_field("c1", &self.c1)?;
            struct_ser.end()
        }
    }

    impl<'de> Deserialize<'de> for Fp2 {
        /// 从结构体 `{c0, c1}` 反序列化 Fp2。
        /// 过程会显式检查重复字段、缺失字段与未知字段，保证输入严格性。
        /// 任一约束不满足都会返回结构化反序列化错误。
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct Fp2Visitor;

            const FIELDS: &[&str] = &["c0", "c1"];

            impl<'de> Visitor<'de> for Fp2Visitor {
                type Value = Fp2;

                /// 描述该 Visitor 期望接收的数据形态。
                /// 错误信息会引用此文本，帮助调用方快速定位输入格式问题。
                /// 这里明确要求是包含 `c0/c1` 的结构体对象。
                fn expecting(
                    &self,
                    formatter: &mut ::core::fmt::Formatter,
                ) -> ::core::fmt::Result {
                    formatter.write_str("a struct with fields c0 and c1")
                }

                /// 访问 map 并逐项解析 Fp2 字段。
                /// 该实现显式处理重复键、未知键和缺失键，
                /// 避免宽松解析带来的歧义。 最终仅在 `c0` 与
                /// `c1` 都合法存在时构造目标对象。
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Self::Value, A::Error> {
                    let (mut c0, mut c1) = (None, None);
                    while let Some(key) = map.next_key()? {
                        match key {
                            "c0" => {
                                if c0.is_some() {
                                    return Err(SerdeError::duplicate_field(
                                        "c0",
                                    ));
                                } else {
                                    c0 = Some(map.next_value()?);
                                }
                            }
                            "c1" => {
                                if c1.is_some() {
                                    return Err(SerdeError::duplicate_field(
                                        "c1",
                                    ));
                                } else {
                                    c1 = Some(map.next_value()?);
                                }
                            }
                            field => {
                                return Err(SerdeError::unknown_field(
                                    field, &FIELDS,
                                ))
                            }
                        }
                    }
                    Ok(Fp2 {
                        c0: c0
                            .ok_or_else(|| SerdeError::missing_field("c0"))?,
                        c1: c1
                            .ok_or_else(|| SerdeError::missing_field("c1"))?,
                    })
                }
            }

            deserializer.deserialize_struct("Fp2", FIELDS, Fp2Visitor)
        }
    }

    #[cfg(test)]
    mod tests {
        use alloc::boxed::Box;

        use rand::rngs::StdRng;
        use rand_core::SeedableRng;

        use super::*;
        use crate::coset::test_utils;

        #[test]
        /// 验证 Fp2 的 serde 往返一致性。
        /// 该测试使用固定种子与静态 JSON 样本，确保编码结果稳定。
        /// 稳定序列化对于跨模块交互和回归测试都至关重要。
        fn serde_fp2() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = StdRng::seed_from_u64(0xc0b);
            let fp2 = Fp2::random(&mut rng);
            let ser = test_utils::assert_canonical_json(
                &fp2,
                include_str!("./fp2.json"),
            )?;
            let deser: Fp2 = serde_json::from_str(&ser).unwrap();

            assert_eq!(fp2, deser);
            Ok(())
        }
    }
}
