use super::Fp6;

#[cfg(feature = "serde")]
mod serde_support {
    use serde::de::{Error as SerdeError, MapAccess, Visitor};
    use serde::ser::SerializeStruct;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for Fp6 {
        /// 将 Fp6 序列化为结构体 `{c0, c1, c2}`。
        /// 具名字段表示有利于跨语言映射与人工可读性。
        /// 每个分量继续复用各自类型的安全序列化逻辑。
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut ser_struct = serializer.serialize_struct("Fp6", 3)?;
            ser_struct.serialize_field("c0", &self.c0)?;
            ser_struct.serialize_field("c1", &self.c1)?;
            ser_struct.serialize_field("c2", &self.c2)?;
            ser_struct.end()
        }
    }

    impl<'de> Deserialize<'de> for Fp6 {
        /// 从结构体 `{c0, c1, c2}` 反序列化 Fp6。
        /// 该实现通过 Visitor 显式处理缺失字段、重复字段和未知字段。
        /// 严格输入验证有助于避免宽松解析带来的协议歧义。
        fn deserialize<D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Self, D::Error> {
            struct Fp6Visitor;

            const FIELDS: &[&str] = &["c0", "c1", "c2"];

            impl<'de> Visitor<'de> for Fp6Visitor {
                type Value = Fp6;

                /// 描述该 Visitor 期望的输入格式。
                /// serde 在错误提示时会使用这段文本，帮助定位问题。
                /// 对结构化类型而言，明确字段列表可提升诊断效率。
                fn expecting(
                    &self,
                    formatter: &mut ::core::fmt::Formatter,
                ) -> ::core::fmt::Result {
                    formatter.write_str("a struct with fields c0, c1 and c2")
                }

                /// 逐项读取 map 字段并构造 Fp6。
                /// 该流程对重复键、未知键、缺失键执行严格校验。
                /// 只有在 `c0/c1/c2` 全部成功解析后才返回目标对象。
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Self::Value, A::Error> {
                    let (mut c0, mut c1, mut c2) = (None, None, None);
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
                            "c2" => {
                                if c2.is_some() {
                                    return Err(SerdeError::duplicate_field(
                                        "c2",
                                    ));
                                } else {
                                    c2 = Some(map.next_value()?);
                                }
                            }
                            field => {
                                return Err(SerdeError::unknown_field(
                                    field, &FIELDS,
                                ))
                            }
                        }
                    }
                    Ok(Fp6 {
                        c0: c0
                            .ok_or_else(|| SerdeError::missing_field("c0"))?,
                        c1: c1
                            .ok_or_else(|| SerdeError::missing_field("c1"))?,
                        c2: c2
                            .ok_or_else(|| SerdeError::missing_field("c2"))?,
                    })
                }
            }

            deserializer.deserialize_struct("Fp6", FIELDS, Fp6Visitor)
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
        /// 验证 Fp6 的 serde 往返一致性。
        /// 用固定随机种子和静态 JSON 样本保证编码格式稳定。
        /// 该测试可防止结构字段顺序或命名在重构时无意漂移。
        fn serde_fp6() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = StdRng::seed_from_u64(0xc0b);
            let fp6 = Fp6::random(&mut rng);
            let ser = test_utils::assert_canonical_json(
                &fp6,
                include_str!("./fp6.json"),
            )?;
            let deser: Fp6 = serde_json::from_str(&ser).unwrap();

            assert_eq!(fp6, deser);
            Ok(())
        }
    }
}
