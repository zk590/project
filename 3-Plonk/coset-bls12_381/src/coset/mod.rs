pub(crate) mod choice;

#[cfg(all(feature = "groups", feature = "alloc"))]
pub mod multiscalar_mul;

#[cfg(all(test, feature = "serde"))]
pub mod test_utils {
    use std::boxed::Box;
    use std::string::String;

    use serde::Serialize;

    /// 该函数用于比较“语义等价”的 JSON，而不是比较字符串字面量。
    /// 先将输入对象序列化，再与期望字符串分别解析为 `serde_json::Value`。
    /// 这种比较方式可忽略字段顺序和空白差异，适合做稳定的序列化回归测试。
    pub fn assert_canonical_json<T>(
        input: &T,
        expected: &str,
    ) -> Result<String, Box<dyn std::error::Error>>
    where
        T: ?Sized + Serialize,
    {
        let serialized = serde_json::to_string(input)?;
        let input_canonical: serde_json::Value = serialized.parse()?;
        let expected_canonical: serde_json::Value = expected.parse()?;
        assert_eq!(input_canonical, expected_canonical);
        Ok(serialized)
    }
}
