pub(crate) mod choice;

#[cfg(all(feature = "groups", feature = "alloc"))]
pub mod multiscalar_mul;

#[cfg(all(test, feature = "serde"))]
pub mod test_utils {
    use std::boxed::Box;
    use std::string::String;

    use serde::Serialize;

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
