use super::Fp;

impl Fp {
    /// 返回 Fp 内部 limb 表示的只读视图。
    /// 该接口主要服务于内部编码与调试，不做表示层转换。
    /// 调用方应将其视为实现细节，避免在协议层直接依赖布局。
    pub const fn internal_repr(&self) -> &[u64; 6] {
        &self.0
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    extern crate alloc;

    use alloc::string::{String, ToString};

    use serde::de::Error as SerdeError;
    use serde::{self, Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for Fp {
        /// 将 Fp 序列化为十六进制字符串。
        /// 文本编码便于 JSON 传输和人工排查，同时保留二进制精确性。
        /// 底层仍复用 `to_bytes` 规范编码，确保跨实现一致。
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let s = hex::encode(self.to_bytes());
            s.serialize(serializer)
        }
    }

    impl<'de> Deserialize<'de> for Fp {
        /// 从十六进制字符串反序列化 Fp。
        /// 先执行 hex 解码与长度检查，再调用 `from_bytes` 做域合法性校验。
        /// 若数据不在模域范围内，将返回结构化反序列化错误。
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            let decoded = hex::decode(&s).map_err(SerdeError::custom)?;
            let decoded_len = decoded.len();
            const FP_BYTES_LEN: usize = 48;
            let bytes: [u8; FP_BYTES_LEN] =
                decoded.try_into().map_err(|_| {
                    SerdeError::invalid_length(
                        decoded_len,
                        &FP_BYTES_LEN.to_string().as_str(),
                    )
                })?;
            let fp = Fp::from_bytes(&bytes).into_option().ok_or(
                SerdeError::custom("Failed to deserialize Fp: invalid Fp"),
            )?;
            Ok(fp)
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
        /// 验证 Fp 的 serde 往返一致性与 canonical JSON 稳定性。
        /// 该测试固定随机种子与期望编码，防止序列化格式漂移。
        /// 对跨组件协议兼容而言，稳定文本表示是关键前提。
        fn serde_fp() -> Result<(), Box<dyn std::error::Error>> {
            let mut rng = StdRng::seed_from_u64(0xc0b);
            let fp = Fp::random(&mut rng);
            let ser = test_utils::assert_canonical_json(
                &fp,
                "\"16e40954bea69030cc133b0597126df8d4d35ed26e4ed93346dcbdc306e2e92039a0d32ccd21176819a26cb9430335f2\""
            )?;
            let deser: Fp = serde_json::from_str(&ser).unwrap();
            assert_eq!(fp, deser);
            Ok(())
        }

        #[test]
        /// 验证过短 Fp 编码会在反序列化阶段被拒绝。
        /// 该用例覆盖输入长度下界，避免截断数据被误解析。
        /// 固定长度约束是密码学数据边界检查的重要组成部分。
        fn serde_fp_too_short_encoded() {
            let length_47_enc = "\"16e40954bea69030cc133b0597126df8d4d35ed26e4ed93346dcbdc306e2e92039a0d32ccd21176819a26cb9430335\"";

            let fp: Result<Fp, _> = serde_json::from_str(&length_47_enc);
            assert!(fp.is_err());
        }

        #[test]
        /// 验证过长 Fp 编码会在反序列化阶段被拒绝。
        /// 该测试防止“合法前缀 + 尾部垃圾”带来的协议歧义。
        /// 对固定长度域元素编码，长度必须是强约束。
        fn serde_fp_too_long_encoded() {
            let length_49_enc = "\"16e40954bea69030cc133b0597126df8d4d35ed26e4ed93346dcbdc306e2e92039a0d32ccd21176819a26cb9430335f200\"";

            let fp: Result<Fp, _> = serde_json::from_str(&length_49_enc);
            assert!(fp.is_err());
        }
    }
}
