use super::HashToField;
use crate::generic_array::{typenum::U48, GenericArray};
use crate::scalar::Scalar;

impl HashToField for Scalar {
    type InputLength = U48;

    /// 将 48 字节 OKM 映射为标量域元素。
    /// 实现通过左侧补零扩展到 64 字节，再按 `from_bytes_wide` 执行宽字节约简。
    /// 这种“宽输入约简”可降低偏差，符合哈希到标量的常见安全实践。
    fn from_okm(okm: &GenericArray<u8, U48>) -> Scalar {
        let mut bs = [0u8; 64];
        bs[16..].copy_from_slice(okm);
        bs.reverse();
        Scalar::from_bytes_wide(&bs)
    }
}

#[test]
/// 验证 hash-to-scalar 在固定测试向量上的输出稳定性。
/// 该测试覆盖全零输入与两组可读字符串输入，便于人工复核。
/// 向量回归可防止字节序、补零和约简路径在重构后发生漂移。
fn test_hash_to_scalar() {
    let tests: &[(&[u8], &str)] = &[
        (
            &[0u8; 48],
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            b"aaaaaabbbbbbccccccddddddeeeeeeffffffgggggghhhhhh",
            "0x2228450bf55d8fe62395161bd3677ff6fc28e45b89bc87e02a818eda11a8c5da",
        ),
        (
            b"111111222222333333444444555555666666777777888888",
            "0x4aa543cbd2f0c8f37f8a375ce2e383eb343e7e3405f61e438b0a15fb8899d1ae",
        ),
    ];
    for (input, expected) in tests {
        let output =
            format!("{:?}", Scalar::from_okm(GenericArray::from_slice(input)));
        assert_eq!(&output, expected);
    }
}
