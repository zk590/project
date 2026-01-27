use alloy_sol_types::sol; 

// 定义公共值结构体
sol! {
    struct PublicValuesStruct {
        bool allValid;
    }
}

// 用于测试的默认消息
pub const DEFAULT_MESSAGE: &[u8] = b"Test message for ECDSA signature verification";

// 用于测试的默认公钥（hex格式）
pub const DEFAULT_PUBLIC_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

// 用于测试的默认签名（hex格式）
pub const DEFAULT_SIGNATURE: &str = "30450221009328d16a626c4609fc853a753a46c733b60f554854a38e091b9806679a737d8502200f76a8810a5f45b67e5d1b6f1c248a51079012d850009f19e237c8301035e01e";