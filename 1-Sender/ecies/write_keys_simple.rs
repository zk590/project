use std::fs::write;

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    // 将HEX字符串转换为二进制数据
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i+2], 16).unwrap())
        .collect()
}

fn main() {
    // 用户提供的公钥和私钥HEX数据
    const TESTING_RECEIVER_PUBKEY_HEX: &str = "0498afe4f150642cd05cc9d2fa36458ce0a58567daeaf5fde7333ba9b403011140a4e28911fcf83ab1f457a30b4959efc4b9306f514a4c3711a16a80e3b47eb58b";
    const TESTING_RECEIVER_PRIVKEY_HEX: &str = "95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d";
    
    // 解析公钥HEX为二进制数据
    let pubkey_bytes = hex_to_bytes(TESTING_RECEIVER_PUBKEY_HEX);
    
    // 解析私钥HEX为二进制数据
    let privkey_bytes = hex_to_bytes(TESTING_RECEIVER_PRIVKEY_HEX);
    
    // 写入公钥到ecies-pub.der文件
    if let Err(err) = write("src/ecies-pub.der", pubkey_bytes) {
        eprintln!("无法写入公钥文件: {:?}", err);
        std::process::exit(1);
    }
    
    // 写入私钥到ecies-priv.der文件
    if let Err(err) = write("src/ecies-priv.der", privkey_bytes) {
        eprintln!("无法写入私钥文件: {:?}", err);
        std::process::exit(1);
    }
    
    println!("✅ 成功将公钥和私钥数据写入到DER文件中");
}