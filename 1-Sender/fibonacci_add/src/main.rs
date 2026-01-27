use std::fs::File;
use std::io::Write;
use clap::Parser;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};

// 定义斐波那契数据文件路径
use common::constants::FIBONACCI_DATA_FILE;

// 定义命令行参数结构
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 斐波那契数列的项数n
    #[arg(short, long)]
    n: u64,
}

// 定义斐波那契结果数据结构
#[derive(Archive, RkyvSerialize, RkyvDeserialize, Debug)]
#[archive_attr(derive(Debug))]
struct FibonacciResult {
    n: u64,
    a: u64,
    b: u64,
}

fn main() {
    // 解析命令行参数
    let args = Args::parse();
    let n = args.n;
    
    println!("计算斐波那契数列第 {} 项", n);
    
    // 计算斐波那契数列
    let (a, b) = fibonacci_add(n);
    
    // 创建结果数据结构
    let result = FibonacciResult {
        n,
        a,
        b,
    };
    
    // 序列化并写入文件
    match serialize_and_write(&result, FIBONACCI_DATA_FILE) {
        Ok(_) => {
            println!("结果已成功写入文件: {}", FIBONACCI_DATA_FILE);
            println!("n = {}", result.n);
            println!("a = {}", result.a);
            println!("b = {}", result.b);
        },
        Err(err) => eprintln!("序列化或写入文件失败: {}", err),
    }
}

// 斐波那契加法实现
fn fibonacci_add(n: u64) -> (u64, u64) {
    let mut a = 0;            // 初始化变量 a 为 0，用于存储前一个斐波那契数
    let mut b = 1;            // 初始化变量 b 为 1，用于存储当前斐波那契数
    for _ in 0..n {           // 循环 n 次计算斐波那契数列
        let mut c = a + b;    // 计算下一个斐波那契数 c = a + b
        c %=  7919;           // 对结果取模 7919，防止整数溢出
        a = b;                // 更新 a 为当前的 b 值
        b = c;                // 更新 b 为新计算的 c 值
    }
    (a, b)
}

// 使用rkyv将结果序列化并写入文件
fn serialize_and_write(result: &FibonacciResult, file_path: &str) -> Result<(), std::io::Error> {
    // 使用rkyv序列化结果
    let bytes = rkyv::to_bytes::<_, 1024>(result)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("序列化失败: {}", e)))?;
    
    // 打开或创建文件
    let mut file = File::create(file_path)?;
    
    // 写入序列化后的二进制数据
    file.write_all(&bytes)?;
    
    println!("序列化后大小: {} 字节", bytes.len());
    
    Ok(())
}