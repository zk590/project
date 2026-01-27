#![no_main]
sp1_zkvm::entrypoint!(main);

pub fn main() {
    // 读取斐波那契数列的项数n
    let n = sp1_zkvm::io::read::<u64>();

    // 写入n到公共输入
    sp1_zkvm::io::commit(&n);

    // 计算乘法斐波那契数列第n项
    let (a, b) = fibonacci_mul(n);

    // 写入结果到公共输入
    sp1_zkvm::io::commit(&a);
    sp1_zkvm::io::commit(&b);
}

// 乘法斐波那契实现
fn fibonacci_mul(n: u64) -> (u64, u64) {
    let mut a = 1;   // 初始化变量 a 为 1，对7919取模
    let mut b = 2;   // 初始化变量 b 为 2，对7919取模
    for _ in 0..n {
        let c = (a * b) % 7919;  // 计算下一个斐波那契数 c = a * b，对7919取模
        a = b % 7919;            // 更新 a 为当前的 b 值
        b = c;                   // 更新 b 为新计算的 c 值
    }
    (a, b)
}