use std::env;

use receiver_plonk::verify_merkle_proof;

fn main() {
    println!("=== 执行 Plonk证明 程序 ===");
    println!("-----------------------------");

    let args: Vec<String> = env::args().collect();

    let result = if args.len() > 1 {
        match args[1].parse::<usize>() {
            Ok(n) => verify_merkle_proof(Some(n)),
            Err(_) => {
                println!("错误：参数必须是有效的数字");
                println!("用法：cargo run -- [n]");
                println!("  其中n是要验证的叶子节点数量（可选）");
                std::process::exit(1);
            }
        }
    } else {
        verify_merkle_proof(None)
    };

    match result {
        Ok(summary) => {
            println!("\n验证程序执行成功!");
            println!(
                "结果: 请求={}, 成功={}, 失败={}",
                summary.requested_files, summary.success_count, summary.failure_count
            );
        }
        Err(e) => {
            println!("\n验证程序执行失败: {:?}", e);
            std::process::exit(1);
        }
    }
}
