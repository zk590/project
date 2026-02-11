use std::env;

use common::constants::MERKLE_SOME_FILE;
use merkle::{create_and_save_leaves_data, simulate_chain_environment, verify_leaves};

// 打印使用说明
fn print_usage() {
    println!("用法:");
    println!("  cargo run -- [参数]");
    println!("参数:");
    println!("  only      - 生成一个叶子节点并序列化到文件");
    println!("  Some <n> <leaf_num>  - 生成n个叶子节点并为leaf_num个节点生成证明并序列化到文件");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let output_file = MERKLE_SOME_FILE;

    // 处理命令行参数
    if args.len() >= 2 {
        match args[1].as_str() {
            "only" => {
                println!("===== 生成单个叶子节点 ======");
                if let Err(err) = create_and_save_leaves_data(1, 1, output_file) {
                    eprintln!("创建单叶子节点数据失败: {}", err);
                }
            }
            "Some" | "--Some" => {
                if args.len() >= 4 {
                    match (args[2].parse::<u64>(), args[3].parse::<u64>()) {
                        (Ok(n), Ok(leaf_num)) => {
                            println!("===== 生成 {} 个叶子节点，并为 {} 个节点生成证明 ======", n, leaf_num);
                            if let Err(err) = create_and_save_leaves_data(n, leaf_num, output_file) {
                                eprintln!("创建叶子节点数据失败: {}", err);
                            }
                        }
                        _ => {
                            eprintln!(
                                "错误: 'Some' 参数后需要提供两个有效的数字: n(叶子总节点数) 和 leaf_num(生成证明的叶子节点数)"
                            );
                            print_usage();
                        }
                    }
                } else {
                    eprintln!("错误: 'Some' 参数需要指定n和leaf_num的值");
                    print_usage();
                }
            }
            _ => {
                eprintln!("错误: 无效的参数");
                print_usage();
            }
        }
    } else {
        // 默认行为：模拟链上环境并测试多叶子节点功能
        println!("===== 模拟链上Merkle树生成 =====");
        simulate_chain_environment(4);

        println!("\n===== 测试多叶子节点功能 =====");
        match create_and_save_leaves_data(8, 4, output_file) {
            Ok(_) => {
                println!("\n===== 验证多叶子节点数据 =====");
                if let Err(err) = verify_leaves(Some(output_file), None, None, None, None) {
                    eprintln!("验证失败: {}", err);
                }
            }
            Err(err) => eprintln!("创建多叶子节点数据失败: {}", err),
        }
    }
}
