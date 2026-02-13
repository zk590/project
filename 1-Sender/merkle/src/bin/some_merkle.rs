use std::env;

use common::constants::MERKLE_SOME_FILE;
use merkle::create_and_save_leaves_from_strings;

fn parse_string_list(args: &[String]) -> Result<Vec<String>, String> {
    if args.is_empty() {
        return Err("字符串列表不能为空".to_string());
    }

    if args.len() == 1 {
        if let Ok(values) = serde_json::from_str::<Vec<String>>(&args[0]) {
            if values.is_empty() {
                return Err("JSON列表不能为空".to_string());
            }
            return Ok(values);
        }

        let values: Vec<String> = args[0]
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect();
        if values.is_empty() {
            return Err("逗号分隔列表不能为空".to_string());
        }
        return Ok(values);
    }

    Ok(args.to_vec())
}

// 打印使用说明
fn print_usage() {
    println!("用法:");
    println!("  cargo run -- [参数]");
    println!("参数:");
    println!("  --List <s1> <s2> ...   - 对输入字符串列表逐项哈希并插入Merkle树，再输出证明");
    println!("  --List \"a,b,c\"         - 逗号分隔字符串列表");
    println!("  --List '[\"a\",\"b\"]'    - JSON字符串列表");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let output_file = MERKLE_SOME_FILE;

    if args.len() < 3 || (args[1] != "--List" && args[1] != "List") {
        print_usage();
        return;
    }

    match parse_string_list(&args[2..]) {
        Ok(raw_values) => {
            println!(
                "===== 处理字符串列表并插入Merkle树，共 {} 项 ======",
                raw_values.len()
            );
            if let Err(err) = create_and_save_leaves_from_strings(&raw_values, output_file) {
                eprintln!("处理字符串列表失败: {}", err);
            }
        }
        Err(err) => {
            eprintln!("错误: {}", err);
            print_usage();
        }
    }
}
