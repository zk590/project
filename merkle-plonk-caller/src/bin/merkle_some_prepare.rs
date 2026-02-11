use std::env;
use std::ffi::CString;

use common::constants::MERKLE_SOME_FILE;

unsafe extern "C" {
    fn merkle_some_generate_with_output(
        n: u64,
        leaf_num: u64,
        output_file: *const std::os::raw::c_char,
    ) -> i32;
}

fn print_usage() {
    println!("用法:");
    println!("  cargo run --release --bin merkle_some_prepare -- <n> <leaf_num> [output_file]");
    println!("示例:");
    println!("  cargo run --release --bin merkle_some_prepare -- 8 4");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        print_usage();
        std::process::exit(1);
    }

    let n = match args[1].parse::<u64>() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("参数 n 必须是 u64");
            std::process::exit(1);
        }
    };
    let leaf_num = match args[2].parse::<u64>() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("参数 leaf_num 必须是 u64");
            std::process::exit(1);
        }
    };
    let output_path = if args.len() >= 4 {
        args[3].as_str()
    } else {
        MERKLE_SOME_FILE
    };

    let output_cstr = CString::new(output_path).expect("invalid output path");
    let code = unsafe { merkle_some_generate_with_output(n, leaf_num, output_cstr.as_ptr()) };

    if code == 0 {
        println!(
            "merkle staticlib call finished successfully: n={}, leaf_num={}, output={}",
            n, leaf_num, output_path
        );
    } else if code == 2 {
        eprintln!("merkle staticlib call failed: invalid output path encoding");
        std::process::exit(2);
    } else {
        eprintln!("merkle staticlib call failed, code={code}");
        std::process::exit(1);
    }
}
