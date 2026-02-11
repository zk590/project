// 使用优化版本作为库对外导出的主实现
pub mod optimized_merkle;
pub use optimized_merkle::*;

use std::ffi::CStr;
use std::os::raw::c_char;

fn parse_c_string(raw: *const c_char) -> Result<String, ()> {
    if raw.is_null() {
        return Err(());
    }
    // SAFETY: 调用方需保证传入的是以 NUL 结尾的有效 C 字符串。
    let cstr = unsafe { CStr::from_ptr(raw) };
    let utf8 = cstr.to_str().map_err(|_| ())?;
    Ok(utf8.to_string())
}

/// C ABI: 调用 `some_merkle` 的核心能力，生成 n 个叶子并为 leaf_num 个叶子输出证明数据。
///
/// 返回值：
/// - `0` 成功
/// - `1` 业务处理失败
/// - `2` 参数无效（空指针或非 UTF-8）
#[unsafe(no_mangle)]
pub extern "C" fn merkle_some_generate_with_output(
    n: u64,
    leaf_num: u64,
    output_file: *const c_char,
) -> i32 {
    let output_file = match parse_c_string(output_file) {
        Ok(v) => v,
        Err(_) => return 2,
    };

    match create_and_save_leaves_data(n, leaf_num, &output_file) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}
