use std::ffi::CString;
use std::path::PathBuf;

use common::constants::{CAPACITY, MERKLE_SOME_FILE};

unsafe extern "C" {
    fn merkle_plonk_process_batch_with_paths(
        merkle_input_file: *const std::os::raw::c_char,
        verifier_file: *const std::os::raw::c_char,
        circuit_cache_file: *const std::os::raw::c_char,
        output_dir: *const std::os::raw::c_char,
        capacity: usize,
    ) -> i32;
}

fn main() {
    println!("start calling merkle-plonk staticlib...");

    let caller_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let artifacts_dir = caller_root.join("artifacts");
    let proofs_dir = caller_root.join("proofs");

    let merkle_input = CString::new(MERKLE_SOME_FILE).expect("invalid MERKLE_SOME_FILE");
    let verifier_file = CString::new(
        artifacts_dir
            .join("verifier.bin")
            .to_string_lossy()
            .as_bytes(),
    )
    .expect("invalid verifier path");
    let circuit_cache_file = CString::new(
        artifacts_dir
            .join("circuit_prove.bin")
            .to_string_lossy()
            .as_bytes(),
    )
    .expect("invalid circuit cache path");
    let output_dir =
        CString::new(proofs_dir.to_string_lossy().as_bytes()).expect("invalid output path");

    let code = unsafe {
        merkle_plonk_process_batch_with_paths(
            merkle_input.as_ptr(),
            verifier_file.as_ptr(),
            circuit_cache_file.as_ptr(),
            output_dir.as_ptr(),
            CAPACITY,
        )
    };

    if code == 0 {
        println!("merkle-plonk staticlib call finished successfully");
    } else {
        eprintln!("merkle-plonk staticlib call failed, code={code}");
        std::process::exit(1);
    }
}