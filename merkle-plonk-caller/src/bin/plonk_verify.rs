use std::ffi::CString;
use std::path::PathBuf;



unsafe extern "C" {
    fn receiver_plonk_verify_with_paths(
        verifier_file: *const std::os::raw::c_char,
        proof_dir: *const std::os::raw::c_char,
        proof_file_prefix: *const std::os::raw::c_char,
        public_inputs_file_prefix: *const std::os::raw::c_char,
        result_file: *const std::os::raw::c_char,
        n: usize,
    ) -> i32;
}

fn main() {
    println!("start calling plonk verify staticlib...");

    let caller_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let artifacts_dir = caller_root.join("artifacts");
    let proofs_dir = caller_root.join("proofs");

    let verifier_file = CString::new(
        artifacts_dir
            .join("verifier.bin")
            .to_string_lossy()
            .as_bytes(),
    )
    .expect("invalid verifier path");
    let output_dir = CString::new(proofs_dir.to_string_lossy().as_bytes()).expect("invalid output path");
    let proof_file_prefix = CString::new("plonk_proof_").expect("invalid proof prefix");
    let public_inputs_file_prefix =
        CString::new("plonk_publicinputs_").expect("invalid public inputs prefix");
    let verification_result_file = CString::new(
        proofs_dir
            .join("verification_result.bin")
            .to_string_lossy()
            .as_bytes(),
    )
    .expect("invalid verification result path");

    let verify_code = unsafe {
        receiver_plonk_verify_with_paths(
            verifier_file.as_ptr(),
            output_dir.as_ptr(),
            proof_file_prefix.as_ptr(),
            public_inputs_file_prefix.as_ptr(),
            verification_result_file.as_ptr(),
            0,
        )
    };

    if verify_code == 0 {
        println!("2-Receiver staticlib verify finished successfully");
    } else {
        eprintln!("2-Receiver staticlib verify failed, code={verify_code}");
        std::process::exit(1);
    }
}