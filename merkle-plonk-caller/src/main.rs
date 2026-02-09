use std::path::PathBuf;

use common::constants::{CAPACITY, MERKLE_SOME_FILE};
use merkle_plonk::{process_batch_proofs_with_config, BatchProofConfig};

fn main() {
    println!("start calling merkle-plonk...");

    let caller_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let artifacts_dir = caller_root.join("artifacts");
    let proofs_dir = caller_root.join("proofs");

    let config = BatchProofConfig {
        merkle_input_file: PathBuf::from(MERKLE_SOME_FILE),
        verifier_file: artifacts_dir.join("verifier.bin"),
        circuit_cache_file: artifacts_dir.join("circuit_prove.bin"),
        output_dir: proofs_dir,
        proof_file_prefix: "plonk_proof_".to_string(),
        public_inputs_file_prefix: "plonk_publicinputs_".to_string(),
        capacity: CAPACITY,
    };

    match process_batch_proofs_with_config(&config) {
        Ok(()) => println!("merkle-plonk call finished successfully"),
        Err(error) => eprintln!("merkle-plonk call failed: {error}"),
    }
}
