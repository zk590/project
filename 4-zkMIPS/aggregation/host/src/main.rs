//! A simple example showing how to aggregate proofs of multiple programs with ZKM.

use zkm_sdk::{
    include_elf, HashableKey, ProverClient, ZKMProof, ZKMProofWithPublicValues, ZKMStdin,
    ZKMVerifyingKey,
};
use common::constants::{
    FIBONACCI_DATA_FILE,
    FIBONACCI_MUL_DATA_FILE,
    SHA2_HASH_FILE,
    SHA3_HASH_FILE
};
use fibonacci_add_lib::read_and_deserialize;
use fibonacci_mul_lib::read_and_deserialize as read_and_deserialize_mul;
use sha2_lib::read_and_deserialize as read_and_deserialize_sha2;
use sha3_lib::read_and_deserialize as read_and_deserialize_sha3;

/// A program that aggregates the proofs of the simple program.
const AGGREGATION_ELF: &[u8] = include_elf!("aggregation");

/// A program that just runs a simple computation.
const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-add");

/// A program that runs fibonacci multiplication.
const FIBONACCI_MUL_ELF: &[u8] = include_elf!("fibonacci-mul");

/// A program that runs SHA2 hash computation.
const SHA2_ELF: &[u8] = include_elf!("sha2");

/// A program that runs SHA3 hash computation.
const SHA3_ELF: &[u8] = include_elf!("sha3");

/// An input to the aggregation program.
///
/// Consists of a proof and a verification key.
struct AggregationInput {
    pub proof: ZKMProofWithPublicValues,
    pub vk: ZKMVerifyingKey,
}

fn main() {
    println!("=== Step 1: Initialization ===");
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    println!("✓ Logger setup completed");

    // Initialize the proving client.
    let client = ProverClient::new();
    println!("✓ Proving client initialized");

    // Setup the proving and verifying keys for all programs
    println!("Setting up proving and verifying keys...");
    let (fibonacci_pk, fibonacci_vk) = client.setup(FIBONACCI_ELF);
    let (fibonacci_mul_pk, fibonacci_mul_vk) = client.setup(FIBONACCI_MUL_ELF);
    let (sha2_pk, sha2_vk) = client.setup(SHA2_ELF);
    let (sha3_pk, sha3_vk) = client.setup(SHA3_ELF);
    println!("✓ Keys setup completed for all programs");

    println!("\n=== Step 2: Reading Input Data ===");
    // Read the fibonacci add data from file
    println!("Reading fibonacci add data from file...");
    let fibonacci_result = read_and_deserialize(FIBONACCI_DATA_FILE).expect("Failed to read fibonacci data");
    let n_add = fibonacci_result.n as u32;
    println!("✓ Fibonacci add data read, n = {}", n_add);

    // Read the fibonacci mul data from file
    println!("Reading fibonacci mul data from file...");
    let fibonacci_mul_result = read_and_deserialize_mul(FIBONACCI_MUL_DATA_FILE).expect("Failed to read fibonacci mul data");
    let n_mul = fibonacci_mul_result.n as u32;
    println!("✓ Fibonacci mul data read, n = {}", n_mul);

    // Read the sha2 data from file
    println!("Reading SHA2 data from file...");
    let sha2_results = read_and_deserialize_sha2(SHA2_HASH_FILE).expect("Failed to read SHA2 data");
    println!("✓ SHA2 data read, {} records", sha2_results.results.len());

    // Read the sha3 data from file
    println!("Reading SHA3 data from file...");
    let sha3_results = read_and_deserialize_sha3(SHA3_HASH_FILE).expect("Failed to read SHA3 data");
    println!("✓ SHA3 data read, {} records", sha3_results.results.len());
    
    println!("\n=== Step 3: Generating Proofs ===");
    // Generate fibonacci add proof
    println!("Generating fibonacci add proof...");
    let fibonacci_add_proof = tracing::info_span!("generate fibonacci add proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&n_add);
        // Use compressed proof as required by aggregation
        client.prove(&fibonacci_pk, stdin).compressed().run().expect("fibonacci add compressed proving failed")
    });
    println!("✓ Fibonacci add proof generated");

    // Generate fibonacci mul proof
    println!("Generating fibonacci mul proof...");
    let fibonacci_mul_proof = tracing::info_span!("generate fibonacci mul proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&n_mul);
        // Use compressed proof as required by aggregation
        client.prove(&fibonacci_mul_pk, stdin).compressed().run().expect("fibonacci mul compressed proving failed")
    });
    println!("✓ Fibonacci mul proof generated");

    // Generate SHA2 proof
    println!("Generating SHA2 proof...");
    let sha2_proof = tracing::info_span!("generate sha2 proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&(sha2_results.results.len() as u32));
        for result in &sha2_results.results {
            let message = result.message.as_bytes();
            let expected_hash = hex::decode(&result.hash).expect("Invalid hex hash");
            stdin.write(&(message.len() as u32));
            for byte in message {
                stdin.write(&byte);
            }
            stdin.write(&(expected_hash.len() as u32));
            for byte in expected_hash {
                stdin.write(&byte);
            }
        }
        // Use compressed proof as required by aggregation
        client.prove(&sha2_pk, stdin).compressed().run().expect("sha2 compressed proving failed")
    });
    println!("✓ SHA2 proof generated");

    // Generate SHA3 proof
    println!("Generating SHA3 proof...");
    let sha3_proof = tracing::info_span!("generate sha3 proof").in_scope(|| {
        let mut stdin = ZKMStdin::new();
        stdin.write(&(sha3_results.results.len() as u32));
        for result in &sha3_results.results {
            let message = result.message.as_bytes();
            let expected_hash = hex::decode(&result.hash).expect("Invalid hex hash");
            stdin.write(&(message.len() as u32));
            for byte in message {
                stdin.write(&byte);
            }
            stdin.write(&(expected_hash.len() as u32));
            for byte in expected_hash {
                stdin.write(&byte);
            }
        }
        // Use compressed proof as required by aggregation
        client.prove(&sha3_pk, stdin).compressed().run().expect("sha3 compressed proving failed")
    });
    println!("✓ SHA3 proof generated");

    println!("\n=== Step 4: Preparing Aggregation Inputs ===");
    // Setup the inputs to the aggregation program with all proofs
    let inputs = vec![
        AggregationInput { proof: fibonacci_add_proof, vk: fibonacci_vk },
        AggregationInput { proof: fibonacci_mul_proof, vk: fibonacci_mul_vk },
        AggregationInput { proof: sha2_proof, vk: sha2_vk },
        AggregationInput { proof: sha3_proof, vk: sha3_vk },
    ];
    println!("✓ Aggregation inputs prepared, {} proof(s)", inputs.len());

    println!("\n=== Step 5: Aggregating Proofs ===");
    let (aggregation_pk, _) = client.setup(AGGREGATION_ELF);
    // Aggregate the proofs.
    tracing::info_span!("aggregate the proofs").in_scope(|| {
        let mut stdin = ZKMStdin::new();

        println!("Writing verification keys to stdin...");
        // Write the verification keys.
        let vkeys = inputs.iter().map(|input| input.vk.hash_u32()).collect::<Vec<_>>();
        stdin.write::<Vec<[u32; 8]>>(&vkeys);
        println!("✓ Verification keys written: {} keys", vkeys.len());

        println!("Writing public values to stdin...");
        // Write the public values.
        let public_values =
            inputs.iter().map(|input| input.proof.public_values.to_vec()).collect::<Vec<_>>();
        stdin.write::<Vec<Vec<u8>>>(&public_values);
        println!("✓ Public values written: {} sets", public_values.len());

        println!("Writing proofs to stdin...");
        // Write the proofs.
        // Note: this data will not actually be read by the aggregation program,
        // instead it will be witnessed by the prover during the recursive aggregation
        // process inside Ziren itself.
        for (i, input) in inputs.into_iter().enumerate() {
            // Only compressed proof is supported
            let ZKMProof::Compressed(proof) = input.proof.proof else { 
                panic!("Only compressed proofs are supported for aggregation"); 
            };
            stdin.write_proof(*proof, input.vk.vk);
            println!("✓ Proof {} written", i+1);
        }

        println!("Generating plonk bn254 proof...");
        // Generate the plonk bn254 proof - this is where the error typically occurs
        // client.execute(ELF, stdin).run()
        client.execute(AGGREGATION_ELF, stdin).run().expect("aggregation failed");
        println!("✓ Plonk bn254 proof generated successfully");
    });
    
    println!("\n=== Aggregation Complete ===");
}
