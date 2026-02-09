//! A simple example showing how to aggregate proofs of multiple programs with ZKM.

use clap::Parser;
use std::fs::File;
use std::io::Write;
use std::time::Instant;
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

/// Command line arguments for the proof aggregation program.
#[derive(Parser, Debug)]
#[command(about = "Aggregate proofs for specified algorithms")]
struct Args {
    /// The algorithms to aggregate proofs for (e.g., fibonacci_add fibonacci_mul sha2 sha3)
    #[arg(value_name = "ALGORITHMS")]
    algorithms: Vec<String>,
    
    /// Output file path for the aggregated proof
    #[arg(short, long, default_value = "aggregated_proof.bin")]
    output: String,
}

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
    // Parse command line arguments
    let args = Args::parse();
    
    // Validate input algorithms
    let algorithms: Vec<&str> = args.algorithms.iter().map(|s| s.as_str()).collect();
    if algorithms.is_empty() {
        println!("Error: No algorithms specified. Please provide at least one algorithm name.");
        println!("Available algorithms: fibonacci_add, fibonacci_mul, sha2, sha3");
        return;
    }
    
    // Check for invalid algorithm names
    let valid_algorithms = ["fibonacci_add", "fibonacci_mul", "sha2", "sha3"];
    for alg in &algorithms {
        if !valid_algorithms.contains(alg) {
            println!("Error: Invalid algorithm name '{}'.", alg);
            println!("Available algorithms: fibonacci_add, fibonacci_mul, sha2, sha3");
            return;
        }
    }

    println!("=== Step 1: Initialization ===");
    // Setup the logger.
    zkm_sdk::utils::setup_logger();
    println!("✓ Logger setup completed");

    // Initialize the proving client.
    let client = ProverClient::new();
    println!("✓ Proving client initialized");

    println!("\n=== Step 2: Setting Up Keys ===");
    // Setup keys only for specified algorithms
    let mut inputs = Vec::new();
    
    // Fibonacci add
    if algorithms.contains(&"fibonacci_add") {
        println!("Setting up keys for fibonacci_add...");
        let (fibonacci_pk, fibonacci_vk) = client.setup(FIBONACCI_ELF);
        println!("✓ Keys setup for fibonacci_add");
        
        println!("Reading fibonacci add data...");
        let fibonacci_result = read_and_deserialize(FIBONACCI_DATA_FILE).expect("Failed to read fibonacci data");
        let n_add = fibonacci_result.n as u32;
        println!("✓ Fibonacci add data read, n = {}", n_add);
        
        println!("Generating fibonacci add proof...");
        let fibonacci_add_proof = tracing::info_span!("generate fibonacci add proof").in_scope(|| {
            let mut stdin = ZKMStdin::new();
            stdin.write(&n_add);
            client.prove(&fibonacci_pk, stdin).compressed().run().expect("fibonacci add compressed proving failed")
        });
        println!("✓ Fibonacci add proof generated");
        
        inputs.push(AggregationInput { proof: fibonacci_add_proof, vk: fibonacci_vk });
    }
    
    // Fibonacci mul
    if algorithms.contains(&"fibonacci_mul") {
        println!("Setting up keys for fibonacci_mul...");
        let (fibonacci_mul_pk, fibonacci_mul_vk) = client.setup(FIBONACCI_MUL_ELF);
        println!("✓ Keys setup for fibonacci_mul");
        
        println!("Reading fibonacci mul data...");
        let fibonacci_mul_result = read_and_deserialize_mul(FIBONACCI_MUL_DATA_FILE).expect("Failed to read fibonacci mul data");
        let n_mul = fibonacci_mul_result.n as u32;
        println!("✓ Fibonacci mul data read, n = {}", n_mul);
        
        println!("Generating fibonacci mul proof...");
        let fibonacci_mul_proof = tracing::info_span!("generate fibonacci mul proof").in_scope(|| {
            let mut stdin = ZKMStdin::new();
            stdin.write(&n_mul);
            client.prove(&fibonacci_mul_pk, stdin).compressed().run().expect("fibonacci mul compressed proving failed")
        });
        println!("✓ Fibonacci mul proof generated");
        
        inputs.push(AggregationInput { proof: fibonacci_mul_proof, vk: fibonacci_mul_vk });
    }
    
    // SHA2
    if algorithms.contains(&"sha2") {
        println!("Setting up keys for sha2...");
        let (sha2_pk, sha2_vk) = client.setup(SHA2_ELF);
        println!("✓ Keys setup for sha2");
        
        println!("Reading SHA2 data...");
        let sha2_results = read_and_deserialize_sha2(SHA2_HASH_FILE).expect("Failed to read SHA2 data");
        println!("✓ SHA2 data read, {} records", sha2_results.results.len());
        
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
            client.prove(&sha2_pk, stdin).compressed().run().expect("sha2 compressed proving failed")
        });
        println!("✓ SHA2 proof generated");
        
        inputs.push(AggregationInput { proof: sha2_proof, vk: sha2_vk });
    }
    
    // SHA3
    if algorithms.contains(&"sha3") {
        println!("Setting up keys for sha3...");
        let (sha3_pk, sha3_vk) = client.setup(SHA3_ELF);
        println!("✓ Keys setup for sha3");
        
        println!("Reading SHA3 data...");
        let sha3_results = read_and_deserialize_sha3(SHA3_HASH_FILE).expect("Failed to read SHA3 data");
        println!("✓ SHA3 data read, {} records", sha3_results.results.len());
        
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
            client.prove(&sha3_pk, stdin).compressed().run().expect("sha3 compressed proving failed")
        });
        println!("✓ SHA3 proof generated");
        
        inputs.push(AggregationInput { proof: sha3_proof, vk: sha3_vk });
    }
    
    println!("\n=== Step 3: Preparing Aggregation Inputs ===");
    println!("✓ Aggregation inputs prepared, {} proof(s)", inputs.len());

    println!("\n=== Step 5: Aggregating Proofs ===");
    let (aggregation_pk, aggregation_vk) = client.setup(AGGREGATION_ELF);
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
            println!("✓ Proof {} written", i + 1);
        }

        println!("Generating plonk bn254 proof...");
        // Generate the plonk bn254 proof - this is where the error typically occurs
        // client.execute(AGGREGATION_ELF, stdin).run().expect("aggregation failed");
        let aggregation_proof = client
            .prove(&aggregation_pk, stdin)
            .plonk()
            .run()
            .expect("aggregation plonk proving failed");
        println!("✓ Plonk bn254 proof generated successfully");
        
        // Verify the aggregated proof
        println!("Verifying the aggregated proof...");
        let start = Instant::now();
        client.verify(&aggregation_proof, &aggregation_vk).expect("Proof verification failed");
        let duration = start.elapsed();
        println!("✓ Proof verification passed, elapsed time: {:?}", duration);
        
        // Save the aggregated proof to file
        println!("Saving aggregated proof to file: {}", args.output);
        let mut file = File::create(&args.output).expect("Failed to create output file");
        file.write_all(&aggregation_proof.bytes()).expect("Failed to write proof to file");
        println!("✓ Proof file saved successfully")
    });
    
    println!("\n=== Aggregation Complete ===");
}