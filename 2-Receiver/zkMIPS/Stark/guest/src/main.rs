//! A program that verifies a Plonk proof in ZKM.

#![no_main]
zkm_zkvm::entrypoint!(main);

use zkm_verifier::StarkVerifier;

pub fn main() {
    // Read the proof, public values, and vkey from the input stream.
    let proof = zkm_zkvm::io::read_vec();
    let zkm_public_values = zkm_zkvm::io::read_vec();
    let zkm_vk = zkm_zkvm::io::read_vec();
    
    println!("zkm_public_values: {:?}", zkm_public_values.len());
    println!("proof length: {:?}", proof.len());
    println!("zkm_vk length: {:?}", zkm_vk.len());

    // Verify the Stark proof using the provided vkey.
    let result = StarkVerifier::verify(&proof, &zkm_public_values, &zkm_vk);
    
    match result {
        Ok(()) => {
            println!("Proof is valid");
        }
        Err(e) => {
            println!("Error verifying proof: {:?}", e);
        }
    }
}