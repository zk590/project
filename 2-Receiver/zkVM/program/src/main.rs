
#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_verifier::{PlonkVerifier, PLONK_VK_BYTES};

pub fn main() {
    // Read the proof, public values and vk_hash from the input stream.
    let proof = sp1_zkvm::io::read::<Vec<u8>>();
    let sp1_public_values = sp1_zkvm::io::read::<Vec<u8>>();
    let sp1_vkey_hash = sp1_zkvm::io::read::<String>();
    
    println!("sp1_public_values: {:?}", sp1_public_values.len());
    println!("proof length: {:?}", proof.len());
    println!("sp1_vkey_hash: {}", sp1_vkey_hash);

    // Use the default PLONK verifying key from sp1-verifier
    let result = PlonkVerifier::verify(&proof, &sp1_public_values, &sp1_vkey_hash, &PLONK_VK_BYTES);
    
    match result {
        Ok(()) => {
            println!("Proof is valid");
        }
        Err(e) => {
            println!("Error verifying proof: {:?}", e);
        }
    }
}