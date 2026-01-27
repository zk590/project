//! A program that verifies a Plonk proof in ZKM.

#![no_main]
zkm_zkvm::entrypoint!(main);

use zkm_verifier::PlonkVerifier;

pub fn main() {
    // Read the proof, public values, vkey hash, and plonk vk from the input stream.
    let proof = zkm_zkvm::io::read_vec();
    let zkm_public_values = zkm_zkvm::io::read_vec();
    let zkm_vkey_hash = zkm_zkvm::io::read_vec();
    let plonk_vk = zkm_zkvm::io::read_vec();
    
    // Convert zkm_vkey_hash from Vec<u8> to String
    let zkm_vkey_hash_str = String::from_utf8(zkm_vkey_hash).unwrap();
    
    println!("zkm_public_values: {:?}", zkm_public_values.len());
    println!("proof length: {:?}", proof.len());
    println!("zkm_vkey_hash: {:?}", zkm_vkey_hash_str);
    println!("plonk_vk length: {:?}", plonk_vk.len());

    // Verify the Plonk proof using the provided vkey.
    let result = PlonkVerifier::verify(&proof, &zkm_public_values, &zkm_vkey_hash_str, &plonk_vk);
    
    match result {
        Ok(()) => {
            println!("Proof is valid");
        }
        Err(e) => {
            println!("Error verifying proof: {:?}", e);
        }
    }
}