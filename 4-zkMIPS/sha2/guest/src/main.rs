
#![no_main]
zkm_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use sha2_lib::{PublicValuesStruct, sha256};

pub fn main() {
    // Read the number of hash results to verify
    let results_len = zkm_zkvm::io::read::<u32>();
    
    // Variable to store overall validation result
    let mut all_valid = true;
    
    // Process each hash result
    for _ in 0..results_len {
        // Read message length and bytes
        let message_len = zkm_zkvm::io::read::<u32>();
        let message = (0..message_len).map(|_| zkm_zkvm::io::read::<u8>()).collect::<Vec<u8>>();
        // Read expected hash length and bytes
        let hash_len = zkm_zkvm::io::read::<u32>();
        let expected_hash = (0..hash_len).map(|_| zkm_zkvm::io::read::<u8>()).collect::<Vec<u8>>();
        // Compute SHA-256 hash of the message using the new lib function
        let computed_hash = sha256(&message);
        
        // Verify if computed hash matches the provided hash
        let is_valid = computed_hash.to_vec() == expected_hash;
        
        // Update overall validation result
        all_valid = all_valid && is_valid;
    }
    
    // Encode the public values and commit them
    let bytes = PublicValuesStruct::abi_encode(&PublicValuesStruct { all_valid });
    zkm_zkvm::io::commit_slice(&bytes);
}
