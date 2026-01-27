use alloy_sol_types::sol;

sol! {
    /// The public values encoded as a struct for Schnorr verification.
    struct PublicValuesStruct {
        bool all_valid;
    }
}
