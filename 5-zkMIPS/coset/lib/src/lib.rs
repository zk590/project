use alloy_sol_types::sol;



// 定义用于验证Merkle证明的公共值结构体
sol! {
    
    /// Merkle证明验证结果结构体
    struct PublicValuesStruct  {
        bytes32 public_inputs;
        bytes proof;
    }
}