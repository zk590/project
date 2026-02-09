# merkle-plonk

`merkle-plonk` 提供了一个可复用的库接口，用于批量验证 Merkle opening 并生成/验证 PLONK 证明。

## 作为库调用

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    merkle_plonk::process_batch_proofs()?;
    Ok(())
}
```

```rust
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = merkle_plonk::BatchProofConfig {
        merkle_input_file: PathBuf::from("input/merkle_some.bin"),
        verifier_file: PathBuf::from("output/verifier.bin"),
        circuit_cache_file: PathBuf::from("cache/circuit_prove.bin"),
        output_dir: PathBuf::from("output/proofs"),
        proof_file_prefix: "plonk_proof_".to_string(),
        public_inputs_file_prefix: "plonk_publicinputs_".to_string(),
        capacity: 20,
    };
    merkle_plonk::process_batch_proofs_with_config(&config)?;
    Ok(())
}
```

## 作为可执行程序

- `batch_merkle_proof`: 调用库入口 `run_batch_cli()`
- `merkle_proof`: 单条证明流程（保留兼容）

## 输入/输出文件

默认路径由 `common::constants` 提供：

- `MERKLE_SOME_FILE`
- `VERIFIER_FILE`
- `plonk_proof_*.bin`
- `plonk_publicinputs_*.bin`
