use common::constants::{MERKLE_PROOF_FILE_PREFIX, VERIFIER_FILE};
use coset_bls12_381::BlsScalar;
use coset_bytes::Serializable;
use plonk::prelude::{Proof, Verifier};
use rkyv::{Archive, Deserialize};
use std::ffi::CStr;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// 使用 rkyv 封装的二进制数据结构。
#[derive(Archive, Deserialize, Debug)]
#[archive(check_bytes)]
struct ZKProofData {
    data: Vec<u8>,
}

/// 对外服务配置：支持调用方指定验证器、证明目录和输出文件。
#[derive(Debug, Clone)]
pub struct VerifyServiceConfig {
    pub verifier_file: PathBuf,
    pub proof_dir: PathBuf,
    pub proof_file_prefix: String,
    pub public_inputs_file_prefix: String,
    pub result_file: PathBuf,
}

impl Default for VerifyServiceConfig {
    fn default() -> Self {
        Self {
            verifier_file: PathBuf::from(VERIFIER_FILE),
            proof_dir: PathBuf::from(MERKLE_PROOF_FILE_PREFIX),
            proof_file_prefix: "plonk_proof_".to_string(),
            public_inputs_file_prefix: "plonk_publicinputs_".to_string(),
            result_file: PathBuf::from("verification_result.bin"),
        }
    }
}

/// 验证汇总结果，便于外部服务直接消费。
#[derive(Debug, Clone)]
pub struct VerificationSummary {
    pub requested_files: usize,
    pub success_count: usize,
    pub failure_count: usize,
    pub total_verification_time: Duration,
}

impl VerificationSummary {
    fn overall_result_flag(&self) -> u8 {
        if self.failure_count == 0 && self.success_count > 0 {
            1
        } else {
            0
        }
    }
}

/// 从文件读取字节数据。
fn read_file(file_path: &Path) -> Result<Vec<u8>, IoError> {
    if !file_path.exists() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            format!("文件不存在: {}", file_path.display()),
        ));
    }

    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    Ok(bytes)
}

/// 写入字节数据到文件。
fn write_file(file_path: &Path, data: &[u8]) -> Result<(), IoError> {
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = File::create(file_path)?;
    file.write_all(data)?;
    Ok(())
}

/// 使用 rkyv 解码证明文件中的业务负载字节。
fn load_proof_data(file_path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = read_file(file_path)?;
    let proof_data = unsafe { rkyv::archived_root::<ZKProofData>(&bytes) };
    Ok(proof_data.data.iter().copied().collect())
}

/// 基于配置执行批量验证。
///
/// - `n = Some(k)`：最多验证前 `k` 份证明
/// - `n = None`：扫描目录中连续编号证明并全部验证
pub fn verify_merkle_proof_with_config(
    config: &VerifyServiceConfig,
    n: Option<usize>,
) -> Result<VerificationSummary, Box<dyn std::error::Error>> {
    let verifier_data = read_file(&config.verifier_file)?;
    println!("Plonk Proof verifier = {}", hex::encode(&verifier_data));

    let verifier = Verifier::try_from_bytes(&verifier_data)?;

    let max_files_to_verify = match n {
        Some(count) => count,
        None => {
            let mut count = 0usize;
            loop {
                let proof_file =
                    config.proof_dir.join(format!("{}{}.bin", config.proof_file_prefix, count + 1));
                if !proof_file.exists() {
                    break;
                }
                count += 1;
            }
            count
        }
    };

    println!("共接收 {} 个Plonk证明", max_files_to_verify);

    let mut total_verification_time = Duration::new(0, 0);
    let mut success_count = 0usize;
    let mut failure_count = 0usize;

    for i in 0..max_files_to_verify {
        println!("\n验证第 {} 个证明文件:", i + 1);

        let proof_file_name = format!("{}{}.bin", config.proof_file_prefix, i + 1);
        let public_inputs_file_name =
            format!("{}{}.bin", config.public_inputs_file_prefix, i + 1);

        let proof_file_path = config.proof_dir.join(&proof_file_name);
        let public_inputs_file_path = config.proof_dir.join(&public_inputs_file_name);

        if !proof_file_path.exists() || !public_inputs_file_path.exists() {
            println!("   文件不存在，跳过此验证");
            failure_count += 1;
            continue;
        }

        let proof_bytes = load_proof_data(&proof_file_path)?;
        if i == 0 {
            println!(" Receive Plonk Proof = {}", hex::encode(&proof_bytes));
        }

        let public_inputs_bytes = load_proof_data(&public_inputs_file_path)?;
        if i == 0 {
            println!(
                " Receive Plonk Public_inputs = {}",
                hex::encode(&public_inputs_bytes)
            );
        }

        let proof = {
            let mut proof_array = [0u8; 1008];
            proof_array.copy_from_slice(&proof_bytes[..]);
            match Proof::from_bytes(&proof_array) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("   Proof反序列化错误: {:?}", e);
                    failure_count += 1;
                    continue;
                }
            }
        };

        let mut public_inputs = Vec::new();
        for j in (0..public_inputs_bytes.len()).step_by(32) {
            if j + 32 <= public_inputs_bytes.len() {
                if let Ok(array_32) = public_inputs_bytes[j..j + 32].try_into() {
                    if let Some(scalar) = BlsScalar::from_bytes(array_32).into_option() {
                        public_inputs.push(scalar);
                    }
                }
            }
        }

        let verify_start_time = Instant::now();
        let verification_result = verifier.verify(&proof, &public_inputs);
        let verify_duration = verify_start_time.elapsed();
        total_verification_time += verify_duration;

        match verification_result {
            Ok(_) => {
                println!(
                    "   PLonk 证明验证成功！耗时: {}.{:03} 秒",
                    verify_duration.as_secs(),
                    verify_duration.subsec_millis()
                );
                success_count += 1;
            }
            Err(e) => {
                println!("   证明验证失败: {:?}", e);
                failure_count += 1;
            }
        }
    }

    println!("\n===== 验证总结 =====");
    println!("总验证文件数: {}", max_files_to_verify);
    println!("成功验证数: {}", success_count);
    println!("失败验证数: {}", failure_count);
    println!(
        "总验证时间: {}.{:03} 秒",
        total_verification_time.as_secs(),
        total_verification_time.subsec_millis()
    );

    let summary = VerificationSummary {
        requested_files: max_files_to_verify,
        success_count,
        failure_count,
        total_verification_time,
    };

    write_file(&config.result_file, &[summary.overall_result_flag()])?;
    println!(
        "总体验证结果已保存到 {}",
        config.result_file.display()
    );

    Ok(summary)
}

/// 兼容旧调用：使用默认配置执行批量验证。
pub fn verify_merkle_proof(
    n: Option<usize>,
) -> Result<VerificationSummary, Box<dyn std::error::Error>> {
    verify_merkle_proof_with_config(&VerifyServiceConfig::default(), n)
}

fn parse_c_string_path(raw: *const c_char) -> Result<PathBuf, ()> {
    if raw.is_null() {
        return Err(());
    }
    // SAFETY: 调用方需保证传入的是以 NUL 结尾的有效 C 字符串。
    let cstr = unsafe { CStr::from_ptr(raw) };
    let utf8 = cstr.to_str().map_err(|_| ())?;
    Ok(PathBuf::from(utf8))
}

fn parse_c_string_value(raw: *const c_char) -> Result<String, ()> {
    if raw.is_null() {
        return Err(());
    }
    // SAFETY: 调用方需保证传入的是以 NUL 结尾的有效 C 字符串。
    let cstr = unsafe { CStr::from_ptr(raw) };
    let utf8 = cstr.to_str().map_err(|_| ())?;
    Ok(utf8.to_string())
}

/// C ABI: 通过调用方传入路径与前缀执行批量验证流程。
///
/// 返回值：
/// - `0` 成功（全部通过）
/// - `1` 业务处理失败（包含验证失败）
/// - `2` 参数无效（空指针或非 UTF-8）
#[unsafe(no_mangle)]
pub extern "C" fn receiver_plonk_verify_with_paths(
    verifier_file: *const c_char,
    proof_dir: *const c_char,
    proof_file_prefix: *const c_char,
    public_inputs_file_prefix: *const c_char,
    result_file: *const c_char,
    n: usize,
) -> i32 {
    let verifier_file = match parse_c_string_path(verifier_file) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    let proof_dir = match parse_c_string_path(proof_dir) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    let proof_file_prefix = match parse_c_string_value(proof_file_prefix) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    let public_inputs_file_prefix = match parse_c_string_value(public_inputs_file_prefix) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    let result_file = match parse_c_string_path(result_file) {
        Ok(v) => v,
        Err(_) => return 2,
    };

    let config = VerifyServiceConfig {
        verifier_file,
        proof_dir,
        proof_file_prefix,
        public_inputs_file_prefix,
        result_file,
    };
    let requested = if n == 0 { None } else { Some(n) };

    match verify_merkle_proof_with_config(&config, requested) {
        Ok(summary) if summary.failure_count == 0 && summary.success_count > 0 => 0,
        Ok(_) => 1,
        Err(_) => 1,
    }
}
