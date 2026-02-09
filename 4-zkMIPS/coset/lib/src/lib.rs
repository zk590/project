use alloy_sol_types::sol;
use rkyv::{Archive, Deserialize, Serialize};

// 仅在host特性启用时导入必要的模块
#[cfg(feature = "host")]
use std::fs::File;
#[cfg(feature = "host")]
use std::io::{Error, ErrorKind, Read};
#[cfg(feature = "host")]
use std::path::Path;

#[cfg(feature = "host")]
use coset_bytes::DeserializableSlice;

// 显式导出host特性需要的类型
#[cfg(feature = "host")]
pub use coset_bls12_381::BlsScalar;
#[cfg(feature = "host")]
pub use plonk::prelude::{Verifier, Proof};

// 定义使用rkyv序列化的数据结构
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct ZKProofData {
    data: Vec<u8>,
}

// 定义用于验证coset证明的公共值结构体
sol! {
    /// coset证明验证结果结构体
    struct PublicValuesStruct {
        bytes32 public_inputs;
        bytes proof;
    }
}

// 仅在host特性启用时编译以下代码
#[cfg(feature = "host")]
extern crate bincode;

#[cfg(feature = "host")]
use zkm_sdk::HashableKey;

#[cfg(feature = "host")]
pub struct SerializedProof {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
    pub vk_bytes: Vec<u8>,
}

#[cfg(feature = "host")]
pub fn serialize_stark_proof(
    proof: &zkm_sdk::ZKMProofWithPublicValues,
    vk: &zkm_sdk::ZKMVerifyingKey,
) -> SerializedProof {
    let vk_bytes = bincode::serialize(vk).expect("序列化vk失败");
    SerializedProof {
        proof: proof.bytes().to_vec(),
        public_values: proof.public_values.to_vec(),
        vk_bytes,
    }
}

#[cfg(feature = "host")]
pub fn serialize_plonk_proof(
    proof: &zkm_sdk::ZKMProofWithPublicValues,
    vk: &zkm_sdk::ZKMVerifyingKey,
) -> SerializedProof {
    SerializedProof {
        proof: proof.bytes().to_vec(),
        public_values: proof.public_values.to_vec(),
        vk_bytes: vk.bytes32().into_bytes(),
    }
}

#[cfg(feature = "host")]
/// 从文件读取数据
pub fn read_file(file_path: &str) -> Result<Vec<u8>, Error> {
    // 检查文件是否存在
    if !Path::new(file_path).exists() {
        return Err(Error::new(ErrorKind::NotFound, format!("文件不存在: {}", file_path)));
    }
    
    // 打开文件并读取所有字节
    let mut file = File::open(file_path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    
    Ok(bytes)
}

#[cfg(feature = "host")]
/// 从文件中加载零知识证明数据
pub fn load_zk_proof_data(proof_path: &str, public_inputs_path: &str) -> Result<(Vec<BlsScalar>, Vec<u8>, Proof), Box<dyn std::error::Error>> {
    // 从文件读取序列化的证明数据
    let proof_file_bytes = read_file(proof_path)?;
    println!("证明文件总大小: {} 字节", proof_file_bytes.len());
    
    // 使用与3-Plonk相同的反序列化方法
    let proof_data = unsafe {
        rkyv::archived_root::<ZKProofData>(&proof_file_bytes)
    };
    
    let proof_bytes: Vec<u8> = proof_data.data.iter().copied().collect();
    println!("Proof数据大小: {} 字节", proof_bytes.len());
    
    // 反序列化Proof
    let proof = Proof::from_slice(&proof_data.data).map_err(|e| {
        Error::new(ErrorKind::Other, format!("反序列化证明失败: {:?}", e))
    })?;
    
    // 从文件读取序列化的公开输入数据
    let public_inputs_file_bytes = read_file(public_inputs_path)?;
    println!("公共输入文件总大小: {} 字节", public_inputs_file_bytes.len());
    
    // 使用与3-Plonk相同的反序列化方法
    let public_inputs_data = unsafe {
        rkyv::archived_root::<ZKProofData>(&public_inputs_file_bytes)
    };
    
    let public_inputs_bytes: Vec<u8> = public_inputs_data.data.iter().copied().collect();
    println!("公共输入数据大小: {} 字节", public_inputs_bytes.len());
    
    // 解析公开输入
    let mut public_inputs = Vec::new();
    let scalar_size = 32; // BlsScalar的大小
    let num_scalars = public_inputs_data.data.len() / scalar_size;
    
    for i in 0..num_scalars {
        let start = i * scalar_size;
        let end = start + scalar_size;
        let scalar_bytes = &public_inputs_data.data[start..end];
        
        // 转换为[u8; 32]类型
        let mut fixed_bytes = [0u8; 32];
        if scalar_bytes.len() == 32 {
            fixed_bytes.copy_from_slice(scalar_bytes);
        } else {
            return Err(Box::new(Error::new(ErrorKind::Other, "公开输入数据长度不正确")));
        }
        
        let scalar = match BlsScalar::from_bytes(&fixed_bytes).into_option() {
            Some(s) => s,
            None => return Err(Box::new(Error::new(ErrorKind::Other, "解析公开输入失败"))),
        };
        
        public_inputs.push(scalar);
        println!("成功解析公共输入 {}: {:?}", i, scalar);
    }
    println!("最终公共输入数量: {}", public_inputs.len());
    
    println!("   ├── plonk证明数据加载完成");
    
    // 返回公共输入、proof_bytes（用于传递给program）和proof（用于本地验证）
    Ok((public_inputs, proof_bytes, proof))
}

#[cfg(feature = "host")]
/// 从文件中加载验证者参数
pub fn load_verifier_params(path: &str) -> Result<Verifier, std::io::Error> {
    
    // 从文件读取验证器数据
    let verifier_bytes = read_file(path)?;
    
    // 反序列化验证器
    let verifier = Verifier::try_from_bytes(&verifier_bytes)
        .map_err(|e| Error::new(ErrorKind::Other, format!("反序列化验证者参数失败: {:?}", e)))?;
    
    println!("   ├── 验证者参数加载完成");
    println!("   ├── 验证者参数大小: {} 字节", verifier_bytes.len());
    
    Ok(verifier)
}