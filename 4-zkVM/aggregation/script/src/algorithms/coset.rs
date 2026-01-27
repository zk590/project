use std::fs::File;
use std::io::{Read, Write, Error, ErrorKind};
use rkyv::{Archive, Deserialize, Serialize};
use crate::algorithms::algorithm_trait::AlgorithmHandler;
use crate::algorithms::errors::AggregationError;
use plonk::prelude::{BlsScalar, Proof, Verifier};
use coset_bytes::{DeserializableSlice, Serializable};

// 定义使用rkyv序列化的数据结构，与main.rs保持一致
#[derive(Archive, Serialize, Deserialize, Debug)]
#[archive(check_bytes)]
pub struct ZKProofData {
    pub data: Vec<u8>,
}

/// Coset算法处理器
pub struct CosetHandler {
    elf: &'static [u8],
    proof_file: String,
    public_inputs_file: String,
    verifier_file: String,
    public_inputs: Option<Vec<BlsScalar>>,
    proof: Option<Proof>,
    verifier: Option<Verifier>,
}

impl CosetHandler {
    pub fn new(elf: &'static [u8], proof_file: &str, public_inputs_file: &str, verifier_file: &str) -> Self {
        Self {
            elf,
            proof_file: proof_file.to_string(),
            public_inputs_file: public_inputs_file.to_string(),
            verifier_file: verifier_file.to_string(),
            public_inputs: None,
            proof: None,
            verifier: None,
        }
    }
    
    /// 从文件读取并使用rkyv反序列化ZKProofData，与main.rs保持一致的实现方式
    pub fn read_proof_data(file_path: &str) -> Result<ZKProofData, AggregationError> {
        // 打开文件
        let mut file = File::open(file_path)
            .map_err(|e| AggregationError::IoError(Error::new(ErrorKind::Other, format!("无法打开文件: {}", e))))?;
        
        // 读取所有字节
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| AggregationError::IoError(Error::new(ErrorKind::Other, format!("读取文件失败: {}", e))))?;
        
        // 使用rkyv反序列化数据
        let data = unsafe {
            rkyv::archived_root::<ZKProofData>(&bytes)
        };
        
        // 转换为ZKProofData结构体
        // 注意：ArchivedVec不支持直接clone，需要使用to_vec()方法或迭代构建
        Ok(ZKProofData {
            data: data.data.to_vec()
        })
    }
    
    /// 将字节数组转换为BlsScalar向量，与main.rs保持一致的实现方式
    pub fn bytes_to_bls_scalars(bytes: &[u8]) -> Result<Vec<BlsScalar>, AggregationError> {
        let mut scalars = Vec::new();
        
        // 检查字节长度是否为32的倍数
        if bytes.len() % 32 != 0 {
            return Err(AggregationError::DataLoadError("公共输入数据长度不是32的倍数".to_string()));
        }
        
        // 每32字节分割一次并转换为BlsScalar
        for chunk in bytes.chunks(32) {
            let mut scalar_bytes = [0u8; 32];
            scalar_bytes.copy_from_slice(&chunk[..32]);
            if let Some(scalar) = BlsScalar::from_bytes(&scalar_bytes).into_option() {
                scalars.push(scalar);
            } else {
                return Err(AggregationError::DataLoadError("解析公共参数失败".to_string()));
            }
        }
        
        Ok(scalars)
    }
    
    /// 从proof数据加载Proof对象
    pub fn load_proof(proof_bytes: &[u8]) -> Result<Proof, AggregationError> {
        Proof::from_slice(proof_bytes)
            .map_err(|e| AggregationError::DataLoadError(format!("反序列化证明失败: {:?}", e)))
    }
    
    /// 从文件加载Verifier对象
    pub fn load_verifier(verifier_bytes: &[u8]) -> Result<Verifier, AggregationError> {
        Verifier::try_from_bytes(verifier_bytes)
            .map_err(|e| AggregationError::DataLoadError(format!("反序列化验证者参数失败: {:?}", e)))
    }
}

impl CosetHandler {
    /// 直接返回分离的输入数据：public_inputs、proof和verifier
    pub fn get_separate_inputs(&self) -> Result<(Vec<BlsScalar>, Proof, Verifier), AggregationError> {
        // 检查并获取public_inputs
        let public_inputs = self.public_inputs.clone()
            .ok_or_else(|| AggregationError::DataLoadError("尚未读取公共输入数据".to_string()))?;
        
        // 检查并获取proof
        let proof = self.proof.clone()
            .ok_or_else(|| AggregationError::DataLoadError("尚未读取证明数据".to_string()))?;
        
        // 检查并获取verifier
        let verifier = self.verifier.as_ref()
            .ok_or_else(|| AggregationError::DataLoadError("尚未读取验证者参数".to_string()))?;
        
        // 从verifier引用获取其字节表示，然后重新创建一个新的Verifier实例
        let verifier_bytes = verifier.to_bytes();
        let new_verifier = Self::load_verifier(&verifier_bytes)?;
        
        Ok((public_inputs, proof, new_verifier))
    }
}

impl AlgorithmHandler for CosetHandler {
    fn name(&self) -> &str {
        "coset"
    }
    
    fn get_elf(&self) -> &'static [u8] {
        self.elf
    }
    
    fn read_data(&mut self) -> Result<(), AggregationError> {
        // 读取proof数据
        let zk_proof_data = Self::read_proof_data(&self.proof_file)?;
        
        // 从proof字节加载Proof对象
        self.proof = Some(Self::load_proof(&zk_proof_data.data)?);
        
        // 读取public_inputs数据
        let public_inputs_data = Self::read_proof_data(&self.public_inputs_file)?;
        
        // 将字节转换为BlsScalar向量
        self.public_inputs = Some(Self::bytes_to_bls_scalars(&public_inputs_data.data)?);
        
        // 读取并加载Verifier对象
        let verifier_bytes = std::fs::read(&self.verifier_file)
            .map_err(|e| AggregationError::IoError(e))?;
        
        self.verifier = Some(Self::load_verifier(&verifier_bytes)?);
        
        Ok(())
    }
    
    fn get_input_data(&self) -> Result<Vec<u8>, AggregationError> {
        let mut result = Vec::new();
        
        // 写入第一个public_input（如果有）
        if let Some(public_inputs) = &self.public_inputs {
            if !public_inputs.is_empty() {
                let first_input_bytes = public_inputs[0].to_bytes();
                result.extend_from_slice(&first_input_bytes);
            } else {
                // 如果没有public_inputs，写入32字节的零
                result.extend_from_slice(&[0u8; 32]);
            }
        } else {
            return Err(AggregationError::DataLoadError("尚未读取公共输入数据".to_string()));
        }
        
        // 写入proof字节
        if let Some(proof) = &self.proof {
            let proof_bytes = proof.to_bytes();
            result.extend_from_slice(&proof_bytes);
        } else {
            return Err(AggregationError::DataLoadError("尚未读取证明数据".to_string()));
        }
        
        // 写入verifier字节
        if let Some(verifier) = &self.verifier {
            let verifier_bytes = verifier.to_bytes();
            result.extend_from_slice(&verifier_bytes);
        } else {
            return Err(AggregationError::DataLoadError("尚未读取验证者参数".to_string()));
        }
        
        Ok(result)
    }
}