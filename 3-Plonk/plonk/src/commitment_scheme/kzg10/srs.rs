use super::key::{CommitKey, OpeningKey};
use crate::{error::Error, util};
use alloc::vec::Vec;
use coset_bls12_381::{BlsScalar, G1Affine, G1Projective, G2Affine};
use coset_bytes::{DeserializableSlice, Serializable};
use ff::Field;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Sized + Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]

pub struct PublicParameters {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) commit_key: CommitKey,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) opening_key: OpeningKey,
}

impl PublicParameters {
    const ADDED_BLINDING_DEGREE: usize = 6;

    /// 由提交键和开口键构造公共参数对象。
    #[inline]
    fn new(commit_key: CommitKey, opening_key: OpeningKey) -> Self {
        Self {
            commit_key,
            opening_key,
        }
    }

    /// 生成 KZG 公共参数（SRS）。
    /// 该过程随机采样隐藏标量 `x`，并构造 `g, g^x, ...` 与 `h, h^x` 结构。
    /// 为支持盲化多项式，内部会在请求度数基础上追加固定盲化余量。
    pub fn setup<R: RngCore + CryptoRng>(
        mut max_degree: usize,
        mut rng: &mut R,
    ) -> Result<PublicParameters, Error> {
        if max_degree < 1 {
            return Err(Error::DegreeIsZero);
        }

        max_degree += Self::ADDED_BLINDING_DEGREE;

        let toxic_waste = BlsScalar::random(&mut rng);

        let powers_of_toxic_waste = util::powers_of(&toxic_waste, max_degree);

        let g1_generator = util::random_g1_point(&mut rng);
        let powers_of_g: Vec<G1Projective> =
            util::slow_multiscalar_mul_single_base(
                &powers_of_toxic_waste,
                g1_generator,
            );
        assert_eq!(powers_of_g.len(), max_degree + 1);

        let mut normalized_g = vec![G1Affine::identity(); max_degree + 1];
        G1Projective::batch_normalize(&powers_of_g, &mut normalized_g);

        let g2_generator: G2Affine = util::random_g2_point(&mut rng).into();
        let x_h: G2Affine = (g2_generator * toxic_waste).into();

        Ok(PublicParameters::new(
            CommitKey {
                powers_of_g: normalized_g,
            },
            OpeningKey::new(g1_generator.into(), g2_generator, x_h),
        ))
    }

    /// 将公共参数编码为“原始字节”格式。
    /// 该格式优先追求体积与速度，不保证对非法输入的健壮校验能力。
    /// 适合受信任环境下的缓存落盘与快速加载场景。
    pub fn to_raw_var_bytes(&self) -> Vec<u8> {
        let mut bytes = self.opening_key.to_bytes().to_vec();
        bytes.extend(&self.commit_key.to_raw_var_bytes());

        bytes
    }

    /// 从原始字节恢复公共参数（不做完整合法性检查）。
    /// 调用方必须保证输入字节来源可信且格式正确，否则可能导致未定义行为风险。
    /// 该接口应仅在受控边界内使用，并优先搭配 `to_raw_var_bytes` 输出。
    pub unsafe fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let (serialized_opening_key, serialized_commit_key) =
            Self::split_serialized_sections(bytes);
        let opening_key = OpeningKey::from_slice(serialized_opening_key)
            .expect("Error at OpeningKey deserialization");
        let commit_key = CommitKey::from_slice_unchecked(serialized_commit_key);
        Self::new(commit_key, opening_key)
    }

    /// 将公共参数编码为安全可解析的可变长字节序列。
    /// 该格式与 `from_slice` 一一对应，优先保证可移植性和解析稳定性。
    /// 推荐用于跨进程传输或持久化到不完全受信任的介质。
    pub fn to_var_bytes(&self) -> Vec<u8> {
        let mut bytes = self.opening_key.to_bytes().to_vec();
        bytes.extend(self.commit_key.to_var_bytes().iter());
        bytes
    }

    /// 从可变长字节切片恢复公共参数。
    /// 该函数会先解析 opening key，再解析 commit key，并检查基础长度约束。
    /// 解析失败返回错误，调用方可据此回退到重新生成参数流程。
    pub fn from_slice(bytes: &[u8]) -> Result<PublicParameters, Error> {
        if bytes.len() <= OpeningKey::SIZE {
            return Err(Error::NotEnoughBytes);
        }
        let mut remaining_bytes = bytes;
        let opening_key = OpeningKey::from_reader(&mut remaining_bytes)?;
        let commit_key = CommitKey::from_slice(remaining_bytes)?;
        Ok(PublicParameters::new(commit_key, opening_key))
    }

    /// 按目标度数裁剪提交键，并返回对应 opening key。
    /// 裁剪过程会自动考虑盲化附加度数，确保后续证明流程可正常工作。
    /// 该接口常用于“先生成大 SRS，再按电路规模动态截取”的部署模式。
    pub(crate) fn trim(
        &self,
        truncated_degree: usize,
    ) -> Result<(CommitKey, OpeningKey), Error> {
        let truncated_commit_key = self
            .commit_key
            .truncate(truncated_degree + Self::ADDED_BLINDING_DEGREE)?;
        let opening_key = self.opening_key.clone();
        Ok((truncated_commit_key, opening_key))
    }

    /// 返回当前公共参数可支持的最大多项式度数。
    /// 该值来自 commit key 长度，与电路最大约束规模直接相关。
    /// 上层在编译电路前可用它做容量上界检查。
    pub fn max_degree(&self) -> usize {
        self.commit_key.max_degree()
    }

    /// 切分序列化后的 opening key 与 commit key 字节区间。
    #[inline]
    fn split_serialized_sections(bytes: &[u8]) -> (&[u8], &[u8]) {
        let opening_key_bytes = &bytes[..OpeningKey::SIZE];
        let commit_key_bytes = &bytes[OpeningKey::SIZE..];
        (opening_key_bytes, commit_key_bytes)
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use coset_bls12_381::BlsScalar;
    use rand_core::OsRng;

    #[test]
    fn test_powers_of() {
        let scalar = BlsScalar::from(10u64);
        let degree = 100u64;

        let powers_of_scalar = util::powers_of(&scalar, degree as usize);

        for (power_index, power_value) in powers_of_scalar.iter().enumerate() {
            assert_eq!(*power_value, scalar.pow(&[power_index as u64, 0, 0, 0]))
        }

        let last_element = powers_of_scalar.last().unwrap();
        assert_eq!(*last_element, scalar.pow(&[degree, 0, 0, 0]))
    }

    #[test]
    fn test_serialize_deserialize_public_parameter() {
        let public_parameters =
            PublicParameters::setup(1 << 7, &mut OsRng).unwrap();

        let deserialized_parameters =
            PublicParameters::from_slice(&public_parameters.to_var_bytes())
                .unwrap();

        assert_eq!(
            deserialized_parameters.commit_key.powers_of_g,
            public_parameters.commit_key.powers_of_g
        );
        assert_eq!(
            deserialized_parameters.opening_key.g,
            public_parameters.opening_key.g
        );
        assert_eq!(
            deserialized_parameters.opening_key.h,
            public_parameters.opening_key.h
        );
        assert_eq!(
            deserialized_parameters.opening_key.x_h,
            public_parameters.opening_key.x_h
        );
    }

    #[test]
    fn public_parameters_bytes_unchecked() {
        let public_parameters =
            PublicParameters::setup(1 << 7, &mut OsRng).unwrap();

        let deserialized_parameters = unsafe {
            let bytes = public_parameters.to_raw_var_bytes();
            PublicParameters::from_slice_unchecked(&bytes)
        };

        assert_eq!(
            public_parameters.commit_key,
            deserialized_parameters.commit_key
        );
        assert_eq!(
            public_parameters.opening_key.g,
            deserialized_parameters.opening_key.g
        );
        assert_eq!(
            public_parameters.opening_key.h,
            deserialized_parameters.opening_key.h
        );
        assert_eq!(
            public_parameters.opening_key.x_h,
            deserialized_parameters.opening_key.x_h
        );
    }
}
