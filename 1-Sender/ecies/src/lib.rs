// 外部依赖导入
extern crate core;
// 导入必要的加密库
use aes_gcm::aes::Aes256;
use aes_gcm::{AeadInOut, AesGcm, Key, KeyInit};
use hkdf::Hkdf;
use k256::elliptic_curve::consts::U16;
use k256::elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use k256::{Secp256k1, elliptic_curve};
use sha2::Sha256;
// use rand_core::RngCore; // 未使用的导入

/// Secp256k1 (K-256) 公钥结构
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(elliptic_curve::PublicKey<Secp256k1>);

/// Secp256k1 (K-256) 私钥结构
#[derive(Clone)]
pub struct SecretKey(elliptic_curve::SecretKey<Secp256k1>);

// 常量定义
const COORDINATE_SIZE: usize = 32; // 椭圆曲线域元素的字节大小
const UNCOMPRESSED_PUBLIC_KEY_SIZE: usize = 1 + 2 * COORDINATE_SIZE; // 非压缩公钥大小：1字节前缀 + 32字节x坐标 + 32字节y坐标
const NONCE_SIZE: usize = 16; // AES-GCM使用的nonce大小
const TAG_SIZE: usize = 16; // 认证标签大小

type Aes256Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes256, k256::elliptic_curve::consts::U16>; // 使用完整路径的AES-256-GCM类型别名
type Nonce = [u8; NONCE_SIZE]; // 使用固定大小的字节数组替代泛型Nonce类型

/// 密钥错误类型
#[derive(Debug, thiserror::Error)]
#[error("Invalid key")]
pub struct KeyError;

/// 解密错误类型
#[derive(Debug, thiserror::Error)]
pub enum DecryptError {
    #[error("Invalid ciphertext length")]
    InvalidLength, // 密文长度无效
    #[error("Invalid ephemeral pk")]
    InvalidKey(#[from] KeyError), // 临时公钥无效
    #[error("Invalid nonce")]
    InvalidNonce, // Nonce无效
    #[error("Invalid tag")]
    InvalidTag, // 认证标签无效
    #[error("Decryption failed")]
    Failed(#[from] aes_gcm::Error), // 解密失败
}

/// 公钥相关实现
impl PublicKey {
    /// 从字节数组尝试创建公钥
    pub fn try_from_bytes(input: impl AsRef<[u8]>) -> Result<Self, KeyError> {
        EncodedPoint::<Secp256k1>::from_bytes(input)
            .ok()
            .and_then(|point| {
                elliptic_curve::PublicKey::<Secp256k1>::from_encoded_point(&point).into_option()
            })
            .map(PublicKey)
            .ok_or_else(|| KeyError)
    }

    /// 将公钥转换为字节数组，可选择压缩格式
    pub fn to_bytes(&self, compressed: bool) -> Box<[u8]> {
        self.0.to_encoded_point(compressed).to_bytes()
    }

    /// 使用公钥加密消息（需要rand特性）
    #[cfg(feature = "rand")]
    pub fn encrypt(self, rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore), msg: impl AsRef<[u8]>) -> Vec<u8> {
        use aes_gcm::AeadCore;

        let msg = msg.as_ref();
        
        // 计算密文总长度：临时公钥 + nonce + 标签 + 消息
        let length = UNCOMPRESSED_PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE + msg.len();

        let mut ciphertext = Vec::with_capacity(length);

        // 生成临时密钥对
        let ephemeral_sk = SecretKey::random(rng);
        let ephemeral_pk = ephemeral_sk.public_key();
        // 将临时公钥添加到密文中
        ciphertext.extend_from_slice(&ephemeral_pk.0.to_encoded_point(false).as_ref());

        // 派生共享密钥并创建AES-GCM加密器
        let shared_secret = ephemeral_sk.encapsulate(&self);
        let cipher = Aes256Gcm::new(&shared_secret);
        let nonce_bytes = Aes256Gcm::generate_nonce_with_rng(rng);
        // 添加nonce到密文中
        ciphertext.extend_from_slice(&nonce_bytes);
        let nonce = aes_gcm::Nonce::<U16>::try_from(&nonce_bytes[..]).unwrap();

        // 为标签预留空间，添加消息，然后计算并存储标签
        ciphertext.resize(UNCOMPRESSED_PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE, 0);
        ciphertext.extend_from_slice(&msg);
        let tag = cipher
            .encrypt_inout_detached(
                &nonce,
                b"",
                (&mut ciphertext[UNCOMPRESSED_PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE..]).into(),
            )
            .unwrap();
        ciphertext[UNCOMPRESSED_PUBLIC_KEY_SIZE + NONCE_SIZE
            ..UNCOMPRESSED_PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE]
            .copy_from_slice(&tag);

        ciphertext
    }

    /// 使用私钥解封装共享密钥
    pub fn decapsulate(&self, secret_key: &SecretKey) -> Key<Aes256Gcm> {
        let tweak = secret_key.0.to_nonzero_scalar();

        // 通过椭圆曲线乘法计算共享点
        let shared_point = elliptic_curve::PublicKey::<Secp256k1>::from_affine(
            elliptic_curve::group::Curve::to_affine(&(self.0.to_projective() * tweak.as_ref())),
        )
        .unwrap();

        // 获取共享密钥
        get_shared_secret(&self.0, &shared_point)
    }
}

/// 私钥相关实现
impl SecretKey {
    /// 从字节数组尝试创建私钥
    pub fn try_from_bytes(input: impl AsRef<[u8]>) -> Result<Self, KeyError> {
        elliptic_curve::SecretKey::<Secp256k1>::from_slice(input.as_ref())
            .ok()
            .map(SecretKey)
            .ok_or_else(|| KeyError)
    }

    /// 将私钥转换为字节数组
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_bytes().to_vec().into_boxed_slice()
    }

    /// 从私钥生成对应的公钥
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    /// 生成随机私钥（需要rand特性）
    #[cfg(feature = "rand")]
    pub fn random(rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore)) -> Self {
        let mut bytes = elliptic_curve::FieldBytes::<Secp256k1>::default();
        // 循环直到生成有效的私钥
        loop {
            rng.fill_bytes(&mut bytes);
            if let Some(scalar) = elliptic_curve::NonZeroScalar::from_repr(bytes).into_option() {
                return SecretKey(elliptic_curve::SecretKey::from(scalar));
            }
        }
    }

    /// 解密消息并返回Vec<u8>
    pub fn try_decrypt<'a>(&self, ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let (ephemeral_pk, nonce, tag, buffer) = split_ciphertext(ciphertext)?;
        let mut buffer = buffer.to_vec();
        self.decrypt_inner(ephemeral_pk, &nonce, &tag, buffer.as_mut_slice())?;
        Ok(buffer)
    }

    /// 解密消息并返回固定大小的数组
    pub fn try_decrypt_fixed<'a, const N: usize>(
        &self,
        ciphertext: &[u8],
    ) -> Result<[u8; N], DecryptError> {
        let (ephemeral_pk, nonce, tag, buffer) = split_ciphertext(ciphertext)?;
        let mut buffer: [u8; N] = buffer.try_into().unwrap();
        self.decrypt_inner(ephemeral_pk, &nonce, &tag, buffer.as_mut_slice())?;
        Ok(buffer)
    }

    /// 原地解密消息（不创建新的内存分配）
    pub fn try_decrypt_inplace<'a>(
        &self,
        ciphertext: &'a mut [u8],
    ) -> Result<&'a mut [u8], DecryptError> {
        let (ephemeral_pk, nonce, tag, buffer) = split_ciphertext_mut(ciphertext)?;
        self.decrypt_inner(ephemeral_pk, &nonce, &tag, buffer)?;
        Ok(buffer)
    }

    /// 使用私钥封装共享密钥
    pub fn encapsulate(&self, peer_pk: &PublicKey) -> Key<Aes256Gcm> {
        let tweak = self.0.to_nonzero_scalar();
        // 通过椭圆曲线乘法计算共享点
        let shared_point = elliptic_curve::PublicKey::<Secp256k1>::from_affine(
            elliptic_curve::group::Curve::to_affine(&(peer_pk.0.to_projective() * tweak.as_ref())),
        )
        .unwrap();

        // 获取共享密钥
        get_shared_secret(&self.public_key().0, &shared_point)
    }

    /// 内部解密方法，被各种解密API调用
    #[inline]
    fn decrypt_inner(
        &self,
        ephemeral_pk: PublicKey,
        nonce: &Nonce,
        tag: &[u8; TAG_SIZE],
        buffer: &mut [u8],
    ) -> Result<(), DecryptError> {
        // 派生共享密钥并创建AES-GCM解密器
        let shared_secret = ephemeral_pk.decapsulate(self);
        let cipher = Aes256Gcm::new(&shared_secret);

        // 解密并验证认证标签
        let nonce_obj = aes_gcm::Nonce::<U16>::try_from(&nonce[..]).unwrap();
        cipher.decrypt_inout_detached(&nonce_obj, b"", buffer.into(), tag.into())?;
        Ok(())
    }
}

/// 生成共享密钥的内部函数
#[inline]
fn get_shared_secret(
    sender_point: &elliptic_curve::PublicKey<Secp256k1>,
    shared_point: &elliptic_curve::PublicKey<Secp256k1>,
) -> Key<Aes256Gcm> {
    // 准备用于HKDF的输入材料
    let mut secret = [0u8; 2 * UNCOMPRESSED_PUBLIC_KEY_SIZE];

    // 复制发送方公钥和共享点到输入材料中
    secret[..UNCOMPRESSED_PUBLIC_KEY_SIZE]
        .copy_from_slice(sender_point.to_encoded_point(false).as_ref());
    secret[UNCOMPRESSED_PUBLIC_KEY_SIZE..]
        .copy_from_slice(shared_point.to_encoded_point(false).as_ref());

    // 使用HKDF派生32字节的AES-256密钥
    let h = Hkdf::<Sha256>::new(None, &secret);
    let mut shared_secret = [0u8; 32];
    h.expand(b"", &mut shared_secret).unwrap();

    shared_secret.into()
}

/// 将密文拆分为临时公钥、nonce、标签和消息部分
#[inline]
fn split_ciphertext(ciphertext: &[u8]) -> Result<(PublicKey, Nonce, [u8; TAG_SIZE], &[u8]), DecryptError> {
    // 验证密文长度是否足够
    if ciphertext.len() < UNCOMPRESSED_PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE {
        return Err(DecryptError::InvalidLength);
    }

    // 提取临时公钥
    let (ephemeral_pk_bytes, remaining) = ciphertext.split_at(UNCOMPRESSED_PUBLIC_KEY_SIZE);
    let ephemeral_pk = PublicKey::try_from_bytes(ephemeral_pk_bytes)?;

    // 提取nonce
    let (nonce, remaining) = remaining.split_at(NONCE_SIZE);
    let nonce = Nonce::try_from(nonce).map_err(|_| DecryptError::InvalidNonce)?;
    
    // 提取认证标签和密文数据
    let (tag, buffer) = remaining.split_at(TAG_SIZE);
    let tag = <[u8; TAG_SIZE]>::try_from(tag).map_err(|_| DecryptError::InvalidTag)?;
    Ok((ephemeral_pk, nonce, tag, buffer))
}

/// 可变引用版本的密文拆分函数
#[inline]
fn split_ciphertext_mut(
    ciphertext: &mut [u8],
) -> Result<(PublicKey, Nonce, [u8; TAG_SIZE], &mut [u8]), DecryptError> {
    // 验证密文长度是否足够
    if ciphertext.len() < UNCOMPRESSED_PUBLIC_KEY_SIZE + NONCE_SIZE + TAG_SIZE {
        return Err(DecryptError::InvalidLength);
    }

    // 提取临时公钥
    let (ephemeral_pk_bytes, remaining) = ciphertext.split_at_mut(UNCOMPRESSED_PUBLIC_KEY_SIZE);
    let ephemeral_pk = PublicKey::try_from_bytes(ephemeral_pk_bytes)?;

    // 提取nonce
    let (nonce, remaining) = remaining.split_at_mut(NONCE_SIZE);
    let nonce = Nonce::try_from(&*nonce).map_err(|_| DecryptError::InvalidNonce)?;
    
    // 提取认证标签和密文数据
    let (tag, buffer) = remaining.split_at_mut(TAG_SIZE);
    let tag = <[u8; TAG_SIZE]>::try_from(&*tag).map_err(|_| DecryptError::InvalidTag)?;
    Ok((ephemeral_pk, nonce, tag, buffer))
}