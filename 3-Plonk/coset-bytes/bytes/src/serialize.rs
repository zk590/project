use super::errors::{BadLength, Error};

/// 定长字节序列化/反序列化接口。
pub trait Serializable<const N: usize> {
    /// 该类型的固定字节长度。
    const SIZE: usize = N;

    type Error;

    /// 从定长字节数组反序列化。
    /// 该函数定义了“字节到类型”的唯一入口，确保编码规则在实现层集中维护。
    /// 调用方需保证字节长度正确，语义合法性由实现类型自行校验并返回错误。
    fn from_bytes(bytes: &[u8; N]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// 将对象序列化为定长字节数组。
    /// 与 `from_bytes` 配对后可形成稳定的二进制表示，便于网络传输或磁盘持久化。
    /// 实现应保持字节序与字段布局一致，避免跨版本解析歧义。
    fn to_bytes(&self) -> [u8; N];
}

/// 为 `Serializable` 提供从切片和 reader 读取的辅助接口。
pub trait DeserializableSlice<const N: usize>: Serializable<N> {
    /// 从任意切片读取前 N 字节并反序列化。
    /// 该方法用于“已有缓冲区”的解码场景，会先校验长度再进行定长拷贝。
    /// 如果切片长度不足，统一返回 `BadLength`，避免部分读取导致的状态不一致。
    fn from_slice(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: BadLength,
    {
        if bytes.len() < N {
            Err(Self::Error::bad_length(bytes.len(), N))
        } else {
            let mut fixed_bytes = [0u8; N];
            fixed_bytes[..N].copy_from_slice(&bytes[..N]);
            Self::from_bytes(&fixed_bytes)
        }
    }

    /// 从 reader 读取 N 字节并反序列化。
    /// 该方法面向流式输入，先尝试读取固定长度字节，再复用 `from_bytes`
    /// 完成解释。 读取失败时使用 reader
    /// 的剩余容量构造错误，帮助快速定位输入不足问题。
    fn from_reader<R>(reader: &mut R) -> Result<Self, Self::Error>
    where
        R: Read,
        Self: Sized,
        Self::Error: BadLength,
    {
        let mut fixed_bytes = [0u8; N];
        reader
            .read(&mut fixed_bytes)
            .map_err(|_| Self::Error::bad_length(reader.capacity(), N))?;

        Self::from_bytes(&fixed_bytes)
    }
}

impl<T, const N: usize> DeserializableSlice<N> for T where T: Serializable<N> {}

pub trait Read {
    /// 返回剩余可读容量。
    /// 该值用于在错误路径中报告“当前可读取字节数”。
    /// 对切片实现来说，容量与剩余长度等价。
    fn capacity(&self) -> usize;

    /// 向 `buffer` 读取字节；长度不足时返回错误。
    /// 实现应保证“要么完整读入，要么报错”，避免调用方拿到部分有效数据。
    /// 成功读取后需要推进内部游标，使后续读取从新位置继续。
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Error>;
}

impl Read for &[u8] {
    /// 返回当前切片还未被消费的长度。
    /// 该实现是无状态计算，开销为 O(1)。
    /// 在错误构造与读取前检查中会被频繁调用。
    #[inline]
    fn capacity(&self) -> usize {
        self.len()
    }

    /// 从切片前缀读取指定长度字节并推进切片“游标”。
    /// 当目标缓冲区大于剩余切片时返回长度错误，不会修改切片状态。
    /// 该实现兼顾单字节与多字节路径，确保小读操作不产生额外拷贝复杂度。
    #[inline]
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        if buffer.len() > self.len() {
            return Err(Error::bad_length(self.len(), buffer.len()));
        }
        let bytes_to_read = buffer.len();
        let (head, tail) = self.split_at(bytes_to_read);

        if bytes_to_read == 1 {
            buffer[0] = head[0];
        } else {
            buffer[..bytes_to_read].copy_from_slice(head);
        }

        *self = tail;
        Ok(bytes_to_read)
    }
}

pub trait Write {
    /// 将 `bytes` 写入目标缓冲区；空间不足时返回错误。
    /// 写入成功后应推进写入位置，使后续写入追加在新位置。
    /// 该接口与 `Read` 对称，便于构建统一的编解码流程。
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Error>;
}

impl Write for &mut [u8] {
    /// 将输入字节写入当前切片前缀，并把切片重置为剩余未写入区域。
    /// 如果空间不足，则返回长度错误并保持原有数据状态不变。
    /// 该策略可用于顺序编码多个字段，降低手动偏移管理复杂度。
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        if bytes.len() > self.len() {
            return Err(Error::bad_length(self.len(), bytes.len()));
        }
        let bytes_to_write = bytes.len();

        let (head, tail) = core::mem::take(self).split_at_mut(bytes_to_write);
        head.copy_from_slice(&bytes[..bytes_to_write]);
        *self = tail;
        Ok(bytes_to_write)
    }
}
