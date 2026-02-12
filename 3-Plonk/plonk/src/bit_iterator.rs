use core::mem;

/// 按位遍历字节序列的迭代器。
/// 该迭代器把任意 `AsRef<[u8]>` 输入展开为布尔位流，
/// 常用于电路中的比特分解、逻辑组件与范围约束预处理。
#[derive(Debug, Clone, Copy)]
pub struct BitIterator8<E> {
    scalar: E,

    num_of_total_bits: usize,

    bit_len: usize,
}

impl<E: AsRef<[u8]>> BitIterator8<E> {
    /// 创建按位迭代器。
    /// 初始化时会根据输入长度推导每个元素的比特宽度，并设置总比特计数器。
    /// 迭代顺序遵循内部实现的索引递减策略，适配现有电路位序约定。
    pub fn new(scalar_bytes: E) -> Self {
        let element_count = scalar_bytes.as_ref().len();
        let num_of_total_bits = mem::size_of::<E>() * 8;
        let bits_per_element = num_of_total_bits / element_count;
        BitIterator8 {
            scalar: scalar_bytes,
            num_of_total_bits,
            bit_len: bits_per_element,
        }
    }
}
impl<E: AsRef<[u8]>> Iterator for BitIterator8<E> {
    type Item = bool;

    /// 返回下一个比特值。
    /// 当比特耗尽时返回 `None`，否则按当前位置提取并转换为布尔值。
    /// 该实现会原地递减剩余计数，因此迭代器为一次性消费语义。
    fn next(&mut self) -> Option<bool> {
        if self.num_of_total_bits == 0 {
            None
        } else {
            self.num_of_total_bits -= 1;
            let element_index = self.num_of_total_bits / self.bit_len;
            let bit_index_within_element =
                self.num_of_total_bits % self.bit_len;
            let element_value = self.scalar.as_ref()[element_index];

            let bit = (element_value >> bit_index_within_element) & 1;
            Some(bit > 0)
        }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec::Vec;
    use coset_bls12_381::BlsScalar;

    #[test]
    fn test_bit_iterator8() {
        let mut bit_iterator = BitIterator8::new(BlsScalar::one().to_bytes());
        let expected = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
        for expected_char in expected.chars() {
            assert_eq!(bit_iterator.next().unwrap(), expected_char == '1');
        }
        let _remaining_bits: Vec<_> = bit_iterator.collect();
    }
}
