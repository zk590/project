use coset_bls12_381::BlsScalar;
use coset_bytes::{DeserializableSlice, Serializable};

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{
    ser::{ScratchSpace, Serializer},
    Archive, Deserialize, Serialize,
};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive(bound(serialize = "__S: Serializer + ScratchSpace")),
    archive_attr(derive(CheckBytes))
)]
pub(crate) struct EvaluationDomain {
    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) size: u64,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) log_size_of_group: u32,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) size_as_field_element: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) size_inv: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) group_gen: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) group_gen_inv: BlsScalar,

    #[cfg_attr(feature = "rkyv-impl", omit_bounds)]
    pub(crate) generator_inv: BlsScalar,
}

impl Serializable<{ u64::SIZE + u32::SIZE + 5 * BlsScalar::SIZE }>
    for EvaluationDomain
{
    type Error = coset_bytes::Error;

    #[allow(unused_must_use)]
    /// 将 FFT 域参数编码为定长字节。
    /// 编码内容覆盖规模、生成元及其逆等关键参数，足以完整重建域对象。
    /// 该格式主要用于缓存与跨进程传输，避免重复域初始化计算。
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        use coset_bytes::Write;

        let mut serialized_domain = [0u8; Self::SIZE];
        let mut writer = &mut serialized_domain[..];
        writer.write(&self.size.to_bytes());
        writer.write(&self.log_size_of_group.to_bytes());
        writer.write(&self.size_as_field_element.to_bytes());
        writer.write(&self.size_inv.to_bytes());
        writer.write(&self.group_gen.to_bytes());
        writer.write(&self.group_gen_inv.to_bytes());
        writer.write(&self.generator_inv.to_bytes());

        serialized_domain
    }

    /// 从定长字节恢复 FFT 域参数。
    /// 该过程按固定顺序读取所有字段，任何一步解析失败都会返回错误。
    /// 成功后得到的域对象可直接参与 FFT/IFFT 及相关评估计算。
    fn from_bytes(
        serialized_domain: &[u8; Self::SIZE],
    ) -> Result<EvaluationDomain, Self::Error> {
        let mut domain_reader = &serialized_domain[..];
        let size = u64::from_reader(&mut domain_reader)?;
        let log_size_of_group = u32::from_reader(&mut domain_reader)?;
        let size_as_field_element = BlsScalar::from_reader(&mut domain_reader)?;
        let size_inv = BlsScalar::from_reader(&mut domain_reader)?;
        let group_gen = BlsScalar::from_reader(&mut domain_reader)?;
        let group_gen_inv = BlsScalar::from_reader(&mut domain_reader)?;
        let generator_inv = BlsScalar::from_reader(&mut domain_reader)?;

        Ok(EvaluationDomain {
            size,
            log_size_of_group,
            size_as_field_element,
            size_inv,
            group_gen,
            group_gen_inv,
            generator_inv,
        })
    }
}

#[cfg(feature = "alloc")]
pub(crate) mod alloc {

    use super::*;
    use crate::error::Error;
    use crate::fft::Evaluations;
    #[rustfmt::skip]
    use ::alloc::vec::Vec;
    use core::ops::MulAssign;
    use coset_bls12_381::{GENERATOR, ROOT_OF_UNITY, TWO_ADACITY};
    #[cfg(feature = "std")]
    use rayon::prelude::*;

    impl EvaluationDomain {
        /// 根据系数数量构造最小 2 的幂阶评估域。
        /// 若请求规模超出曲线支持的二进制阶上限会返回错误。
        /// 成功时会同时预计算域大小逆元与生成元逆元，供后续算法复用。
        pub(crate) fn new(num_coeffs: usize) -> Result<Self, Error> {
            let size = num_coeffs.next_power_of_two() as u64;
            let log_size_of_group = size.trailing_zeros();

            if log_size_of_group >= TWO_ADACITY {
                return Err(Error::InvalidEvalDomainSize {
                    log_size_of_group,
                    adacity: TWO_ADACITY,
                });
            }

            let mut group_gen = ROOT_OF_UNITY;
            for _ in log_size_of_group..TWO_ADACITY {
                group_gen = group_gen.square();
            }
            let size_as_field_element = BlsScalar::from(size);
            let size_inv = size_as_field_element.invert().unwrap();

            Ok(EvaluationDomain {
                size,
                log_size_of_group,
                size_as_field_element,
                size_inv,
                group_gen,
                group_gen_inv: group_gen.invert().unwrap(),
                generator_inv: GENERATOR.invert().unwrap(),
            })
        }

        /// 返回当前评估域大小（元素个数）。
        /// 该值总是 2 的幂，且不小于构造时传入的系数需求。
        /// 常用于向量补零与循环边界计算。
        pub(crate) fn size(&self) -> usize {
            self.size as usize
        }

        /// 对系数向量执行 FFT，返回评估值向量。
        /// 输入会被复制到新向量并在内部补零到域大小。
        /// 算法核心由 `best_fft` 执行，输出按域元素顺序排列。
        pub(crate) fn fft(&self, coeffs: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut coeffs = coeffs.to_vec();
            self.fft_in_place(&mut coeffs);
            coeffs
        }

        /// 在原地对系数向量执行 FFT。
        /// 该实现会先补齐长度，再执行蝶形变换，避免调用方手工管理容量。
        /// 适合性能敏感场景下复用已分配缓冲区。
        fn fft_in_place(&self, coeffs: &mut Vec<BlsScalar>) {
            coeffs.resize(self.size(), BlsScalar::zero());
            best_fft(coeffs, self.group_gen, self.log_size_of_group)
        }

        /// 对评估值执行逆 FFT，返回系数向量。
        /// 输入会复制后在内部原地处理，最终得到标准系数表示。
        /// 该函数是 `fft` 的逆过程，二者在同一域参数下可互相还原。
        pub(crate) fn ifft(&self, evals: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut evals = evals.to_vec();
            self.ifft_in_place(&mut evals);
            evals
        }

        #[inline]
        /// 在原地执行逆 FFT 并乘以域大小逆元完成归一化。
        /// 该函数会先补齐向量长度，再使用逆生成元做蝶形变换。
        /// 标准化步骤保证结果与多项式系数语义一致。
        pub(crate) fn ifft_in_place(&self, evals: &mut Vec<BlsScalar>) {
            evals.resize(self.size(), BlsScalar::zero());
            best_fft(evals, self.group_gen_inv, self.log_size_of_group);

            #[cfg(not(feature = "std"))]
            evals.iter_mut().for_each(|val| *val *= &self.size_inv);

            #[cfg(feature = "std")]
            evals.par_iter_mut().for_each(|val| *val *= &self.size_inv);
        }

        /// 将向量按几何级数幂次逐项缩放。
        /// 常用于 coset FFT 前后，把输入映射到陪集域再映回原域。
        /// 该过程不分配新内存，直接在切片上原地更新。
        fn distribute_powers(
            coefficients: &mut [BlsScalar],
            generator: BlsScalar,
        ) {
            let mut current_power = BlsScalar::one();
            coefficients.iter_mut().for_each(|coefficient| {
                *coefficient *= &current_power;
                current_power *= &generator
            })
        }

        /// 执行 coset FFT（先乘陪集生成元幂，再做 FFT）。
        /// 该变换常用于商多项式相关步骤，避免主域根导致的零值退化。
        /// 输出依然位于当前域规模下，只是对应陪集上的评估值。
        pub(crate) fn coset_fft(&self, coeffs: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut coeffs = coeffs.to_vec();
            self.coset_fft_in_place(&mut coeffs);
            coeffs
        }

        /// 在原地执行 coset FFT。
        /// 先做幂次分布将系数映射到陪集，再复用标准 FFT 逻辑。
        /// 该路径减少中间分配，适合批处理场景。
        fn coset_fft_in_place(&self, coeffs: &mut Vec<BlsScalar>) {
            Self::distribute_powers(coeffs, GENERATOR);
            self.fft_in_place(coeffs);
        }

        /// 执行 coset 逆 FFT。
        /// 先做标准 IFFT 回到系数域，再乘以生成元逆幂还原原始坐标系。
        /// 该函数与 `coset_fft` 成对使用。
        pub(crate) fn coset_ifft(&self, evals: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut evals = evals.to_vec();
            self.coset_ifft_in_place(&mut evals);
            evals
        }

        /// 在原地执行 coset 逆 FFT。
        /// 该过程复用 `ifft_in_place` 并追加逆幂分布，还原普通系数表示。
        /// 适用于需要反复在 coset/普通域切换的证明流程。
        fn coset_ifft_in_place(&self, evals: &mut Vec<BlsScalar>) {
            self.ifft_in_place(evals);
            Self::distribute_powers(evals, self.generator_inv);
        }

        #[allow(clippy::needless_range_loop)]
        /// 计算点 `tau` 处的全部拉格朗日基多项式取值。
        /// 若 `tau` 恰落在域元素上，会退化为 one-hot 向量并走快速路径。
        /// 否则通过批量求逆加速分母计算，避免逐项求逆的高开销。
        pub(crate) fn evaluate_all_lagrange_coefficients(
            &self,
            tau: BlsScalar,
        ) -> Vec<BlsScalar> {
            let size = self.size as usize;
            let t_size = tau.pow(&[self.size, 0, 0, 0]);
            let one = BlsScalar::one();
            if t_size == BlsScalar::one() {
                let mut lagrange_values = vec![BlsScalar::zero(); size];
                let mut domain_element = one;
                for index in 0..size {
                    if domain_element == tau {
                        lagrange_values[index] = one;
                        break;
                    }
                    domain_element *= &self.group_gen;
                }
                lagrange_values
            } else {
                use crate::util::batch_inversion;

                let mut running_lagrange_factor =
                    (t_size - one) * self.size_inv;
                let mut running_domain_element = one;
                let mut denominator_terms = vec![BlsScalar::zero(); size];
                let mut lagrange_factors = vec![BlsScalar::zero(); size];
                for index in 0..size {
                    denominator_terms[index] = tau - running_domain_element;
                    lagrange_factors[index] = running_lagrange_factor;
                    running_lagrange_factor *= &self.group_gen;
                    running_domain_element *= &self.group_gen;
                }

                batch_inversion(denominator_terms.as_mut_slice());

                #[cfg(not(feature = "std"))]
                denominator_terms.iter_mut().zip(lagrange_factors).for_each(
                    |(inverted_denominator, lagrange_factor)| {
                        *inverted_denominator =
                            lagrange_factor * *inverted_denominator;
                    },
                );

                #[cfg(feature = "std")]
                denominator_terms
                    .par_iter_mut()
                    .zip(lagrange_factors)
                    .for_each(|(inverted_denominator, lagrange_factor)| {
                        *inverted_denominator =
                            lagrange_factor * *inverted_denominator;
                    });

                denominator_terms
            }
        }

        /// 计算消失多项式 `Z_H(tau) = tau^|H| - 1` 在给定点的取值。
        /// 该值在商多项式约束中用于衡量“是否落在域根集合上”。
        /// 当 `tau` 属于域元素时结果为 0，否则通常为非零。
        pub(crate) fn evaluate_vanishing_polynomial(
            &self,
            tau: &BlsScalar,
        ) -> BlsScalar {
            tau.pow(&[self.size, 0, 0, 0]) - BlsScalar::one()
        }

        /// 在陪集上评估消失多项式，返回对应评估表。
        /// 该结果常被缓存并在证明阶段多次复用，以降低重复计算成本。
        /// 断言保证域大小足以容纳目标多项式度数。
        pub(crate) fn compute_vanishing_poly_over_coset(
            &self,
            poly_degree: u64,
        ) -> Evaluations {
            assert!((self.size() as u64) > poly_degree);
            let coset_generator = GENERATOR.pow(&[poly_degree, 0, 0, 0]);
            let vanishing_evaluations: Vec<_> = (0..self.size())
                .map(|coset_index| {
                    (coset_generator
                        * self.group_gen.pow(&[
                            poly_degree * coset_index as u64,
                            0,
                            0,
                            0,
                        ]))
                        - BlsScalar::one()
                })
                .collect();
            Evaluations::from_vec_and_domain(vanishing_evaluations, *self)
        }

        /// 返回域元素迭代器，从 1 开始按生成元幂次递增。
        /// 迭代长度固定为域大小，遍历顺序与 FFT 使用的群顺序一致。
        /// 可用于构造评估点列表或调试域参数。
        pub(crate) fn elements(&self) -> Elements {
            Elements {
                current_element: BlsScalar::one(),
                current_power: 0,
                domain: *self,
            }
        }
    }

    /// 选择并执行最佳 FFT 实现。
    /// 当前实现固定走串行路径，保留该封装以便未来切换并行策略。
    /// 接口保持稳定，调用方无需感知底层算法选择。
    fn best_fft(values: &mut [BlsScalar], omega: BlsScalar, log_n: u32) {
        serial_fft(values, omega, log_n)
    }

    #[inline]
    /// 计算 `n` 的 `l` 位比特反转结果。
    /// 该函数用于 FFT 预处理中的位逆置换重排步骤。
    /// 输出索引确保后续蝶形运算按就地算法要求访问数据。
    fn bitreverse(mut value: u32, bit_len: u32) -> u32 {
        let mut reversed = 0;
        for _ in 0..bit_len {
            reversed = (reversed << 1) | (value & 1);
            value >>= 1;
        }
        reversed
    }

    /// 执行基 2 Cooley-Tukey 串行 FFT。
    /// 算法分为位逆置换与逐层蝶形合并两阶段，在原地完成变换。
    /// 输入长度必须等于 `2^log_n`，否则会触发断言。
    pub(crate) fn serial_fft(
        values: &mut [BlsScalar],
        omega: BlsScalar,
        log_n: u32,
    ) {
        let domain_size = values.len() as u32;
        assert_eq!(domain_size, 1 << log_n);

        for index in 0..domain_size {
            let reversed_index = bitreverse(index, log_n);
            if index < reversed_index {
                values.swap(reversed_index as usize, index as usize);
            }
        }

        let mut butterfly_step = 1;
        for _ in 0..log_n {
            let root_step = omega.pow(&[
                (domain_size / (2 * butterfly_step)) as u64,
                0,
                0,
                0,
            ]);

            let mut block_start = 0;
            while block_start < domain_size {
                let mut twiddle_factor = BlsScalar::one();
                for offset in 0..butterfly_step {
                    let mut right_value = values
                        [(block_start + offset + butterfly_step) as usize];
                    right_value *= &twiddle_factor;
                    let mut left_value =
                        values[(block_start + offset) as usize];
                    left_value -= &right_value;
                    values[(block_start + offset + butterfly_step) as usize] =
                        left_value;
                    values[(block_start + offset) as usize] += &right_value;
                    twiddle_factor.mul_assign(&root_step);
                }

                block_start += 2 * butterfly_step;
            }

            butterfly_step *= 2;
        }
    }

    #[derive(Debug)]
    pub(crate) struct Elements {
        current_element: BlsScalar,
        current_power: u64,
        domain: EvaluationDomain,
    }

    impl Iterator for Elements {
        type Item = BlsScalar;
        fn next(&mut self) -> Option<BlsScalar> {
            if self.current_power == self.domain.size {
                None
            } else {
                let current_element = self.current_element;
                self.current_element *= &self.domain.group_gen;
                self.current_power += 1;
                Some(current_element)
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use super::*;

    #[test]
    fn size_of_elements() {
        for coeffs in 1..10 {
            let size = 1 << coeffs;
            let domain = EvaluationDomain::new(size).unwrap();
            let domain_size = domain.size();
            assert_eq!(domain_size, domain.elements().count());
        }
    }

    #[test]
    fn elements_contents() {
        for coeffs in 1..10 {
            let size = 1 << coeffs;
            let domain = EvaluationDomain::new(size).unwrap();
            for (i, element) in domain.elements().enumerate() {
                assert_eq!(element, domain.group_gen.pow(&[i as u64, 0, 0, 0]));
            }
        }
    }

    #[test]
    fn coset_bytes_evaluation_domain_serde() {
        let eval_domain = EvaluationDomain::new(1 << (13 - 1))
            .expect("Error in eval_domain generation");
        let bytes = eval_domain.to_bytes();
        let obtained_eval_domain = EvaluationDomain::from_slice(&bytes)
            .expect("Deserialization error");
        assert_eq!(eval_domain, obtained_eval_domain);
    }
}
