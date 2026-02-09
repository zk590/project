// 模块说明：本文件实现 PLONK 组件（src/fft/domain.rs）。

//

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

        pub(crate) fn size(&self) -> usize {
            self.size as usize
        }

        pub(crate) fn fft(&self, coeffs: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut coeffs = coeffs.to_vec();
            self.fft_in_place(&mut coeffs);
            coeffs
        }

        fn fft_in_place(&self, coeffs: &mut Vec<BlsScalar>) {
            coeffs.resize(self.size(), BlsScalar::zero());
            best_fft(coeffs, self.group_gen, self.log_size_of_group)
        }

        pub(crate) fn ifft(&self, evals: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut evals = evals.to_vec();
            self.ifft_in_place(&mut evals);
            evals
        }

        #[inline]
        pub(crate) fn ifft_in_place(&self, evals: &mut Vec<BlsScalar>) {
            evals.resize(self.size(), BlsScalar::zero());
            best_fft(evals, self.group_gen_inv, self.log_size_of_group);

            #[cfg(not(feature = "std"))]
            evals.iter_mut().for_each(|val| *val *= &self.size_inv);

            #[cfg(feature = "std")]
            evals.par_iter_mut().for_each(|val| *val *= &self.size_inv);
        }

        fn distribute_powers(coeffs: &mut [BlsScalar], g: BlsScalar) {
            let mut pow = BlsScalar::one();
            coeffs.iter_mut().for_each(|c| {
                *c *= &pow;
                pow *= &g
            })
        }

        pub(crate) fn coset_fft(&self, coeffs: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut coeffs = coeffs.to_vec();
            self.coset_fft_in_place(&mut coeffs);
            coeffs
        }

        fn coset_fft_in_place(&self, coeffs: &mut Vec<BlsScalar>) {
            Self::distribute_powers(coeffs, GENERATOR);
            self.fft_in_place(coeffs);
        }

        pub(crate) fn coset_ifft(&self, evals: &[BlsScalar]) -> Vec<BlsScalar> {
            let mut evals = evals.to_vec();
            self.coset_ifft_in_place(&mut evals);
            evals
        }

        fn coset_ifft_in_place(&self, evals: &mut Vec<BlsScalar>) {
            self.ifft_in_place(evals);
            Self::distribute_powers(evals, self.generator_inv);
        }

        #[allow(clippy::needless_range_loop)]

        pub(crate) fn evaluate_all_lagrange_coefficients(
            &self,
            tau: BlsScalar,
        ) -> Vec<BlsScalar> {
            let size = self.size as usize;
            let t_size = tau.pow(&[self.size, 0, 0, 0]);
            let one = BlsScalar::one();
            if t_size == BlsScalar::one() {
                let mut u = vec![BlsScalar::zero(); size];
                let mut omega_i = one;
                for i in 0..size {
                    if omega_i == tau {
                        u[i] = one;
                        break;
                    }
                    omega_i *= &self.group_gen;
                }
                u
            } else {
                use crate::util::batch_inversion;

                let mut l = (t_size - one) * self.size_inv;
                let mut r = one;
                let mut u = vec![BlsScalar::zero(); size];
                let mut ls = vec![BlsScalar::zero(); size];
                for i in 0..size {
                    u[i] = tau - r;
                    ls[i] = l;
                    l *= &self.group_gen;
                    r *= &self.group_gen;
                }

                batch_inversion(u.as_mut_slice());

                #[cfg(not(feature = "std"))]
                u.iter_mut().zip(ls).for_each(|(tau_minus_r, l)| {
                    *tau_minus_r = l * *tau_minus_r;
                });

                #[cfg(feature = "std")]
                u.par_iter_mut().zip(ls).for_each(|(tau_minus_r, l)| {
                    *tau_minus_r = l * *tau_minus_r;
                });

                u
            }
        }

        /// - 1`.
        pub(crate) fn evaluate_vanishing_polynomial(
            &self,
            tau: &BlsScalar,
        ) -> BlsScalar {
            tau.pow(&[self.size, 0, 0, 0]) - BlsScalar::one()
        }

        pub(crate) fn compute_vanishing_poly_over_coset(
            &self,
            poly_degree: u64,
        ) -> Evaluations {
            assert!((self.size() as u64) > poly_degree);
            let coset_gen = GENERATOR.pow(&[poly_degree, 0, 0, 0]);
            let v_h: Vec<_> = (0..self.size())
                .map(|i| {
                    (coset_gen
                        * self.group_gen.pow(&[
                            poly_degree * i as u64,
                            0,
                            0,
                            0,
                        ]))
                        - BlsScalar::one()
                })
                .collect();
            Evaluations::from_vec_and_domain(v_h, *self)
        }

        pub(crate) fn elements(&self) -> Elements {
            Elements {
                cur_elem: BlsScalar::one(),
                cur_pow: 0,
                domain: *self,
            }
        }
    }

    fn best_fft(a: &mut [BlsScalar], omega: BlsScalar, log_n: u32) {
        serial_fft(a, omega, log_n)
    }

    #[inline]
    fn bitreverse(mut n: u32, l: u32) -> u32 {
        let mut r = 0;
        for _ in 0..l {
            r = (r << 1) | (n & 1);
            n >>= 1;
        }
        r
    }

    pub(crate) fn serial_fft(
        a: &mut [BlsScalar],
        omega: BlsScalar,
        log_n: u32,
    ) {
        let n = a.len() as u32;
        assert_eq!(n, 1 << log_n);

        for k in 0..n {
            let rk = bitreverse(k, log_n);
            if k < rk {
                a.swap(rk as usize, k as usize);
            }
        }

        let mut butterfly_step = 1;
        for _ in 0..log_n {
            let root_step =
                omega.pow(&[(n / (2 * butterfly_step)) as u64, 0, 0, 0]);

            let mut block_start = 0;
            while block_start < n {
                let mut w = BlsScalar::one();
                for offset in 0..butterfly_step {
                    let mut right_value =
                        a[(block_start + offset + butterfly_step) as usize];
                    right_value *= &w;
                    let mut left_value = a[(block_start + offset) as usize];
                    left_value -= &right_value;
                    a[(block_start + offset + butterfly_step) as usize] =
                        left_value;
                    a[(block_start + offset) as usize] += &right_value;
                    w.mul_assign(&root_step);
                }

                block_start += 2 * butterfly_step;
            }

            butterfly_step *= 2;
        }
    }

    #[derive(Debug)]
    pub(crate) struct Elements {
        cur_elem: BlsScalar,
        cur_pow: u64,
        domain: EvaluationDomain,
    }

    impl Iterator for Elements {
        type Item = BlsScalar;
        fn next(&mut self) -> Option<BlsScalar> {
            if self.cur_pow == self.domain.size {
                None
            } else {
                let cur_elem = self.cur_elem;
                self.cur_elem *= &self.domain.group_gen;
                self.cur_pow += 1;
                Some(cur_elem)
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
