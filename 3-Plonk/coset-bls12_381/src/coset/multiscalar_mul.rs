use crate::{
    g1::{G1Affine, G1Projective},
    scalar::Scalar,
};

use alloc::vec::*;

#[cfg(feature = "byteorder")]
pub fn pippenger<P, I>(points: P, scalars: I) -> G1Projective
where
    P: Iterator<Item = G1Projective>,
    I: Iterator<Item = Scalar>,
{
    let size = scalars.size_hint().0;

    let window_bits = if size < 500 {
        6
    } else if size < 800 {
        7
    } else {
        8
    };

    let max_digit: usize = 1 << window_bits;
    let digits_count: usize = to_radix_2w_size_hint(window_bits);
    let buckets_count: usize = max_digit / 2;

    let scalars = scalars.map(|scalar| to_radix_2w(&scalar, window_bits));
    let scalars_points = scalars.zip(points).collect::<Vec<_>>();

    let mut buckets: Vec<_> = (0..buckets_count)
        .map(|_| G1Projective::identity())
        .collect();

    let mut columns = (0..digits_count).rev().map(|digit_index| {
        for item in buckets.iter_mut() {
            *item = G1Projective::identity();
        }

        for (digits, pt) in scalars_points.iter() {
            let digit = digits[digit_index] as i16;
            #[allow(clippy::comparison_chain)]
            if digit > 0 {
                let bucket_index = (digit - 1) as usize;
                buckets[bucket_index] += pt;
            } else if digit < 0 {
                let bucket_index = (-digit - 1) as usize;
                buckets[bucket_index] -= pt;
            }
        }

        let mut buckets_intermediate_sum = buckets[buckets_count - 1];
        let mut buckets_sum = buckets[buckets_count - 1];
        for i in (0..(buckets_count - 1)).rev() {
            buckets_intermediate_sum += buckets[i];
            buckets_sum += buckets_intermediate_sum;
        }

        buckets_sum
    });

    let hi_column = columns.next().unwrap();

    columns.fold(hi_column, |total, column_sum| {
        mul_by_pow_2(&total, window_bits as u32) + column_sum
    })
}

#[cfg(feature = "byteorder")]
pub(crate) fn mul_by_pow_2(point: &G1Projective, k: u32) -> G1Projective {
    debug_assert!(k > 0);
    let mut doubled_point: G1Projective;
    let mut current_point = point;
    for _ in 0..(k - 1) {
        doubled_point = current_point.double();
        current_point = &doubled_point;
    }

    current_point.double()
}

#[cfg(feature = "byteorder")]
fn to_radix_2w_size_hint(w: usize) -> usize {
    debug_assert!(w >= 6);
    debug_assert!(w <= 8);

    let digits_count = match w {
        6 => (256 + w - 1) / w,
        7 => (256 + w - 1) / w,

        8 => (256 + w - 1) / w + 1,
        _ => panic!("invalid radix parameter"),
    };

    debug_assert!(digits_count <= 43);
    digits_count
}

#[cfg(feature = "byteorder")]
fn to_radix_2w(scalar: &Scalar, w: usize) -> [i8; 43] {
    debug_assert!(w >= 6);
    debug_assert!(w <= 8);

    use byteorder::{ByteOrder, LittleEndian};

    let mut scalar64x4 = [0u64; 4];
    LittleEndian::read_u64_into(&scalar.to_bytes(), &mut scalar64x4[0..4]);

    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let mut digits = [0i8; 43];
    let digits_count = (256 + w - 1) / w;
    for i in 0..digits_count {
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;

        let bit_buf: u64 = match bit_idx < 64 - w || u64_idx == 3 {
            true => scalar64x4[u64_idx] >> bit_idx,

            false => {
                (scalar64x4[u64_idx] >> bit_idx)
                    | (scalar64x4[1 + u64_idx] << (64 - bit_idx))
            }
        };

        let coef = carry + (bit_buf & window_mask);

        carry = (coef + (radix / 2)) >> w;
        digits[i] = ((coef as i64) - (carry << w) as i64) as i8;
    }

    match w {
        8 => digits[digits_count] += carry as i8,
        _ => digits[digits_count - 1] += (carry << w) as i8,
    }

    digits
}

pub fn msm_variable_base(
    points: &[G1Affine],
    scalars: &[Scalar],
) -> G1Projective {
    #[cfg(feature = "parallel")]
    use rayon::prelude::*;

    let window_size = if scalars.len() < 32 {
        3
    } else {
        ln_without_floats(scalars.len()) + 2
    };

    let num_bits = 255usize;
    let fr_one = Scalar::one();

    let zero = G1Projective::identity();
    let window_starts: Vec<_> = (0..num_bits).step_by(window_size).collect();

    #[cfg(feature = "parallel")]
    let window_starts_iter = window_starts.into_par_iter();
    #[cfg(not(feature = "parallel"))]
    let window_starts_iter = window_starts.into_iter();

    let window_sums: Vec<_> = window_starts_iter
        .map(|window_start| {
            let mut window_sum = zero;

            let mut buckets = alloc::vec![zero; (1 << window_size) - 1];
            scalars
                .iter()
                .zip(points)
                .filter(|(scalar, _)| *scalar != &Scalar::zero())
                .for_each(|(&scalar, base)| {
                    if scalar == fr_one {
                        if window_start == 0 {
                            window_sum = window_sum.add_mixed(base);
                        }
                    } else {
                        let mut reduced_scalar = scalar.reduce();

                        reduced_scalar.divn(window_start as u32);

                        let scalar_window_value =
                            reduced_scalar.0[0] % (1 << window_size);

                        if scalar_window_value != 0 {
                            buckets[(scalar_window_value - 1) as usize] =
                                buckets[(scalar_window_value - 1) as usize]
                                    .add_mixed(base);
                        }
                    }
                });

            let mut running_sum = G1Projective::identity();
            for bucket in buckets.into_iter().rev() {
                running_sum += bucket;
                window_sum += &running_sum;
            }

            window_sum
        })
        .collect();

    let lowest = *window_sums.first().unwrap();

    window_sums[1..]
        .iter()
        .rev()
        .fold(zero, |mut total, window_sum| {
            total += window_sum;
            for _ in 0..window_size {
                total = total.double();
            }
            total
        })
        + lowest
}

fn ln_without_floats(value: usize) -> usize {
    (log2(value) * 69 / 100) as usize
}
fn log2(value: usize) -> u32 {
    if value <= 1 {
        return 0;
    }

    let leading_zeros = value.leading_zeros();
    core::mem::size_of::<usize>() as u32 * 8 - leading_zeros
}

mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(feature = "byteorder")]
    #[test]
    fn pippenger_test() {
        let mut sample_size = 512;
        let arithmetic_start = Scalar::from(2128506u64).invert().unwrap();
        let arithmetic_step = Scalar::from(4443282u64).invert().unwrap();
        let points = (0..sample_size)
            .map(|i| G1Projective::generator() * Scalar::from(1 + i as u64))
            .collect::<Vec<_>>();
        let scalars = (0..sample_size)
            .map(|i| {
                arithmetic_start + (Scalar::from(i as u64) * arithmetic_step)
            })
            .collect::<Vec<_>>();
        let premultiplied: Vec<G1Projective> = scalars
            .iter()
            .zip(points.iter())
            .map(|(sc, pt)| pt * sc)
            .collect();
        while sample_size > 0 {
            let scalars = &scalars[0..sample_size];
            let points = &points[0..sample_size];
            let control: G1Projective =
                premultiplied[0..sample_size].iter().sum();
            let subject = pippenger(
                points.to_vec().into_iter(),
                scalars.to_vec().into_iter(),
            );
            assert_eq!(subject, control);
            sample_size /= 2;
        }
    }

    #[test]
    fn msm_variable_base_test() {
        let points = alloc::vec![G1Affine::generator()];
        let scalars = alloc::vec![Scalar::from(100u64)];
        let premultiplied = G1Projective::generator() * Scalar::from(100u64);
        let subject = msm_variable_base(&points, &scalars);
        assert_eq!(subject, premultiplied);
    }
}
