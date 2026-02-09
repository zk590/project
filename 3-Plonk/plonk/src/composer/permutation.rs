// 模块说明：本文件实现 PLONK 组件（src/composer/permutation.rs）。

//

use crate::composer::{WireData, Witness};
use crate::fft::{EvaluationDomain, Polynomial};
use alloc::vec::Vec;
use constants::{K1, K2, K3};
use coset_bls12_381::BlsScalar;
use hashbrown::HashMap;
use itertools::izip;

pub(crate) mod constants;

#[derive(Debug, Clone)]
pub(crate) struct Permutation {
    pub(crate) witness_map: HashMap<Witness, Vec<WireData>>,
}

impl Permutation {
    pub(crate) fn new() -> Permutation {
        Permutation::with_capacity(0)
    }

    pub(crate) fn with_capacity(size: usize) -> Permutation {
        Permutation {
            witness_map: HashMap::with_capacity(size),
        }
    }

    pub(crate) fn new_witness(&mut self) -> Witness {
        let witness = Witness::new(self.witness_map.keys().len());

        self.witness_map
            .insert(witness, Vec::with_capacity(16usize));

        witness
    }

    fn are_witnesses_valid(&self, witnesses: &[Witness]) -> bool {
        witnesses
            .iter()
            .all(|witness| self.witness_map.contains_key(witness))
    }

    pub fn add_witnesses_to_map<T: Into<Witness>>(
        &mut self,
        a: T,
        b: T,
        c: T,
        d: T,
        gate_index: usize,
    ) {
        let left: WireData = WireData::Left(gate_index);
        let right: WireData = WireData::Right(gate_index);
        let output: WireData = WireData::Output(gate_index);
        let fourth: WireData = WireData::Fourth(gate_index);

        self.add_witness_to_map(a.into(), left);
        self.add_witness_to_map(b.into(), right);
        self.add_witness_to_map(c.into(), output);
        self.add_witness_to_map(d.into(), fourth);
    }

    pub(crate) fn add_witness_to_map<T: Into<Witness> + Copy>(
        &mut self,
        witness: T,
        wire_data: WireData,
    ) {
        assert!(self.are_witnesses_valid(&[witness.into()]));

        let mapped_wires = self.witness_map.get_mut(&witness.into()).unwrap();
        mapped_wires.push(wire_data);
    }

    pub(super) fn compute_sigma_permutations(
        &mut self,
        n: usize,
    ) -> [Vec<WireData>; 4] {
        let sigma_1: Vec<_> = (0..n).map(WireData::Left).collect();
        let sigma_2: Vec<_> = (0..n).map(WireData::Right).collect();
        let sigma_3: Vec<_> = (0..n).map(WireData::Output).collect();
        let sigma_4: Vec<_> = (0..n).map(WireData::Fourth).collect();

        let mut sigmas = [sigma_1, sigma_2, sigma_3, sigma_4];

        for (_, wire_data_entries) in self.witness_map.iter() {
            for (wire_index, current_wire) in
                wire_data_entries.iter().enumerate()
            {
                let next_index = match wire_index == wire_data_entries.len() - 1
                {
                    true => 0,
                    false => wire_index + 1,
                };

                let next_wire = &wire_data_entries[next_index];

                match current_wire {
                    WireData::Left(index) => sigmas[0][*index] = *next_wire,
                    WireData::Right(index) => sigmas[1][*index] = *next_wire,
                    WireData::Output(index) => sigmas[2][*index] = *next_wire,
                    WireData::Fourth(index) => sigmas[3][*index] = *next_wire,
                };
            }
        }

        sigmas
    }

    fn build_permutation_lagrange_mapping(
        &self,
        sigma_mapping: &[WireData],
        domain: &EvaluationDomain,
    ) -> Vec<BlsScalar> {
        let roots: Vec<_> = domain.elements().collect();

        let lagrange_poly: Vec<BlsScalar> = sigma_mapping
            .iter()
            .map(|wire_data| match wire_data {
                WireData::Left(index) => {
                    let domain_element = &roots[*index];
                    *domain_element
                }
                WireData::Right(index) => {
                    let domain_element = &roots[*index];
                    K1 * domain_element
                }
                WireData::Output(index) => {
                    let domain_element = &roots[*index];
                    K2 * domain_element
                }
                WireData::Fourth(index) => {
                    let domain_element = &roots[*index];
                    K3 * domain_element
                }
            })
            .collect();

        lagrange_poly
    }

    pub(crate) fn compute_sigma_polynomials(
        &mut self,
        n: usize,
        domain: &EvaluationDomain,
    ) -> [Polynomial; 4] {
        let sigmas = self.compute_sigma_permutations(n);

        assert_eq!(sigmas[0].len(), n);
        assert_eq!(sigmas[1].len(), n);
        assert_eq!(sigmas[2].len(), n);
        assert_eq!(sigmas[3].len(), n);

        let s_sigma_1 =
            self.build_permutation_lagrange_mapping(&sigmas[0], domain);
        let s_sigma_2 =
            self.build_permutation_lagrange_mapping(&sigmas[1], domain);
        let s_sigma_3 =
            self.build_permutation_lagrange_mapping(&sigmas[2], domain);
        let s_sigma_4 =
            self.build_permutation_lagrange_mapping(&sigmas[3], domain);

        let s_sigma_1_poly =
            Polynomial::from_coefficients_vec(domain.ifft(&s_sigma_1));
        let s_sigma_2_poly =
            Polynomial::from_coefficients_vec(domain.ifft(&s_sigma_2));
        let s_sigma_3_poly =
            Polynomial::from_coefficients_vec(domain.ifft(&s_sigma_3));
        let s_sigma_4_poly =
            Polynomial::from_coefficients_vec(domain.ifft(&s_sigma_4));

        [
            s_sigma_1_poly,
            s_sigma_2_poly,
            s_sigma_3_poly,
            s_sigma_4_poly,
        ]
    }

    pub(crate) fn compute_permutation_vec(
        &self,
        domain: &EvaluationDomain,
        wires: [&[BlsScalar]; 4],
        beta: &BlsScalar,
        gamma: &BlsScalar,
        sigma_polys: [&Polynomial; 4],
    ) -> Vec<BlsScalar> {
        let domain_size = domain.size();

        let coset_scalars = vec![BlsScalar::one(), K1, K2, K3];

        let gatewise_wires = izip!(wires[0], wires[1], wires[2], wires[3])
            .map(|(w0, w1, w2, w3)| vec![w0, w1, w2, w3]);

        let gatewise_sigmas: Vec<Vec<BlsScalar>> =
            sigma_polys.iter().map(|sigma| domain.fft(sigma)).collect();
        let gatewise_sigmas = izip!(
            &gatewise_sigmas[0],
            &gatewise_sigmas[1],
            &gatewise_sigmas[2],
            &gatewise_sigmas[3]
        )
        .map(|(s0, s1, s2, s3)| vec![s0, s1, s2, s3]);

        let roots: Vec<BlsScalar> = domain.elements().collect();

        let product_argument = izip!(roots, gatewise_sigmas, gatewise_wires)
            .map(|(gate_root, gate_sigmas, gate_wires)| {
                (gate_root, izip!(gate_sigmas, gate_wires, &coset_scalars))
            })
            .map(|(gate_root, wire_params)| {
                (
                    wire_params
                        .clone()
                        .map(|(_sigma, wire_value, coset_scalar)| {
                            wire_value + beta * coset_scalar * gate_root + gamma
                        })
                        .product::<BlsScalar>(),
                    wire_params
                        .map(|(sigma, wire_value, _coset_scalar)| {
                            wire_value + beta * sigma + gamma
                        })
                        .product::<BlsScalar>(),
                )
            })
            .map(|(n, d)| n * d.invert().unwrap())
            .collect::<Vec<BlsScalar>>();

        let mut permutation_accumulator = Vec::with_capacity(domain_size);

        let mut state = BlsScalar::one();
        permutation_accumulator.push(state);

        for product_term in product_argument {
            state *= product_term;
            permutation_accumulator.push(state);
        }

        permutation_accumulator.remove(domain_size);

        assert_eq!(domain_size, permutation_accumulator.len());

        permutation_accumulator
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod test {
    use super::*;
    use crate::fft::Polynomial;
    use coset_bls12_381::BlsScalar;
    use ff::Field;
    use rand_core::OsRng;

    #[allow(dead_code)]
    fn build_fast_permutation_polynomial(
        domain: &EvaluationDomain,
        left_wire_values: &[BlsScalar],
        right_wire_values: &[BlsScalar],
        output_wire_values: &[BlsScalar],
        fourth_wire_values: &[BlsScalar],
        beta: &BlsScalar,
        gamma: &BlsScalar,
        (s_sigma_1_poly, s_sigma_2_poly, s_sigma_3_poly, s_sigma_4_poly): (
            &Polynomial,
            &Polynomial,
            &Polynomial,
            &Polynomial,
        ),
    ) -> Vec<BlsScalar> {
        let domain_size = domain.size();

        let common_roots: Vec<BlsScalar> =
            domain.elements().map(|root| root * beta).collect();

        let s_sigma_1_mapping = domain.fft(s_sigma_1_poly);
        let s_sigma_2_mapping = domain.fft(s_sigma_2_poly);
        let s_sigma_3_mapping = domain.fft(s_sigma_3_poly);
        let s_sigma_4_mapping = domain.fft(s_sigma_4_poly);

        let beta_s_sigma_1: Vec<_> =
            s_sigma_1_mapping.iter().map(|sigma| sigma * beta).collect();
        let beta_s_sigma_2: Vec<_> =
            s_sigma_2_mapping.iter().map(|sigma| sigma * beta).collect();
        let beta_s_sigma_3: Vec<_> =
            s_sigma_3_mapping.iter().map(|sigma| sigma * beta).collect();
        let beta_s_sigma_4: Vec<_> =
            s_sigma_4_mapping.iter().map(|sigma| sigma * beta).collect();

        let beta_roots_k1: Vec<_> = common_roots
            .iter()
            .map(|root_value| root_value * K1)
            .collect();

        let beta_roots_k2: Vec<_> = common_roots
            .iter()
            .map(|root_value| root_value * K2)
            .collect();

        let beta_roots_k3: Vec<_> = common_roots
            .iter()
            .map(|root_value| root_value * K3)
            .collect();

        let left_wire_with_gamma: Vec<_> = left_wire_values
            .iter()
            .map(|wire_value| wire_value + gamma)
            .collect();

        let right_wire_with_gamma: Vec<_> = right_wire_values
            .iter()
            .map(|wire_value| wire_value + gamma)
            .collect();

        let output_wire_with_gamma: Vec<_> = output_wire_values
            .iter()
            .map(|wire_value| wire_value + gamma)
            .collect();

        let fourth_wire_with_gamma: Vec<_> = fourth_wire_values
            .iter()
            .map(|wire_value| wire_value + gamma)
            .collect();

        let accumulator_components_without_l1: Vec<_> = izip!(
            left_wire_with_gamma,
            right_wire_with_gamma,
            output_wire_with_gamma,
            fourth_wire_with_gamma,
            common_roots,
            beta_roots_k1,
            beta_roots_k2,
            beta_roots_k3,
            beta_s_sigma_1,
            beta_s_sigma_2,
            beta_s_sigma_3,
            beta_s_sigma_4,
        )
        .map(
            |(
                a_gamma,
                b_gamma,
                c_gamma,
                d_gamma,
                beta_root,
                beta_root_k1,
                beta_root_k2,
                beta_root_k3,
                beta_s_sigma_1,
                beta_s_sigma_2,
                beta_s_sigma_3,
                beta_s_sigma_4,
            )| {
                let left_numerator_component = left_wire_with_gamma + beta_root;

                let right_numerator_component =
                    right_wire_with_gamma + beta_root_k1;

                let output_numerator_component =
                    output_wire_with_gamma + beta_root_k2;

                let fourth_numerator_component =
                    fourth_wire_with_gamma + beta_root_k3;

                let left_denominator_component =
                    (left_wire_with_gamma + beta_s_sigma_1).invert().unwrap();

                let right_denominator_component =
                    (right_wire_with_gamma + beta_s_sigma_2).invert().unwrap();

                let output_denominator_component =
                    (output_wire_with_gamma + beta_s_sigma_3).invert().unwrap();

                let fourth_denominator_component =
                    (fourth_wire_with_gamma + beta_s_sigma_4).invert().unwrap();

                [
                    left_numerator_component,
                    right_numerator_component,
                    output_numerator_component,
                    fourth_numerator_component,
                    left_denominator_component,
                    right_denominator_component,
                    output_denominator_component,
                    fourth_denominator_component,
                ]
            },
        )
        .collect();

        let accumulator_components = core::iter::once([BlsScalar::one(); 8])
            .chain(accumulator_components_without_l1);

        let mut prev = [BlsScalar::one(); 8];

        let product_accumulated_components: Vec<_> = accumulator_components
            .map(|current_component| {
                current_component
                    .iter()
                    .zip(prev.iter_mut())
                    .for_each(|(curr, prev)| *prev *= curr);
                prev
            })
            .collect();

        let mut permutation_accumulator: Vec<_> =
            product_accumulated_components
                .iter()
                .map(move |current_component| {
                    current_component.iter().product()
                })
                .collect();

        permutation_accumulator.remove(domain_size);

        assert_eq!(domain_size, permutation_accumulator.len());

        permutation_accumulator
    }

    fn build_slow_permutation_polynomial<I>(
        domain: &EvaluationDomain,
        left_wire_values: I,
        right_wire_values: I,
        output_wire_values: I,
        fourth_wire_values: I,
        beta: &BlsScalar,
        gamma: &BlsScalar,
        (s_sigma_1_poly, s_sigma_2_poly, s_sigma_3_poly, s_sigma_4_poly): (
            &Polynomial,
            &Polynomial,
            &Polynomial,
            &Polynomial,
        ),
    ) -> (Vec<BlsScalar>, Vec<BlsScalar>, Vec<BlsScalar>)
    where
        I: Iterator<Item = BlsScalar>,
    {
        let domain_size = domain.size();

        let s_sigma_1_mapping = domain.fft(s_sigma_1_poly);
        let s_sigma_2_mapping = domain.fft(s_sigma_2_poly);
        let s_sigma_3_mapping = domain.fft(s_sigma_3_poly);
        let s_sigma_4_mapping = domain.fft(s_sigma_4_poly);

        let beta_s_sigma_1_iter =
            s_sigma_1_mapping.iter().map(|sigma| *sigma * beta);
        let beta_s_sigma_2_iter =
            s_sigma_2_mapping.iter().map(|sigma| *sigma * beta);
        let beta_s_sigma_3_iter =
            s_sigma_3_mapping.iter().map(|sigma| *sigma * beta);
        let beta_s_sigma_4_iter =
            s_sigma_4_mapping.iter().map(|sigma| *sigma * beta);

        let beta_roots_iter = domain.elements().map(|root| root * beta);

        let beta_roots_k1_iter = domain.elements().map(|root| K1 * beta * root);

        let beta_roots_k2_iter = domain.elements().map(|root| K2 * beta * root);

        let beta_roots_k3_iter = domain.elements().map(|root| K3 * beta * root);

        let left_wire_with_gamma: Vec<_> = left_wire_values
            .map(|wire_value| wire_value + gamma)
            .collect();

        let right_wire_with_gamma: Vec<_> = right_wire_values
            .map(|wire_value| wire_value + gamma)
            .collect();

        let output_wire_with_gamma: Vec<_> = output_wire_values
            .map(|wire_value| wire_value + gamma)
            .collect();

        let fourth_wire_with_gamma: Vec<_> = fourth_wire_values
            .map(|wire_value| wire_value + gamma)
            .collect();

        let mut numerator_partial_components: Vec<BlsScalar> =
            Vec::with_capacity(domain_size);
        let mut denominator_partial_components: Vec<BlsScalar> =
            Vec::with_capacity(domain_size);

        let mut numerator_coefficients: Vec<BlsScalar> =
            Vec::with_capacity(domain_size);
        let mut denominator_coefficients: Vec<BlsScalar> =
            Vec::with_capacity(domain_size);

        numerator_coefficients.push(BlsScalar::one());
        denominator_coefficients.push(BlsScalar::one());

        for (
            a_gamma,
            b_gamma,
            c_gamma,
            d_gamma,
            beta_root,
            beta_root_k1,
            beta_root_k2,
            beta_root_k3,
        ) in izip!(
            left_wire_with_gamma.iter(),
            right_wire_with_gamma.iter(),
            output_wire_with_gamma.iter(),
            fourth_wire_with_gamma.iter(),
            beta_roots_iter,
            beta_roots_k1_iter,
            beta_roots_k2_iter,
            beta_roots_k3_iter,
        ) {
            let prod_a = beta_root + a_gamma;

            let prod_b = beta_root_k1 + b_gamma;

            let prod_c = beta_root_k2 + c_gamma;

            let prod_d = beta_root_k3 + d_gamma;

            let mut numerator_term = prod_a * prod_b * prod_c * prod_d;

            numerator_partial_components.push(numerator_term);

            numerator_term *= numerator_coefficients.last().unwrap();

            numerator_coefficients.push(numerator_term);
        }

        for (
            a_gamma,
            b_gamma,
            c_gamma,
            d_gamma,
            beta_s_sigma_1,
            beta_s_sigma_2,
            beta_s_sigma_3,
            beta_s_sigma_4,
        ) in izip!(
            left_wire_with_gamma,
            right_wire_with_gamma,
            output_wire_with_gamma,
            fourth_wire_with_gamma,
            beta_s_sigma_1_iter,
            beta_s_sigma_2_iter,
            beta_s_sigma_3_iter,
            beta_s_sigma_4_iter,
        ) {
            let prod_a = beta_s_sigma_1 + a_gamma;

            let prod_b = beta_s_sigma_2 + b_gamma;

            let prod_c = beta_s_sigma_3 + c_gamma;

            let prod_d = beta_s_sigma_4 + d_gamma;

            let mut denominator_term = prod_a * prod_b * prod_c * prod_d;

            denominator_partial_components.push(denominator_term);

            let previous_denominator = denominator_coefficients.last().unwrap();

            denominator_term *= previous_denominator;

            denominator_coefficients.push(denominator_term);
        }

        assert_eq!(denominator_coefficients.len(), domain_size + 1);
        assert_eq!(numerator_coefficients.len(), domain_size + 1);

        let numerator_last = numerator_coefficients.pop().unwrap();
        assert_ne!(numerator_last, BlsScalar::zero());
        let denominator_last = denominator_coefficients.pop().unwrap();
        assert_ne!(denominator_last, BlsScalar::zero());
        assert_eq!(
            numerator_last * denominator_last.invert().unwrap(),
            BlsScalar::one()
        );

        let mut z_coefficients: Vec<BlsScalar> =
            Vec::with_capacity(domain_size);
        for (numerator, denominator) in numerator_coefficients
            .iter()
            .zip(denominator_coefficients.iter())
        {
            z_coefficients.push(*numerator * denominator.invert().unwrap());
        }
        assert_eq!(z_coefficients.len(), domain_size);

        (
            z_coefficients,
            numerator_partial_components,
            denominator_partial_components,
        )
    }

    #[test]
    fn test_permutation_format() {
        let mut perm: Permutation = Permutation::new();

        let num_witnesses = 10u8;
        for i in 0..num_witnesses {
            let var = perm.new_witness();
            assert_eq!(var.index(), i as usize);
            assert_eq!(perm.witness_map.len(), (i as usize) + 1);
        }

        let var_one = perm.new_witness();
        let var_two = perm.new_witness();
        let var_three = perm.new_witness();

        let gate_size = 100;
        for i in 0..gate_size {
            perm.add_witnesses_to_map(var_one, var_one, var_two, var_three, i);
        }

        for (_, wire_data) in perm.witness_map.iter() {
            for wire in wire_data.iter() {
                match wire {
                    WireData::Left(index)
                    | WireData::Right(index)
                    | WireData::Output(index)
                    | WireData::Fourth(index) => assert!(*index < gate_size),
                };
            }
        }
    }

    #[test]
    fn test_permutation_compute_sigmas_only_left_wires() {
        let mut perm = Permutation::new();

        let var_zero = perm.new_witness();
        let var_two = perm.new_witness();
        let var_three = perm.new_witness();
        let var_four = perm.new_witness();
        let var_five = perm.new_witness();
        let var_six = perm.new_witness();
        let var_seven = perm.new_witness();
        let var_eight = perm.new_witness();
        let var_nine = perm.new_witness();

        let num_wire_mappings = 4;

        perm.add_witnesses_to_map(var_zero, var_zero, var_five, var_nine, 0);
        perm.add_witnesses_to_map(var_zero, var_two, var_six, var_nine, 1);
        perm.add_witnesses_to_map(var_zero, var_three, var_seven, var_nine, 2);
        perm.add_witnesses_to_map(var_zero, var_four, var_eight, var_nine, 3);

        let sigmas = perm.compute_sigma_permutations(num_wire_mappings);
        let s_sigma_1 = &sigmas[0];
        let s_sigma_2 = &sigmas[1];
        let s_sigma_3 = &sigmas[2];
        let s_sigma_4 = &sigmas[3];

        assert_eq!(s_sigma_1[0], WireData::Right(0));
        assert_eq!(s_sigma_1[1], WireData::Left(2));
        assert_eq!(s_sigma_1[2], WireData::Left(3));
        assert_eq!(s_sigma_1[3], WireData::Left(0));

        assert_eq!(s_sigma_2[0], WireData::Left(1));
        assert_eq!(s_sigma_2[1], WireData::Right(1));
        assert_eq!(s_sigma_2[2], WireData::Right(2));
        assert_eq!(s_sigma_2[3], WireData::Right(3));

        assert_eq!(s_sigma_3[0], WireData::Output(0));
        assert_eq!(s_sigma_3[1], WireData::Output(1));
        assert_eq!(s_sigma_3[2], WireData::Output(2));
        assert_eq!(s_sigma_3[3], WireData::Output(3));

        assert_eq!(s_sigma_4[0], WireData::Fourth(1));
        assert_eq!(s_sigma_4[1], WireData::Fourth(2));
        assert_eq!(s_sigma_4[2], WireData::Fourth(3));
        assert_eq!(s_sigma_4[3], WireData::Fourth(0));

        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();
        let domain_generator = domain.group_gen;
        let domain_generator_squared = domain_generator.pow(&[2, 0, 0, 0]);
        let domain_generator_cubed = domain_generator.pow(&[3, 0, 0, 0]);

        let encoded_s_sigma_1 =
            perm.build_permutation_lagrange_mapping(s_sigma_1, &domain);
        assert_eq!(encoded_s_sigma_1[0], BlsScalar::one() * K1);
        assert_eq!(encoded_s_sigma_1[1], domain_generator_squared);
        assert_eq!(encoded_s_sigma_1[2], domain_generator_cubed);
        assert_eq!(encoded_s_sigma_1[3], BlsScalar::one());

        let encoded_s_sigma_2 =
            perm.build_permutation_lagrange_mapping(s_sigma_2, &domain);
        assert_eq!(encoded_s_sigma_2[0], domain_generator);
        assert_eq!(encoded_s_sigma_2[1], domain_generator * K1);
        assert_eq!(encoded_s_sigma_2[2], domain_generator_squared * K1);
        assert_eq!(encoded_s_sigma_2[3], domain_generator_cubed * K1);

        let encoded_s_sigma_3 =
            perm.build_permutation_lagrange_mapping(s_sigma_3, &domain);
        assert_eq!(encoded_s_sigma_3[0], BlsScalar::one() * K2);
        assert_eq!(encoded_s_sigma_3[1], domain_generator * K2);
        assert_eq!(encoded_s_sigma_3[2], domain_generator_squared * K2);
        assert_eq!(encoded_s_sigma_3[3], domain_generator_cubed * K2);

        let encoded_s_sigma_4 =
            perm.build_permutation_lagrange_mapping(s_sigma_4, &domain);
        assert_eq!(encoded_s_sigma_4[0], domain_generator * K3);
        assert_eq!(encoded_s_sigma_4[1], domain_generator_squared * K3);
        assert_eq!(encoded_s_sigma_4[2], domain_generator_cubed * K3);
        assert_eq!(encoded_s_sigma_4[3], K3);

        let left_wire_values = vec![
            BlsScalar::from(2),
            BlsScalar::from(2),
            BlsScalar::from(2),
            BlsScalar::from(2),
        ];
        let right_wire_values = vec![
            BlsScalar::from(2),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
        ];
        let output_wire_values = vec![
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
        ];
        let fourth_wire_values = vec![
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::one(),
        ];

        test_correct_permutation_poly(
            num_wire_mappings,
            perm,
            &domain,
            left_wire_values,
            right_wire_values,
            output_wire_values,
            fourth_wire_values,
        );
    }

    #[test]
    fn test_permutation_compute_sigmas() {
        let mut perm: Permutation = Permutation::new();

        let var_one = perm.new_witness();
        let var_two = perm.new_witness();
        let var_three = perm.new_witness();
        let var_four = perm.new_witness();

        let num_wire_mappings = 4;

        perm.add_witnesses_to_map(var_one, var_one, var_two, var_four, 0);
        perm.add_witnesses_to_map(var_two, var_one, var_two, var_four, 1);
        perm.add_witnesses_to_map(var_three, var_three, var_one, var_four, 2);
        perm.add_witnesses_to_map(var_two, var_one, var_three, var_four, 3);

        let sigmas = perm.compute_sigma_permutations(num_wire_mappings);
        let s_sigma_1 = &sigmas[0];
        let s_sigma_2 = &sigmas[1];
        let s_sigma_3 = &sigmas[2];
        let s_sigma_4 = &sigmas[3];

        assert_eq!(s_sigma_1[0], WireData::Right(0));
        assert_eq!(s_sigma_1[1], WireData::Output(1));
        assert_eq!(s_sigma_1[2], WireData::Right(2));
        assert_eq!(s_sigma_1[3], WireData::Output(0));

        assert_eq!(s_sigma_2[0], WireData::Right(1));
        assert_eq!(s_sigma_2[1], WireData::Output(2));
        assert_eq!(s_sigma_2[2], WireData::Output(3));
        assert_eq!(s_sigma_2[3], WireData::Left(0));

        assert_eq!(s_sigma_3[0], WireData::Left(1));
        assert_eq!(s_sigma_3[1], WireData::Left(3));
        assert_eq!(s_sigma_3[2], WireData::Right(3));
        assert_eq!(s_sigma_3[3], WireData::Left(2));

        assert_eq!(s_sigma_4[0], WireData::Fourth(1));
        assert_eq!(s_sigma_4[1], WireData::Fourth(2));
        assert_eq!(s_sigma_4[2], WireData::Fourth(3));
        assert_eq!(s_sigma_4[3], WireData::Fourth(0));

        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();
        let domain_generator = domain.group_gen;
        let domain_generator_squared = domain_generator.pow(&[2, 0, 0, 0]);
        let domain_generator_cubed = domain_generator.pow(&[3, 0, 0, 0]);

        let encoded_s_sigma_1 =
            perm.build_permutation_lagrange_mapping(s_sigma_1, &domain);
        assert_eq!(encoded_s_sigma_1[0], K1);
        assert_eq!(encoded_s_sigma_1[1], domain_generator * K2);
        assert_eq!(encoded_s_sigma_1[2], domain_generator_squared * K1);
        assert_eq!(encoded_s_sigma_1[3], BlsScalar::one() * K2);

        let encoded_s_sigma_2 =
            perm.build_permutation_lagrange_mapping(s_sigma_2, &domain);
        assert_eq!(encoded_s_sigma_2[0], domain_generator * K1);
        assert_eq!(encoded_s_sigma_2[1], domain_generator_squared * K2);
        assert_eq!(encoded_s_sigma_2[2], domain_generator_cubed * K2);
        assert_eq!(encoded_s_sigma_2[3], BlsScalar::one());

        let encoded_s_sigma_3 =
            perm.build_permutation_lagrange_mapping(s_sigma_3, &domain);
        assert_eq!(encoded_s_sigma_3[0], domain_generator);
        assert_eq!(encoded_s_sigma_3[1], domain_generator_cubed);
        assert_eq!(encoded_s_sigma_3[2], domain_generator_cubed * K1);
        assert_eq!(encoded_s_sigma_3[3], domain_generator_squared);

        let encoded_s_sigma_4 =
            perm.build_permutation_lagrange_mapping(s_sigma_4, &domain);
        assert_eq!(encoded_s_sigma_4[0], domain_generator * K3);
        assert_eq!(encoded_s_sigma_4[1], domain_generator_squared * K3);
        assert_eq!(encoded_s_sigma_4[2], domain_generator_cubed * K3);
        assert_eq!(encoded_s_sigma_4[3], K3);
    }

    #[test]
    fn test_basic_slow_permutation_poly() {
        let num_wire_mappings = 2;
        let mut perm = Permutation::new();
        let domain = EvaluationDomain::new(num_wire_mappings).unwrap();

        let var_one = perm.new_witness();
        let var_two = perm.new_witness();
        let var_three = perm.new_witness();
        let var_four = perm.new_witness();

        perm.add_witnesses_to_map(var_one, var_two, var_three, var_four, 0);
        perm.add_witnesses_to_map(var_three, var_two, var_one, var_four, 1);

        let left_wire_values: Vec<_> =
            vec![BlsScalar::one(), BlsScalar::from(3)];
        let right_wire_values: Vec<_> =
            vec![BlsScalar::from(2), BlsScalar::from(2)];
        let output_wire_values: Vec<_> =
            vec![BlsScalar::from(3), BlsScalar::one()];
        let fourth_wire_values: Vec<_> =
            vec![BlsScalar::one(), BlsScalar::one()];

        test_correct_permutation_poly(
            num_wire_mappings,
            perm,
            &domain,
            left_wire_values,
            right_wire_values,
            output_wire_values,
            fourth_wire_values,
        );
    }

    fn shift_poly_by_one(z_coefficients: Vec<BlsScalar>) -> Vec<BlsScalar> {
        let mut shifted_z_coefficients = z_coefficients;
        shifted_z_coefficients.push(shifted_z_coefficients[0]);
        shifted_z_coefficients.remove(0);
        shifted_z_coefficients
    }

    fn test_correct_permutation_poly(
        n: usize,
        mut perm: Permutation,
        domain: &EvaluationDomain,
        a: Vec<BlsScalar>,
        b: Vec<BlsScalar>,
        c: Vec<BlsScalar>,
        d: Vec<BlsScalar>,
    ) {
        //
        let beta = BlsScalar::random(&mut OsRng);
        let gamma = BlsScalar::random(&mut OsRng);
        assert_ne!(gamma, beta);

        let [s_sigma_1_poly, s_sigma_2_poly, s_sigma_3_poly, s_sigma_4_poly] =
            perm.compute_sigma_polynomials(n, domain);
        let (z_vec, numerator_components, denominator_components) =
            build_slow_permutation_polynomial(
                domain,
                a.clone().into_iter(),
                b.clone().into_iter(),
                c.clone().into_iter(),
                d.clone().into_iter(),
                &beta,
                &gamma,
                (
                    &s_sigma_1_poly,
                    &s_sigma_2_poly,
                    &s_sigma_3_poly,
                    &s_sigma_4_poly,
                ),
            );

        let fast_z_vec = build_fast_permutation_polynomial(
            domain,
            &a,
            &b,
            &c,
            &d,
            &beta,
            &gamma,
            (
                &s_sigma_1_poly,
                &s_sigma_2_poly,
                &s_sigma_3_poly,
                &s_sigma_4_poly,
            ),
        );
        assert_eq!(fast_z_vec, z_vec);

        //

        // `1`
        assert_eq!(z_vec.len(), n);
        assert_eq!(&z_vec[0], &BlsScalar::one());
        //

        let (mut a_0, mut b_0) = (BlsScalar::one(), BlsScalar::one());
        for n in numerator_components.iter() {
            a_0 *= n;
        }
        for n in denominator_components.iter() {
            b_0 *= n;
        }
        assert_eq!(a_0 * b_0.invert().unwrap(), BlsScalar::one());

        let z_poly = Polynomial::from_coefficients_vec(domain.ifft(&z_vec));
        //

        assert_eq!(z_poly.evaluate(&BlsScalar::one()), BlsScalar::one());
        let n_plus_one = domain.elements().last().unwrap() * domain.group_gen;
        assert_eq!(z_poly.evaluate(&n_plus_one), BlsScalar::one());
        //

        assert_eq!(z_poly.degree(), n - 1);
        //

        let roots: Vec<_> = domain.elements().collect();

        for i in 1..roots.len() {
            let current_root = roots[i];
            let next_root = current_root * domain.group_gen;

            let current_identity_perm_product = &numerator_components[i];
            assert_ne!(current_identity_perm_product, &BlsScalar::zero());

            let current_copy_perm_product = &denominator_components[i];
            assert_ne!(current_copy_perm_product, &BlsScalar::zero());

            assert_ne!(
                current_copy_perm_product,
                current_identity_perm_product
            );

            let z_eval = z_poly.evaluate(&current_root);
            assert_ne!(z_eval, BlsScalar::zero());

            let z_eval_shifted = z_poly.evaluate(&next_root);
            assert_ne!(z_eval_shifted, BlsScalar::zero());

            let lhs = z_eval_shifted * current_copy_perm_product;

            let rhs = z_eval * current_identity_perm_product;
            assert_eq!(
                lhs, rhs,
                "check failed at index: {}\'n lhs is : {:?} \n rhs is :{:?}",
                i, lhs, rhs
            );
        }

        let shifted_z = shift_poly_by_one(fast_z_vec);
        let shifted_z_poly =
            Polynomial::from_coefficients_vec(domain.ifft(&shifted_z));
        for element in domain.elements() {
            let z_eval = z_poly.evaluate(&(element * domain.group_gen));
            let shifted_z_eval = shifted_z_poly.evaluate(&element);

            assert_eq!(z_eval, shifted_z_eval)
        }
    }
}
