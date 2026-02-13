// 模块说明：本文件实现 PLONK 组件（src/proof_system/quotient_poly.rs）。

use crate::{
    error::Error,
    fft::{EvaluationDomain, Polynomial},
    proof_system::ProverKey,
};
use alloc::vec::Vec;
use coset_bls12_381::BlsScalar;
#[cfg(feature = "std")]
use rayon::prelude::*;

/// 将向量前 `shift_window` 个元素追加到尾部，供“位移索引”访问。
#[inline]
fn extend_with_prefix(values: &mut Vec<BlsScalar>, shift_window: usize) {
    values.extend_from_within(..shift_window);
}

/// 构造单点电路可满足项（算术/范围/逻辑/固定基/可变基 + 公共输入）。
#[allow(clippy::too_many_arguments)]
#[inline]
fn circuit_term_at(
    prover_key: &ProverKey,
    index: usize,
    range_challenge: &BlsScalar,
    logic_challenge: &BlsScalar,
    fixed_base_challenge: &BlsScalar,
    var_base_challenge: &BlsScalar,
    a_eval: &BlsScalar,
    b_eval: &BlsScalar,
    c_eval: &BlsScalar,
    d_eval: &BlsScalar,
    a_shift_eval: &BlsScalar,
    b_shift_eval: &BlsScalar,
    d_shift_eval: &BlsScalar,
    public_eval: &BlsScalar,
) -> BlsScalar {
    let t_arith = prover_key
        .arithmetic
        .compute_quotient_i(index, a_eval, b_eval, c_eval, d_eval);

    let t_range = prover_key.range.compute_quotient_i(
        index,
        range_challenge,
        a_eval,
        b_eval,
        c_eval,
        d_eval,
        d_shift_eval,
    );

    let t_logic = prover_key.logic.compute_quotient_i(
        index,
        logic_challenge,
        a_eval,
        a_shift_eval,
        b_eval,
        b_shift_eval,
        c_eval,
        d_eval,
        d_shift_eval,
    );

    let t_fixed = prover_key.fixed_base.compute_quotient_i(
        index,
        fixed_base_challenge,
        a_eval,
        a_shift_eval,
        b_eval,
        b_shift_eval,
        c_eval,
        d_eval,
        d_shift_eval,
    );

    let t_var = prover_key.variable_base.compute_quotient_i(
        index,
        var_base_challenge,
        a_eval,
        a_shift_eval,
        b_eval,
        b_shift_eval,
        c_eval,
        d_eval,
        d_shift_eval,
    );

    t_arith + t_range + t_logic + t_fixed + t_var + public_eval
}

pub(crate) fn build_quotient_polynomial(
    domain: &EvaluationDomain,
    prover_key: &ProverKey,
    z_poly: &Polynomial,
    (a_poly, b_poly, c_poly, d_poly): (
        &Polynomial,
        &Polynomial,
        &Polynomial,
        &Polynomial,
    ),
    public_inputs_poly: &Polynomial,
    (
        alpha,
        beta,
        gamma,
        range_challenge,
        logic_challenge,
        fixed_base_challenge,
        var_base_challenge,
    ): &(
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
        BlsScalar,
    ),
) -> Result<Polynomial, Error> {
    let domain_8n = EvaluationDomain::new(8 * domain.size())?;

    let mut z_eval_8n = domain_8n.coset_fft(z_poly);

    let mut a_eval_8n = domain_8n.coset_fft(a_poly);
    let mut b_eval_8n = domain_8n.coset_fft(b_poly);
    let c_eval_8n = domain_8n.coset_fft(c_poly);
    let mut d_eval_8n = domain_8n.coset_fft(d_poly);

    extend_with_prefix(&mut z_eval_8n, 8);
    extend_with_prefix(&mut a_eval_8n, 8);
    extend_with_prefix(&mut b_eval_8n, 8);
    extend_with_prefix(&mut d_eval_8n, 8);

    let circuit_satisfiability_terms = build_circuit_satisfiability_terms(
        domain,
        (
            range_challenge,
            logic_challenge,
            fixed_base_challenge,
            var_base_challenge,
        ),
        prover_key,
        (&a_eval_8n, &b_eval_8n, &c_eval_8n, &d_eval_8n),
        public_inputs_poly,
    );

    let permutation_check_terms = build_permutation_check_terms(
        domain,
        prover_key,
        (&a_eval_8n, &b_eval_8n, &c_eval_8n, &d_eval_8n),
        &z_eval_8n,
        (alpha, beta, gamma),
    );

    #[cfg(not(feature = "std"))]
    let range = (0..domain_8n.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..domain_8n.size()).into_par_iter();

    let quotient: Vec<_> = range
        .map(|index| {
            let numerator = circuit_satisfiability_terms[index]
                + permutation_check_terms[index];
            let denominator = prover_key.v_h_coset_8n()[index];
            numerator * denominator.invert().unwrap()
        })
        .collect();

    let coset = domain_8n.coset_ifft(&quotient);

    Ok(Polynomial::from_coefficients_vec(coset))
}

fn build_circuit_satisfiability_terms(
    domain: &EvaluationDomain,
    (
        range_challenge,
        logic_challenge,
        fixed_base_challenge,
        var_base_challenge,
    ): (&BlsScalar, &BlsScalar, &BlsScalar, &BlsScalar),
    prover_key: &ProverKey,
    (a_eval_8n, b_eval_8n, c_eval_8n, d_eval_8n): (
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
    ),
    pi_poly: &Polynomial,
) -> Vec<BlsScalar> {
    let domain_8n = EvaluationDomain::new(8 * domain.size()).unwrap();
    let public_eval_8n = domain_8n.coset_fft(pi_poly);

    #[cfg(not(feature = "std"))]
    let range = (0..domain_8n.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..domain_8n.size()).into_par_iter();

    let quotient_terms: Vec<_> = range
        .map(|index| {
            let a_eval = &a_eval_8n[index];
            let b_eval = &b_eval_8n[index];
            let c_eval = &c_eval_8n[index];
            let d_eval = &d_eval_8n[index];
            let a_shift_eval = &a_eval_8n[index + 8];
            let b_shift_eval = &b_eval_8n[index + 8];
            let d_shift_eval = &d_eval_8n[index + 8];
            let public_eval = &public_eval_8n[index];
            circuit_term_at(
                prover_key,
                index,
                range_challenge,
                logic_challenge,
                fixed_base_challenge,
                var_base_challenge,
                a_eval,
                b_eval,
                c_eval,
                d_eval,
                a_shift_eval,
                b_shift_eval,
                d_shift_eval,
                public_eval,
            )
        })
        .collect();
    quotient_terms
}

fn build_permutation_check_terms(
    domain: &EvaluationDomain,
    prover_key: &ProverKey,
    (a_eval_8n, b_eval_8n, c_eval_8n, d_eval_8n): (
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
        &[BlsScalar],
    ),
    z_eval_8n: &[BlsScalar],
    (alpha, beta, gamma): (&BlsScalar, &BlsScalar, &BlsScalar),
) -> Vec<BlsScalar> {
    let domain_8n = EvaluationDomain::new(8 * domain.size()).unwrap();
    let l1_poly_alpha =
        build_scaled_first_lagrange_poly(domain, alpha.square());
    let l1_alpha_sq_evals = domain_8n.coset_fft(&l1_poly_alpha);

    #[cfg(not(feature = "std"))]
    let range = (0..domain_8n.size()).into_iter();

    #[cfg(feature = "std")]
    let range = (0..domain_8n.size()).into_par_iter();

    let permutation_terms: Vec<_> = range
        .map(|index| {
            prover_key.permutation.compute_quotient_i(
                index,
                &a_eval_8n[index],
                &b_eval_8n[index],
                &c_eval_8n[index],
                &d_eval_8n[index],
                &z_eval_8n[index],
                &z_eval_8n[index + 8],
                alpha,
                &l1_alpha_sq_evals[index],
                beta,
                gamma,
            )
        })
        .collect();
    permutation_terms
}
fn build_scaled_first_lagrange_poly(
    domain: &EvaluationDomain,
    scale: BlsScalar,
) -> Polynomial {
    let mut x_evals = vec![BlsScalar::zero(); domain.size()];
    x_evals[0] = scale;
    domain.ifft_in_place(&mut x_evals);
    Polynomial::from_coefficients_vec(x_evals)
}
