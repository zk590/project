//! Fr 标量域运算性能基准：加减乘、平方、求逆与字节编解码。

use coset_jubjub::*;
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_add_assign(c: &mut Criterion) {
    let mut n = Fr::one();
    let neg_one = -Fr::one();
    c.bench_function("Fr add_assign", |b| {
        b.iter(move || {
            n += &neg_one;
        })
    });
}

fn bench_sub_assign(c: &mut Criterion) {
    let mut n = Fr::one();
    let neg_one = -Fr::one();
    c.bench_function("Fr sub_assign", |b| {
        b.iter(move || {
            n -= &neg_one;
        })
    });
}

fn bench_mul_assign(c: &mut Criterion) {
    let mut n = Fr::one();
    let neg_one = -Fr::one();
    c.bench_function("Fr mul_assign", |b| {
        b.iter(move || {
            n *= &neg_one;
        })
    });
}

fn bench_square(c: &mut Criterion) {
    let n = Fr::one();
    c.bench_function("Fr square", |b| b.iter(move || n.square()));
}

fn bench_invert(c: &mut Criterion) {
    let n = Fr::one();
    c.bench_function("Fr invert", |b| b.iter(move || n.invert()));
}

fn bench_sqrt(c: &mut Criterion) {
    let n = Fr::one().double().double();
    c.bench_function("Fr sqrt", |b| b.iter(move || n.sqrt()));
}

criterion_group!(
    benches,
    bench_add_assign,
    bench_sub_assign,
    bench_mul_assign,
    bench_square,
    bench_invert,
    bench_sqrt,
);
criterion_main!(benches);
