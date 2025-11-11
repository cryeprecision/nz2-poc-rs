use criterion::{Criterion, Throughput, criterion_group};
use std::hint::black_box;

const RAW_FILE: &[u8] = include_bytes!("../../test-data/cat.jpg");
const LINE_WIDTH: u32 = 128;

fn rapidyenc_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("rapidyenc_encode");
    group.throughput(Throughput::Bytes(RAW_FILE.len() as u64));
    group.bench_function("throughput", |b| {
        b.iter(|| {
            let encoded = rapidyenc::encode(RAW_FILE, LINE_WIDTH);
            black_box(&encoded);
        })
    });
    group.finish();
}

fn rapidyenc_decode(c: &mut Criterion) {
    // Pre-encode the since we're testing decoding here
    let encoded = rapidyenc::encode(RAW_FILE, LINE_WIDTH);

    let mut group = c.benchmark_group("rapidyenc_decode");
    group.throughput(Throughput::Bytes(RAW_FILE.len() as u64));
    group.bench_function("throughput", |b| {
        b.iter(|| {
            let mut decoded = encoded.clone();
            rapidyenc::decode(&mut decoded);
            black_box(&decoded);
        })
    });
    group.finish();
}

criterion_group!(benches, rapidyenc_encode, rapidyenc_decode);
