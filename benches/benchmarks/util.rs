use std::hint::black_box;

use criterion::{Criterion, criterion_group};
use nz2_poc_rs::util;

fn derive_message_id(c: &mut Criterion) {
    let file_key = util::generate_file_key();
    let keys = util::derive_subkeys(&file_key);

    let mut group = c.benchmark_group("derive_message_id");
    group.throughput(criterion::Throughput::Elements(1));
    group.bench_function("throughput", |b| {
        b.iter(|| {
            let ids = util::derive_message_id(&keys, 0);
            black_box(&ids);
        });
    });
    group.finish();
}

criterion_group!(benches, derive_message_id);
