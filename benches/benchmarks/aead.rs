use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use criterion::{Criterion, Throughput, criterion_group};
use nz2_poc_rs::aead;
use std::hint::black_box;

const RAW_FILE: &[u8] = include_bytes!("../../test-data/cat.jpg");

fn file_with_space_for_tag() -> Vec<u8> {
    let mut buffer = vec![0u8; RAW_FILE.len() + aead::TAG_SIZE_BYTES];
    buffer[..RAW_FILE.len()].copy_from_slice(RAW_FILE);
    buffer
}

fn aead_encrypt(c: &mut Criterion) {
    let key = ChaCha20Poly1305::generate_key().unwrap();
    let cipher = ChaCha20Poly1305::new(&key);

    let mut group = c.benchmark_group("aead_encrypt");
    group.throughput(Throughput::Bytes(RAW_FILE.len() as u64));
    group.bench_function("throughput", |b| {
        b.iter_batched(
            file_with_space_for_tag,
            |mut buffer| {
                aead::encrypt_segment(&cipher, 0, &[], &mut buffer).unwrap();
                black_box(&buffer);
            },
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();
}

fn aead_decrypt(c: &mut Criterion) {
    let key = ChaCha20Poly1305::generate_key().unwrap();
    let cipher = ChaCha20Poly1305::new(&key);

    let mut buffer = file_with_space_for_tag();
    aead::encrypt_segment(&cipher, 0, &[], &mut buffer).unwrap();

    let mut group = c.benchmark_group("aead_decrypt");
    group.throughput(Throughput::Bytes(RAW_FILE.len() as u64));
    group.bench_function("throughput", move |b| {
        b.iter_batched(
            || buffer.clone(),
            |mut buffer| {
                _ = aead::decrypt_segment(&cipher, 0, &[], &mut buffer).unwrap();
                black_box(&buffer);
            },
            criterion::BatchSize::LargeInput,
        );
    });
    group.finish();
}

criterion_group!(benches, aead_encrypt, aead_decrypt);
