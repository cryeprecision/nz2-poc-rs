mod benchmarks;

criterion::criterion_main! {
    benchmarks::aead::benches,
    benchmarks::util::benches,
    benchmarks::rapidyenc::benches,
}
