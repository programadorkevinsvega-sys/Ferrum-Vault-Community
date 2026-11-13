use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ferrum_crypto::Aes256GcmProvider;

fn bench_aes_256_gcm(c: &mut Criterion) {
    let key = [0x5A_u8; 32];
    let provider = Aes256GcmProvider::new(&key).expect("valid AES-256 key");
    let aad = b"ferrum/community/phase-1.1/benchmark";

    let mut group = c.benchmark_group("aws_lc_rs_aes_256_gcm");
    for size in [64_usize, 1_024, 16_384, 1_048_576] {
        let plaintext = vec![0xA5_u8; size];
        let sealed = provider.seal(aad, &plaintext).expect("seal succeeds");
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("seal", size), &plaintext, |b, input| {
            b.iter(|| {
                black_box(
                    provider
                        .seal(black_box(aad), black_box(input))
                        .expect("seal succeeds"),
                )
            });
        });

        group.bench_with_input(BenchmarkId::new("open", size), &sealed, |b, input| {
            b.iter(|| {
                black_box(
                    provider
                        .open(black_box(aad), black_box(input))
                        .expect("open succeeds"),
                )
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_aes_256_gcm);
criterion_main!(benches);
