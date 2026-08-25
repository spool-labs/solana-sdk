use {
    criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion},
    solana_address::{syscalls::find_program_addresses, Address},
};

/// The grinder's shape: a fixed leading seed and a counter that walks
fn seed_sets(count: usize) -> Vec<Vec<Vec<u8>>> {
    (0..count)
        .map(|i| vec![b"tape".to_vec(), (i as u64).to_le_bytes().to_vec()])
        .collect()
}

fn bench(c: &mut Criterion) {
    let program_id = Address::new_from_array([7u8; 32]);
    let mut group = c.benchmark_group("pda_batch");

    for count in [1usize, 8, 64, 256, 1024] {
        let owned = seed_sets(count);
        let refs: Vec<Vec<&[u8]>> = owned
            .iter()
            .map(|set| set.iter().map(|s| s.as_slice()).collect())
            .collect();
        let sets: Vec<&[&[u8]]> = refs.iter().map(|s| s.as_slice()).collect();
        let mut out = vec![None; count];

        group.throughput(criterion::Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::new("looped", count), &count, |b, _| {
            b.iter(|| {
                for set in &sets {
                    black_box(Address::find_program_address(set, &program_id));
                }
            })
        });
        group.bench_with_input(BenchmarkId::new("batched", count), &count, |b, _| {
            b.iter(|| find_program_addresses(black_box(&sets), &program_id, &mut out))
        });
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
