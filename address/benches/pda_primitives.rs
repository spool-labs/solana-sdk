use {
    criterion::{black_box, criterion_group, criterion_main, Criterion},
    solana_address::bytes_are_curve_point,
};

const PDA_MARKER: &[u8] = b"ProgramDerivedAddress";

fn bench(c: &mut Criterion) {
    let mut digests = [[0u8; 32]; 4];
    let mut candidates = [[0u8; 32]; 64];
    for (i, c) in candidates.iter_mut().enumerate() {
        c[0] = i as u8;
        c[31] = (i as u8).wrapping_mul(37);
    }

    // A node PDA preimage: seeds, bump, program id, marker
    let prefix: Vec<u8> = b"node".iter().chain([9u8; 32].iter()).copied().collect();
    let tail: Vec<u8> = [7u8; 32].iter().chain(PDA_MARKER.iter()).copied().collect();
    let bump = [255u8];
    let msgs: [tape_sha256::Message<'_>; 4] = core::array::from_fn(|_| tape_sha256::Message {
        prefix: &prefix,
        body: &bump,
        tail: &tail,
    });

    let mut group = c.benchmark_group("pda_primitives");
    group.bench_function("on_curve_check", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let c = candidates[i % candidates.len()];
            i += 1;
            black_box(bytes_are_curve_point(c))
        })
    });
    let seeds: [&[u8]; 2] = [b"node", &[9u8; 32]];
    let program_id = [7u8; 32];
    group.bench_function("sha256_one_sdk_path", |b| {
        b.iter(|| {
            let mut hasher = solana_sha256_hasher::Hasher::default();
            for seed in black_box(&seeds) {
                hasher.hash(seed);
            }
            hasher.hash(&[255u8]);
            hasher.hashv(&[program_id.as_ref(), PDA_MARKER]);
            black_box(hasher.result())
        })
    });
    group.bench_function("sha256_one", |b| {
        b.iter(|| tape_sha256::hash_messages(black_box(&msgs[..1]), &mut digests[..1]))
    });
    group.bench_function("sha256_four_lanes", |b| {
        b.iter(|| tape_sha256::hash_messages(black_box(&msgs[..4]), &mut digests[..4]))
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
