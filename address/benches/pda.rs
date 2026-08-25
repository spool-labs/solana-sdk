use {
    criterion::{black_box, criterion_group, criterion_main, Criterion},
    solana_address::{syscalls::grind, Address},
};

const SAMPLES: usize = 512;

/// Deterministic filler so every run grinds the same authorities
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_le_bytes());
        }
        out
    }
}

/// How deep the first off-curve candidate sits, so samples can be bucketed
fn tries(seeds: &[&[u8]], program_id: &Address) -> usize {
    for (n, bump) in (1..=u8::MAX).rev().enumerate() {
        let byte = [bump];
        let mut with_bump: Vec<&[u8]> = seeds.to_vec();
        with_bump.push(&byte);
        if Address::create_program_address(&with_bump, program_id).is_ok() {
            return n + 1;
        }
    }
    usize::MAX
}

fn cases(prefix: &'static [u8], extra_seed: bool) -> Vec<Vec<Vec<u8>>> {
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    (0..SAMPLES)
        .map(|_| {
            let mut seeds = vec![prefix.to_vec(), rng.bytes32().to_vec()];
            if extra_seed {
                seeds.push(rng.bytes32().to_vec());
            }
            seeds
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    println!(
        "tape-sha256 backend={} lanes={}",
        tape_sha256::backend(),
        tape_sha256::lane_width()
    );

    let program_id = Address::new_from_array([7u8; 32]);

    for (name, prefix, extra) in [
        ("node", b"node".as_slice(), false),
        ("track", b"track".as_slice(), true),
    ] {
        let owned = cases(prefix, extra);
        let refs: Vec<Vec<&[u8]>> = owned
            .iter()
            .map(|s| s.iter().map(|v| v.as_slice()).collect())
            .collect();

        let depths: Vec<usize> = refs.iter().map(|s| tries(s, &program_id)).collect();
        let mean = depths.iter().sum::<usize>() as f64 / depths.len() as f64;
        let one = depths.iter().filter(|&&d| d == 1).count();
        let deep = depths.iter().filter(|&&d| d >= 4).count();
        println!(
            "{name}: mean tries {mean:.2}, first-bump hits {one}/{SAMPLES}, >=4 tries {deep}/{SAMPLES}"
        );

        // Parity guard: a bench that measured two different answers is worthless
        for seeds in &refs {
            assert_eq!(
                grind::serial(seeds, &program_id),
                grind::batched(seeds, &program_id)
            );
            assert_eq!(
                grind::serial(seeds, &program_id),
                grind::serial_reuse(seeds, &program_id)
            );
        }

        let shallow: Vec<&Vec<&[u8]>> = refs
            .iter()
            .zip(&depths)
            .filter(|(_, &d)| d == 1)
            .map(|(s, _)| s)
            .collect();
        let deep_set: Vec<&Vec<&[u8]>> = refs
            .iter()
            .zip(&depths)
            .filter(|(_, &d)| d >= 4)
            .map(|(s, _)| s)
            .collect();

        let mut group = c.benchmark_group(format!("find_pda/{name}"));
        for (bucket, set) in [
            ("mixed", refs.iter().collect::<Vec<_>>()),
            ("first_bump", shallow),
            ("deep", deep_set),
        ] {
            if set.is_empty() {
                continue;
            }
            group.bench_function(format!("{bucket}/serial"), |b| {
                let mut i = 0usize;
                b.iter(|| {
                    let seeds = set[i % set.len()];
                    i += 1;
                    black_box(grind::serial(seeds, &program_id))
                })
            });
            group.bench_function(format!("{bucket}/serial_reuse"), |b| {
                let mut i = 0usize;
                b.iter(|| {
                    let seeds = set[i % set.len()];
                    i += 1;
                    black_box(grind::serial_reuse(seeds, &program_id))
                })
            });
            group.bench_function(format!("{bucket}/batched"), |b| {
                let mut i = 0usize;
                b.iter(|| {
                    let seeds = set[i % set.len()];
                    i += 1;
                    black_box(grind::batched(seeds, &program_id))
                })
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
