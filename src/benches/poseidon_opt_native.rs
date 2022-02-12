use criterion::{black_box, criterion_group, criterion_main, Criterion};
use plonk_protoype::poseidon::constants::PoseidonConstants;

use ark_bls12_381::Fr;
use ark_std::{test_rng, UniformRand};
use num_traits::Zero;
use plonk_protoype::poseidon::poseidon::{NativeSpec, Poseidon};

fn poseidon_opt_native(c: &mut Criterion) {
    let param = PoseidonConstants::generate::<3>();

    let mut group = c.benchmark_group("Optimized Poseidon Native");
    let mut rng = test_rng();
    group.bench_function("Poseidon NATIVE Height-20 ARITY-2 MT", |b| {
        let inputs = (0..20).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        b.iter(|| {
            let mut poseidon = Poseidon::<(), NativeSpec<Fr, 3>, 3>::new(&mut (), param.clone());
            let mut curr_hash = Fr::zero();
            for x in inputs.iter() {
                poseidon.reset(&mut ());
                poseidon.input(curr_hash).unwrap();
                poseidon.input(*x).unwrap();
                curr_hash = poseidon.output_hash(&mut ());
            }
            black_box(curr_hash);
        })
    });
}

criterion_group!(benches, poseidon_opt_native);
criterion_main!(benches);
