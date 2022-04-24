use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::TEModelParameters;
use ark_ed_on_bls12_381::EdwardsParameters as JubJubParameters;
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::sonic_pc::SonicKZG10;
use ark_poly_commit::PolynomialCommitment;
use ark_std::test_rng;
use criterion::{criterion_group, criterion_main, Criterion};
use plonk_core::circuit::PublicInputBuilder;
use plonk_core::prelude::*;
use plonk_protoype::poseidon::constants::PoseidonConstants;
use plonk_protoype::poseidon::poseidon::{PlonkSpec, Poseidon};
use rand::Rng;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct TestCircuit<F, P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    constants: PoseidonConstants<F>,
    /// the length of input matches the height of the merkle tree path proof we want to simulate
    input: Vec<F>,
    padded_circuit_size: usize,
    _p: PhantomData<P>,
}

impl<F, P> Circuit<F, P> for TestCircuit<F, P>
where
    F: PrimeField,
    P: TEModelParameters<BaseField = F>,
{
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(&mut self, composer: &mut StandardComposer<F, P>) -> Result<(), Error> {
        let mut poseidon = Poseidon::<_, PlonkSpec<3>, 3>::new(composer, &self.constants);

        let inputs_var = self
            .input
            .iter()
            .map(|x| composer.add_input(*x))
            .collect::<Vec<_>>();

        let mut curr_hash = composer.zero_var();
        for x in inputs_var {
            poseidon.reset(composer);
            poseidon.input(curr_hash);
            poseidon.input(x);
            curr_hash = poseidon.output_hash(composer);
        }

        // println!("Circuit size: {}", composer.circuit_size());
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        self.padded_circuit_size
    }
}

fn poseidon_opt_plonk_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("Optimized Poseidon PLONK");
    let mut rng = test_rng();

    // Generate CRS
    type PC = SonicKZG10<Bls12_381, DensePolynomial<Fr>>;
    //type PC = KZG10::<Bls12_381>; //Use a different polynomial commitment
    // scheme

    let pp = PC::setup(
        // +1 per wire, +2 for the permutation poly
        1 << 15,
        None,
        &mut rng,
    )
    .expect("Unable to sample public parameters.");

    group.bench_function("Height-20 ARITY-2 MT PROVE", |b| {
        let input = (0..20).map(|_| rng.gen::<Fr>()).collect::<Vec<_>>();
        let mut circuit = TestCircuit::<Fr, JubJubParameters> {
            constants: PoseidonConstants::generate::<3>(),
            input,
            padded_circuit_size: 1 << 14,
            _p: PhantomData,
        };

        let (pk_p, _) = circuit.compile::<PC>(&pp).unwrap();

        b.iter(|| {
            let mut circuit = circuit.clone();
            circuit.gen_proof::<PC>(&pp, pk_p.clone(), b"test").unwrap();
        })
    });
}

fn poseidon_opt_plonk_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Optimized Poseidon PLONK");
    let mut rng = test_rng();

    // Generate CRS
    type PC = SonicKZG10<Bls12_381, DensePolynomial<Fr>>;
    //type PC = KZG10::<Bls12_381>; //Use a different polynomial commitment
    // scheme

    let pp = PC::setup(
        // +1 per wire, +2 for the permutation poly
        1 << 15,
        None,
        &mut rng,
    )
    .expect("Unable to sample public parameters.");

    group.bench_function("Height-20 ARITY-2 MT VERIFY", |b| {
        let input = (0..20).map(|_| rng.gen::<Fr>()).collect::<Vec<_>>();
        let mut circuit = TestCircuit::<Fr, JubJubParameters> {
            constants: PoseidonConstants::generate::<3>(),
            input,
            padded_circuit_size: 1 << 14,
            _p: PhantomData,
        };

        let (pk_p, verifier_data) = circuit.compile::<PC>(&pp).unwrap();

        let proof = circuit.gen_proof::<PC>(&pp, pk_p.clone(), b"test").unwrap();

        let public_inputs = PublicInputBuilder::new().finish();
        let VerifierData { key, pi_pos } = verifier_data;

        b.iter(|| {
            verify_proof::<Fr, JubJubParameters, PC>(
                &pp,
                key.clone(),
                &proof,
                &public_inputs,
                &pi_pos,
                b"test"
            ).unwrap()
        })
    });

}

criterion_group!(benches, poseidon_opt_plonk_prove);
criterion_main!(benches);
