use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::EdwardsParameters as JubJubParameters;
use ark_ff::PrimeField;
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use plonk_protoype::poseidon::constants::PoseidonConstants;
use plonk_protoype::poseidon::poseidon::{r1cs::R1csSpec, Poseidon};
use rand::Rng;
use std::marker::PhantomData;
use ark_ec::TEModelParameters;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::SynthesisError;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::ConstraintSystemRef;


#[derive(Debug, Clone)]
pub struct TestCircuit
{
    constants: PoseidonConstants<Fr>,
    input: Vec<Fr>,
}

impl ConstraintSynthesizer<Fr> for TestCircuit
{
    fn generate_constraints(self, mut cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        const WIDTH: usize = 3;
        let mut poseidon =
            Poseidon::<_, R1csSpec<Fr, WIDTH>, WIDTH>::new(&mut cs, self.constants.clone());

        let inputs_var = self
            .input
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
            .collect::<Vec<_>>();

        let mut curr_hash = FpVar::zero();
        for x in inputs_var {
            poseidon.reset(&mut cs);
            poseidon.input(curr_hash);
            poseidon.input(x);
            curr_hash = poseidon.output_hash(&mut cs);
        }

        // println!("Circuit size: {}", cs.num_constraints());

        Ok(())
    }
}

fn poseidon_opt_r1cs_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("Optimized Poseidon R1CS");
    let mut rng = &mut test_rng();

    group.bench_function("Height-20 ARITY-2 MT PROVE", |b| {
        let input = (0..20).map(|_| rng.gen::<Fr>()).collect::<Vec<_>>();
        let mut circuit = TestCircuit {
            constants: PoseidonConstants::generate::<3>(),
            input,
        };
    
        let param =
        ark_groth16::generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng)
            .unwrap();
    
        let pvk = ark_groth16::prepare_verifying_key(&param.vk);

        b.iter(|| {
            ark_groth16::create_random_proof(circuit.clone(), &param, &mut rng).unwrap();
        })
    });
}

fn poseidon_opt_r1cs_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Optimized Poseidon R1CS");
    let mut rng = &mut test_rng();

    group.bench_function("Height-20 ARITY-2 MT VERIFY", |b| {
        let input = (0..20).map(|_| rng.gen::<Fr>()).collect::<Vec<_>>();
        let mut circuit = TestCircuit {
            constants: PoseidonConstants::generate::<3>(),
            input,
        };
    
        let param =
        ark_groth16::generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng)
            .unwrap();
    
        let pvk = ark_groth16::prepare_verifying_key(&param.vk);

        let proof = ark_groth16::create_random_proof(circuit, &param, &mut rng).unwrap();

        let inputs: Vec<Fr> = vec![];
        b.iter(|| {
            assert!(ark_groth16::verify_proof(&pvk, &proof, &inputs[..]).unwrap());
        })
    });
}

criterion_group!(benches, poseidon_opt_r1cs_prove);
criterion_main!(benches);