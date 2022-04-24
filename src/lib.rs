// Copyright 2019-2021 Manta Network.
// This file is part of manta-api.
//
// manta-api is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-api is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-api.  If not, see <http://www.gnu.org/licenses/>.

pub mod merkle_tree;

pub mod poseidon;
// pub mod merkle_tree;
// pub mod zk;
/// Native Compiler Marker Trait
///
/// This trait is only implemented for `()`, the only native compiler.
pub trait Native {
    /// Returns the native compiler.
    fn compiler() -> Self;
}

impl Native for () {
    #[inline]
    fn compiler() -> Self {}
}

use std::marker::PhantomData;

use ark_ec::TEModelParameters;
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::{sonic_pc::{SonicKZG10, UniversalParams}, PolynomialCommitment};
use ark_r1cs_std::{fields::{fp::FpVar, FieldVar}, alloc::AllocVar};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use plonk_core::{circuit::Circuit, constraint_system::StandardComposer};
use poseidon::{constants::PoseidonConstants, poseidon::PlonkSpec};
use ark_bls12_381::{Fr, Bls12_381};
use ark_std::{test_rng, UniformRand};
use num_traits::Zero;
use poseidon::poseidon::{NativeSpec, Poseidon};
use rand::Rng;
use wasm_bindgen::prelude::*;
use ark_ed_on_bls12_381::EdwardsParameters as JubJubParameters;
use plonk_core::prelude::*;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_groth16::{self, ProvingKey};

use crate::poseidon::poseidon::r1cs::R1csSpec;

#[wasm_bindgen]
pub struct NativeContext {
    parameter: PoseidonConstants<Fr>,
    hash_inputs: Vec<Fr>,
}

#[wasm_bindgen]
impl NativeContext {
    #[wasm_bindgen(constructor)]
    pub fn new()-> Self {
        let mut rng = test_rng();
        let param = PoseidonConstants::<Fr>::generate::<3>();
        let inputs = (0..20).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        Self {
            parameter: param,
            hash_inputs: inputs
        }
    }
}

#[wasm_bindgen]
pub fn bench_native_poseidon(context: NativeContext) {
    let mut poseidon = Poseidon::<(), NativeSpec<Fr, 3>, 3>::new(&mut (), &context.parameter);
    let mut curr_hash = Fr::zero();
    for x in context.hash_inputs.iter() {
        poseidon.reset(&mut ());
        poseidon.input(curr_hash).unwrap();
        poseidon.input(*x).unwrap();
        curr_hash = poseidon.output_hash(&mut ());
    }
}

#[derive(Debug, Clone)]
pub struct PlonkTestCircuit<F, P>
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

impl<F, P> Circuit<F, P> for PlonkTestCircuit<F, P>
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

#[wasm_bindgen]
pub struct PlonkContext {
    pp: UniversalParams<Bls12_381>,
    circuit: PlonkTestCircuit<Fr, JubJubParameters>,
    pk_p: ProverKey<Fr>,
}

#[wasm_bindgen]
impl PlonkContext {
    #[wasm_bindgen(constructor)]
    pub fn new()-> Self {
        let mut rng = test_rng();
        type PC = SonicKZG10<Bls12_381, DensePolynomial<Fr>>;

        let pp = PC::setup(
            // +1 per wire, +2 for the permutation poly
            1 << 15,
            None,
            &mut rng,
        )
        .expect("Unable to sample public parameters.");
    
        let input = (0..20).map(|_| rng.gen::<Fr>()).collect::<Vec<_>>();

        let mut circuit = PlonkTestCircuit::<Fr, JubJubParameters> {
            constants: PoseidonConstants::generate::<3>(),
            input: input.clone(),
            padded_circuit_size: 1 << 14,
            _p: PhantomData,
        };
    
        let (pk_p, _) = circuit.compile::<PC>(&pp).unwrap();

        Self {
            pp: pp,
            circuit: circuit,
            pk_p: pk_p,
        }
    }
}

#[wasm_bindgen]
pub fn bench_plonk_poseidon(mut context: PlonkContext) {
    type PC = SonicKZG10<Bls12_381, DensePolynomial<Fr>>;
    context.circuit.gen_proof::<PC>(&context.pp, context.pk_p, b"test").unwrap();
}

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
            Poseidon::<_, R1csSpec<Fr, WIDTH>, WIDTH>::new(&mut cs, &self.constants);

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

        Ok(())
    }
}

#[wasm_bindgen]
pub struct R1CSContext {
    circuit: TestCircuit,
    param: ProvingKey<Bls12_381>,
}

#[wasm_bindgen]
impl R1CSContext {
    #[wasm_bindgen(constructor)]
    pub fn new()-> Self {
        let mut rng = &mut test_rng();
        let input = (0..20).map(|_| rng.gen::<Fr>()).collect::<Vec<_>>();

        let circuit = TestCircuit {
            constants: PoseidonConstants::generate::<3>(),
            input: input.clone(),
        };
    
        let param =
        ark_groth16::generate_random_parameters::<Bls12_381, _, _>(circuit.clone(), &mut rng)
            .unwrap();

        Self {
            circuit: circuit,
            param: param,
        }
    }
}

#[wasm_bindgen]
pub fn bench_r1cs_poseidon(context: R1CSContext) {
    let mut rng = &mut test_rng();
    ark_groth16::create_random_proof(context.circuit, &context.param, &mut rng).unwrap();
}