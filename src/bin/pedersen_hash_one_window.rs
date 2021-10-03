//! This example creates a pedersen hash with only one window, as an example
use std::ops::Add;

use dusk_bytes::{ParseHexStr, Serializable};
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use dusk_plonk::prelude::*;
use rand::{Rng, RngCore, SeedableRng, prelude::StdRng};
/// For circuit, we need to constrain bits input to be in [0,1]
fn perdersen_native(gen: JubJubExtended, bits: &[bool]) -> JubJubExtended {
    let mut curr = gen;
    let identity = JubJubExtended::identity();
    bits.iter().fold(identity.clone(), |prev, bit|{
        let result = prev.add(if *bit {&curr} else { &identity});
        curr = curr.double();
        result
    })
}

pub struct PedersenOneWindow<const WINDOW_SIZE: usize> {
    gen: JubJubAffine,
    bits: [bool; WINDOW_SIZE],
    target_hash: JubJubAffine
}

impl<const WINDOW_SIZE: usize> Circuit for  PedersenOneWindow<WINDOW_SIZE> {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<(), Error> {
        // first, convert bit to scalar, and bound bit to be boolean
        let bits = self.bits.iter().map(|b|
            {let bit = composer.add_input(if *b {BlsScalar::one()} else {BlsScalar::zero()} );
        composer.boolean_gate(bit)}).collect::<Vec<_>>();

        let mut curr = composer.add_affine(self.gen);
        let identity = composer.add_affine(JubJubAffine::identity()); 
        let result = bits.iter().fold(identity.clone(), |prev, bit| {
            let to_add = composer.conditional_point_select(curr, identity, *bit);
            curr = composer.point_addition_gate(curr, curr);
            composer.point_addition_gate(prev, to_add) 
        });
        composer.assert_equal_public_point(result, self.target_hash);
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        // TODO: How to determine this??
        1 << 12
    }
}

fn main(){
    let mut rng = StdRng::seed_from_u64(0x12345678);
    let gen = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(rng.next_u64());
    let mut bits = [false;16];
    bits.iter_mut().for_each(|b|*b = rng.gen_bool(0.5));
    let native_result = perdersen_native(gen, &bits); 

    let mut circuit = PedersenOneWindow{
        bits: bits.clone(),
        gen: gen.into(),
        target_hash: native_result.into()
    };

    let pp = PublicParameters::setup(1 << 12, &mut rng).unwrap();
    
    let (pk, vd) = circuit.compile(&pp).unwrap();

    let proof = circuit.gen_proof(&pp, &pk, b"Test").unwrap();

    let public_inputs: Vec<PublicInputValue> = vec![
        JubJubAffine::from(circuit.target_hash)
        .into(),
    ];


    circuit::verify_proof(
        &pp,
        &vd.key(),
        &proof,
        &public_inputs,
        &vd.pi_pos(),
        b"Test",
    ).unwrap();

}