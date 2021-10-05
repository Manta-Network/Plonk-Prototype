//! This example creates a pedersen hash with only one window, as an example
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use dusk_plonk::prelude::*;
use rand::{Rng, RngCore, SeedableRng, prelude::StdRng};
/// For circuit, we need to constrain bits input to be in [0,1]
fn bowe_hopwood_native(gen: JubJubExtended, bits: [bool;3]) -> JubJubExtended {
    assert_eq!(bits.len(), 3);
    // generate gen, 2*gen, 4*gen
    let gen2 = gen + gen;
    let mut encoded = gen;
    if bits[0] {
        encoded += gen;
    }
    if bits[1] {
        encoded += gen2;
    }
    if bits[2] {
        encoded = -encoded;
    }
    encoded
}

pub struct BHOneChunk {
    gen: JubJubAffine,
    bits: [bool; 3],
    target_hash: JubJubAffine
}

impl Circuit for  BHOneChunk {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<(), Error> {
        // generate gen, 2*gen, 4*gen
        let gen = composer.add_affine(self.gen.into());
        let gen2 = composer.point_addition_gate(gen, gen);
        let bits = self.bits.iter().map(|bit|{
            let bit = composer.add_input(if *bit {BlsScalar::one()} else {BlsScalar::zero()});
            composer.boolean_gate(bit)
        }).collect::<Vec<_>>();
        let mut encoded = gen;

        let point_zero = composer.add_affine(JubJubAffine::identity());

        {
            let temp = composer.conditional_point_select(gen, point_zero, bits[0]);
            encoded = composer.point_addition_gate(encoded, temp);
        }
        {
            let temp = composer.conditional_point_select(gen2, point_zero, bits[1]);
            encoded = composer.point_addition_gate(encoded, temp);
        }
        
        
        // TODO: looks not efficient, probably use 1) fixed base  2)allocate constant for negative one
        let encoded_ne = {
            let temp = composer.add_input(BlsScalar::one().neg());
            composer.variable_base_scalar_mul(temp, encoded)
        };

        encoded = composer.conditional_point_select(encoded_ne, encoded, bits[2]);

        composer.assert_equal_public_point(encoded, self.target_hash);
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
    let mut bits = [false;3];
    bits.iter_mut().for_each(|b|*b = rng.gen());
    let native_result = bowe_hopwood_native(gen, bits);

    let mut circuit = BHOneChunk{
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

    println!("{:?}", native_result);

}