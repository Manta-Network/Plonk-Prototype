//! This example creates a pedersen hash with only one window, as an example
use dusk_jubjub::{JubJubAffine, JubJubExtended};
use dusk_plonk::prelude::*;
use rand::{Rng, RngCore, SeedableRng, prelude::StdRng};
fn bowe_hopwood_native_one_chunk(gen: JubJubExtended, bits: &[bool]) -> JubJubExtended {
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

fn bowe_hopwood_native_one_window(mut gen: JubJubExtended, bits: &[bool], num_chunks_in_window: usize) -> JubJubExtended {
    const CHUNK_SIZE: usize = 3;
    assert_eq!(bits.len(), CHUNK_SIZE * num_chunks_in_window, "invalid length of bits");
    let mut curr_result = JubJubExtended::identity();
    (0..num_chunks_in_window).for_each(|i|{
        let local_point = bowe_hopwood_native_one_chunk(gen, &bits[i*CHUNK_SIZE..i*CHUNK_SIZE + 3]);
        curr_result += local_point;
        for _ in 0..(CHUNK_SIZE + 1) {
            gen = gen.double();
        }
    });

    curr_result
}

fn chunk_3bit_gadget(composer: &mut StandardComposer, gen: Point, bits: &[Variable]) -> Point {
    // generate gen, 2*gen, 4*gen
    let gen2 = composer.point_addition_gate(gen, gen);
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

    let encoded_ne = {
        let temp = composer.add_input(JubJubScalar::one().neg().into());
        composer.variable_base_scalar_mul(temp, encoded)
    };

    composer.conditional_point_select(encoded_ne, encoded, bits[2])
}

fn bowe_hopwood_one_window_gadget(composer: &mut StandardComposer, mut gen: Point, bits: &[Variable], num_chunks_in_window: usize) -> Point {
    const CHUNK_SIZE: usize = 3;
    assert_eq!(bits.len(), CHUNK_SIZE * num_chunks_in_window, "invalid length of bits");
    let mut curr_result = Point::identity(composer);
    (0..num_chunks_in_window).for_each(|i|{
        let local_point = chunk_3bit_gadget(composer, gen ,&bits[i*CHUNK_SIZE..i*CHUNK_SIZE + 3]);
        curr_result = composer.point_addition_gate(curr_result, local_point);
        for _ in 0..(CHUNK_SIZE + 1) {
            gen = composer.point_addition_gate(gen, gen);
        }
    });

    curr_result
}


#[derive(Debug, Default)]
pub struct BoweHopwoodOneWindow {
    gen: JubJubAffine,
    bits: Vec<bool>,
    target_hash: JubJubAffine
}

impl Circuit for BoweHopwoodOneWindow {
    const CIRCUIT_ID: [u8; 32] = [0xfe; 32];

    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<(), Error> {
        const NUM_CHUNKS_IN_WINDOW: usize = 64;
        let bits = self.bits.iter().map(|bit|{
            let bit = composer.add_input(if *bit {BlsScalar::one()} else {BlsScalar::zero()});
            composer.boolean_gate(bit)
        }).collect::<Vec<_>>();
        let gen = composer.add_affine(self.gen);
        let result = bowe_hopwood_one_window_gadget(composer, gen, &bits, NUM_CHUNKS_IN_WINDOW);
        composer.assert_equal_public_point(result, self.target_hash);
        Ok(())

    }

    fn padded_circuit_size(&self) -> usize {
        1 << 20 // TODO
    }
}

#[test]
fn test(){
    let mut rng = StdRng::seed_from_u64(0x12345678);
    let gen = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(rng.next_u64());
    let bits = (0..64*3).map(|_|rng.gen()).collect::<Vec<_>>();
    let native_result = bowe_hopwood_native_one_window(gen, &bits, 64);

    let mut circuit = BoweHopwoodOneWindow{
        bits: bits.clone(),
        gen: gen.into(),
        target_hash: native_result.into()
    };

    let pp = PublicParameters::setup(1 << 20, &mut rng).unwrap();
    
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




 

