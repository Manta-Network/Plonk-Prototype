//! This example creates a pedersen hash with only one window, as an example
use dusk_jubjub::{JubJubAffine, JubJubExtended};
use dusk_plonk::prelude::*;
use rand::{prelude::StdRng, Rng, RngCore, SeedableRng};
const CHUNK_SIZE: usize = 3;

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

fn bowe_hopwood_native_one_window(
    mut gen: JubJubExtended,
    bits: &[bool],
    num_chunks_in_window: usize,
) -> JubJubExtended {
    assert_eq!(
        bits.len(),
        CHUNK_SIZE * num_chunks_in_window,
        "invalid length of bits"
    );
    let mut curr_result = JubJubExtended::identity();
    (0..num_chunks_in_window).for_each(|i| {
        let local_point =
            bowe_hopwood_native_one_chunk(gen, &bits[i * CHUNK_SIZE..i * CHUNK_SIZE + 3]);
        curr_result += local_point;
        for _ in 0..(CHUNK_SIZE + 1) {
            gen = gen.double();
        }
    });

    curr_result
}

fn bowe_hopwood_native(
    gen: &[JubJubExtended],
    bits: &[bool],
    num_chunks_in_window: usize,
) -> JubJubExtended {
    assert_eq!(gen.len(), bits.len() / (CHUNK_SIZE * num_chunks_in_window));
    assert!(bits.len() % (CHUNK_SIZE * num_chunks_in_window) == 0);
    let ps = bits
        .chunks(CHUNK_SIZE * num_chunks_in_window)
        .zip(gen.iter())
        .map(|(chunk, g)| bowe_hopwood_native_one_window(*g, chunk, num_chunks_in_window));
    ps.fold(JubJubExtended::identity(), |prev, curr| prev + curr)
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

    // gen = k * generator

    // k in finite field
    // k, bit[0], bit[1], bit[2]
    // if bit[2] is true -> gen^{-bit[0] - bit[1]}
    // if bit[2] if false -> gen^{bit[0] + bit[1]}
    // result * generator
    let encoded_ne = {
        let temp = composer.add_input(JubJubScalar::one().neg().into());
        let c0 = composer.circuit_size();
        // TODO: var base scalar mul is super expensive
        let result = composer.variable_base_scalar_mul(temp, encoded);
        let c1 = composer.circuit_size();
        println!("variable_base_scalar_mul constraints: {:?}", c1 - c0);
        result
    };

    composer.conditional_point_select(encoded_ne, encoded, bits[2])
}

fn bowe_hopwood_one_window_gadget(
    composer: &mut StandardComposer,
    mut gen: Point,
    bits: &[Variable],
    num_chunks_in_window: usize,
) -> Point {
    const CHUNK_SIZE: usize = 3;
    assert_eq!(
        bits.len(),
        CHUNK_SIZE * num_chunks_in_window,
        "invalid length of bits"
    );
    let mut curr_result = Point::identity(composer);
    (0..num_chunks_in_window).for_each(|i| {
        let local_point =
            chunk_3bit_gadget(composer, gen, &bits[i * CHUNK_SIZE..i * CHUNK_SIZE + 3]);

        curr_result = composer.point_addition_gate(curr_result, local_point);

        for _ in 0..(CHUNK_SIZE + 1) {
            gen = composer.point_addition_gate(gen, gen);
        }
    });

    curr_result
}

// number of bits = CHUNK_SIZE * number_chunks_in_window * num_windows
fn bowe_hopwood_gadget(
    composer: &mut StandardComposer,
    gen: &[Point],
    bits: &[Variable],
    num_chunks_in_window: usize,
) -> Point {
    assert_eq!(gen.len(), bits.len() / (CHUNK_SIZE * num_chunks_in_window));
    assert!(bits.len() % (CHUNK_SIZE * num_chunks_in_window) == 0);
    let ps = bits
        .chunks(CHUNK_SIZE * num_chunks_in_window)
        .zip(gen.iter())
        .map(|(chunk, g)| bowe_hopwood_one_window_gadget(composer, *g, chunk, num_chunks_in_window))
        .collect::<Vec<_>>();

    let mut curr = Point::identity(composer);
    for mp in ps {
        curr = composer.point_addition_gate(curr, mp);
    }

    curr
}

#[derive(Debug, Default)]
pub struct BoweHopwood {
    gen: Vec<JubJubAffine>,
    bits: Vec<bool>,
    target_hash: JubJubAffine,
}

impl Circuit for BoweHopwood {
    const CIRCUIT_ID: [u8; 32] = [0xfe; 32];

    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<(), Error> {
        const NUM_CHUNKS_IN_WINDOW: usize = 64;
        let gen_var = self
            .gen
            .iter()
            .map(|x| composer.add_affine(*x))
            .collect::<Vec<_>>();

        let bits_var = self
            .bits
            .iter()
            .map(|x| {
                let v = composer.add_input(if *x {
                    BlsScalar::one()
                } else {
                    BlsScalar::zero()
                });
                composer.boolean_gate(v)
            })
            .collect::<Vec<_>>();

        let result_point = bowe_hopwood_gadget(composer, &gen_var, &bits_var, NUM_CHUNKS_IN_WINDOW);
        composer.assert_equal_public_point(result_point, self.target_hash);
        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        1 << 19 // TODO
    }
}

#[test]
fn test() {
    const NUM_WINDOWS: usize = 2;
    const NUM_CHUNKS_IN_WINDOW: usize = 64;
    let mut rng = StdRng::seed_from_u64(0x12345678);
    let gen = (0..NUM_WINDOWS)
        .map(|_| dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(rng.next_u64()))
        .collect::<Vec<_>>();

    let bits = (0..3 * NUM_CHUNKS_IN_WINDOW * NUM_WINDOWS)
        .map(|_| rng.gen())
        .collect::<Vec<_>>();
    let native_result = bowe_hopwood_native(gen.as_slice(), &bits, 64);

    let mut circuit = BoweHopwood {
        bits,
        gen: gen.iter().map(|x| x.into()).collect(),
        target_hash: native_result.into(),
    };

    let mut composer = StandardComposer::new();

    circuit.gadget(&mut composer);

    println!("total number of constraints: {:?}", composer.circuit_size());

    // let pp = PublicParameters::setup(1 << 19, &mut rng).unwrap();

    // let (pk, vd) = circuit.compile(&pp).unwrap();

    // let proof = circuit.gen_proof(&pp, &pk, b"Test").unwrap();

    // let public_inputs: Vec<PublicInputValue> =
    // vec![JubJubAffine::from(circuit.target_hash).into()];

    // circuit::verify_proof(
    //     &pp,
    //     &vd.key(),
    //     &proof,
    //     &public_inputs,
    //     &vd.pi_pos(),
    //     b"Test",
    // )
    // .unwrap();

    // println!("{:?}", native_result);
}
