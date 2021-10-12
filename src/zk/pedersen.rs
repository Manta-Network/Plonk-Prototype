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

//! Pedersen implementation

use std::ops::Neg;

use crate::zk::gadgets::*;
use dusk_bls12_381::multi_miller_loop;
use dusk_jubjub::{
    JubJubAffine, JubJubExtended, Scalar, GENERATOR, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_plonk::prelude::*;
use dusk_poseidon::*;

const BASE_SIZE: usize = 8;

#[derive(Clone, Copy)]
///
pub struct PrecomputedBases {
    powers_of_p: [JubJubAffine; BASE_SIZE],
}
/// Size256(n) ladder
pub struct PedersenLadder {
    rows: Vec<PrecomputedBases>,
}

/// Quad langth 4. Incoming bits = 256.
/// numbers of windows needed 256/4 + 1 = 65.
/// With the last window deciding if the outcome is odd or even
/// many ladders
///
pub struct HashLadder {
    first_table: PedersenLadder,
    second_table: PedersenLadder,
}

impl HashLadder {
    pub fn new(
        p: JubJubExtended,
        p_prime: JubJubExtended,
        num_bases: usize,
        num_bases_prime: usize,
    ) -> Self {
        Self {
            first_table: PedersenLadder::new(p, num_bases),
            second_table: PedersenLadder::new(p_prime, num_bases_prime),
        }
    }
}

impl PedersenLadder {
    fn new(p: JubJubExtended, num_bases: usize) -> Self {
        let bases = (0..num_bases)
            .into_iter()
            .map(|i| {
                let base_point = p * Scalar::from((2 as u64).pow(5 * i as u32));
                PrecomputedBases::new(base_point)
            })
            .collect();

        Self { rows: bases }
    }
}

impl PrecomputedBases {
    fn new(base_point: JubJubExtended) -> Self {
        let bases_vec = (0..BASE_SIZE)
            .into_iter()
            .map(|i| JubJubAffine::from(base_point * Scalar::from((i + 1) as u64)))
            .collect::<Vec<JubJubAffine>>();

        let mut bases = [JubJubAffine::from(base_point); BASE_SIZE];
        bases.copy_from_slice(bases_vec.as_slice());

        Self { powers_of_p: bases }
    }
}

/// Pedersen Hash function
/// TODO: have function accept scalar and split into bytes
pub fn compute_pedersen_hash(scalar: [i8; 256]) -> JubJubAffine {
    let second_bases = scalar[200..].len() / 4;

    let full_ladder = HashLadder::new(
        GENERATOR_EXTENDED,
        GENERATOR_NUMS_EXTENDED,
        50,
        second_bases,
    );

    const CHUNK_SIZE: usize = 4;

    let mut accumulator = JubJubExtended::identity();
    scalar[0..200].chunks(CHUNK_SIZE).enumerate().for_each(|(i, bits)| {
        accumulator = accumulator + JubJubExtended::from(multiplexer(full_ladder.first_table.rows[i], bits));
    });

    scalar[200..].chunks(CHUNK_SIZE).enumerate().for_each(|(i, bits)| {
        accumulator = accumulator + JubJubExtended::from(multiplexer(full_ladder.second_table.rows[i], bits));
    });

    JubJubAffine::from(accumulator)
}

// Conditionally select the outputs for each basepoint.
fn multiplexer(ladder: PrecomputedBases, bits: &[i8]) -> JubJubAffine {
    let a = 1 + bits[0];
    let b = 2 * bits[1];
    let c = 4 * bits[2];
    let output = a + b + c;

    let conditional = ladder.powers_of_p[output as usize];

    if bits[3] == -1 {
        conditional.neg()
    } else {
        conditional
    }
}

// // Get the y_output of pedersen_hash
// fn get_y_output(ladder: PrecomputedBases, bits: &[bool; 4]) -> BlsScalar {
//     let a_0 = ladder.x_values[0];
//     let a_1 = ladder.x_values[1];
//     let a_2 = ladder.x_values[2];
//     let a_3 = ladder.x_values[3];
//     let a_4 = ladder.x_values[4];
//     let a_5 = ladder.x_values[5];
//     let a_6 = ladder.x_values[6];
//     let a_7 = ladder.x_values[7];

//     let z = 1 as u32;

//     let s_n = bits[0] as u8 + bits[1] as u8;
//     let lhs = (((a_7 - a_6 - a_5 + a_4 - a_3 + a_2 + a_1 - a_0)
//         * BlsScalar::from(s_n as u64).reduce())
//         + ((a_6 - a_4 - a_2 + a_0) * BlsScalar::from(bits[1] as u64).reduce())
//         + ((a_5 - a_4 - a_1 + a_0) * BlsScalar::from(bits[0] as u64).reduce())
//         + (a_4 - a_0))
//         * BlsScalar::one().reduce();

//     let rhs = ((a_3 - a_2 - a_1 + a_0) * BlsScalar::from(s_n as u64).reduce())
//         + ((a_2 - a_0) * BlsScalar::from(bits[1] as u64).reduce())
//         + ((a_1 - a_0) * BlsScalar::from(s_n as u64).reduce())
//         + a_0;
// }

//
pub fn encode(composer: &mut StandardComposer, bits: [Variable; 4]) -> Variable {
    // bits(m_j) = [b_0, b_1, b_3, b_4]
    // ((2b_3) - 1) * (1 + b_0 + 2b_1 + 4b_2)

    //TODO: Can the 1 be a public input? If so, it can help a lot.
    let rhs = composer.big_add(
        (BlsScalar::one(), bits[0]),
        (BlsScalar::from(2), bits[1]),
        Some((BlsScalar::from(4), bits[2])),
        BlsScalar::zero(),
        Some(BlsScalar::one()),
    );

    // let's say n = (1 + b_0 + 2b_1 + 4b_2)
    // thus lhs = ((2b_3 * n) - n)
    composer.big_mul(
        BlsScalar::one(),
        bits[3],
        rhs,
        Some((-BlsScalar::one(), rhs)),
        BlsScalar::zero(),
        None,
    )
}

// pub fn pedersen_hash(composer: &mut StandardComposer, encoded_values: &[Variable]) -> (Point, Point) {

//     for i in 0..50 {
//         let base = composer.add_witness_to_circuit_description((BlsScalar::from(32));
//         let two_five_j = composer.big_mul(BlsScalar::::from(2), , b, q_4_d, q_c, pi);
//         let mut point_1 = composer.big_add_gate(a, b, c, d, q_l, q_r, q_o, q_4, q_c, pi);
//     }

// }

