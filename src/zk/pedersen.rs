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
use dusk_jubjub::{
    JubJubAffine, JubJubExtended, Scalar, GENERATOR, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};
use dusk_plonk::prelude::*;


// we use 3-bit lookup tables for the pedersen hash
const BASE_SIZE: usize = 8;

#[derive(Clone, Copy)]
/// Precomputed powers of P..BASE_SIZE*P 
pub struct PrecomputedBases {
    powers_of_p: [JubJubExtended; BASE_SIZE],
}
/// Pedersen Ladder contains precomputed powers 
/// of a group generator G, for different windows
/// of bits
pub struct PedersenLadder {
    rows: Vec<PrecomputedBases>,
}
/// Quad langth 4. Incoming bits = 256.
/// numbers of windows needed 256/4 + 1 = 65.
/// With the last window deciding if the outcome is odd or even
/// many ladders
///
/// Hash ladder is a struct which contains two Pedersen ladders
pub struct HashLadder {
    first_table: PedersenLadder,
    second_table: PedersenLadder,
}

impl HashLadder {
    /// Construct Hash Ladder
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
    /// Construct Pedersen Ladder
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
    /// Construct set of bases
    fn new(base_point: JubJubExtended) -> Self {
        let bases_vec = (0..BASE_SIZE)
            .into_iter()
            .map(|i| base_point * Scalar::from((i + 1) as u64))
            .collect::<Vec<_>>();

        let mut bases: [JubJubExtended; BASE_SIZE] = [JubJubAffine::from(base_point).into(); BASE_SIZE];
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

// Conditionally select the outputs for each basepoint
// from a selection of {-8, 8} multiples of P
fn multiplexer(ladder: PrecomputedBases, bits: &[i8]) -> JubJubAffine {
    let a = 1 + bits[0];
    let b = 2 * bits[1];
    let c = 4 * bits[2];
    let output = a + b + c;

    let conditional: JubJubAffine = ladder.powers_of_p[output as usize].into();

    if bits[3] == -1 {
        conditional.neg()
    } else {
        conditional
    }
}

/// Calculate perdersen window using 4-bit lookup table
fn multiplexer_using_lookup(ladder: PrecomputedBases, bits: &[bool]) -> JubJubAffine {
    // multiplexer will use mux
    todo!();
}

fn mul_point_with_bool(point: JubJubExtended, bit: bool) -> JubJubExtended {
    if bit {
        point
    } else {
        JubJubExtended::identity()
    }
}


/// Calculate mux3 using 3-bit lookup table (native version)
/// source: https://github.com/iden3/circomlib/blob/master/circuits/mux3.circom
/// 
/// * `c`: constant data
/// * `bits`: selection bits
fn mux3(c: &[JubJubExtended], s: &[bool]) -> JubJubExtended {
    assert_eq!(c.len(), 8);
    assert_eq!(s.len(), 3);
    let s10 = s[1] & s[0];

    let a210 = mul_point_with_bool(c[7]-c[6]-c[5]+c[4] - c[3]+c[2]+c[1]-c[0], s10);
    let a21 = mul_point_with_bool(c[6]-c[4]-c[2]+c[0], s[1]);
    let a20 = mul_point_with_bool(c[5]-c[4]-c[1]+c[0], s[0]);
    let a2  = c[4]-c[0];

    let a10 = mul_point_with_bool(c[3]-c[2]-c[1]+c[0], s10);
    let a1 = mul_point_with_bool(c[2]-c[0], s[1]);
    let a0 = mul_point_with_bool(c[1]-c[0], s[0]);
    let a  = c[0];

    let out = mul_point_with_bool(a210 + a21 + a20 + a2, s[2]) + a10 + a1 + a0 + a;
    out 

}

/// Calculate mux3 using 3-bit lookup table (constraint version)
fn mux3_gadget(data: JubJubAffine, bits: &[Variable]) -> JubJubAffine {
    
    todo!();
}



/// This function is from the orginal method of encoding functions
/// in pedersen hash 
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


/// zk pedersen
/// TODO: Hash from bytes or convert scalar internally
pub fn circuit_pedersen(composer: &mut StandardComposer, scalar: [bool; 256]) -> Point {

    let second_bases = scalar[200..].len() / 4;

    let full_ladder = HashLadder::new(
        GENERATOR_EXTENDED,
        GENERATOR_NUMS_EXTENDED,
        50,
        second_bases,
    );

    const CHUNK_SIZE: usize = 4; 
    todo!()


}

#[cfg(test)]
mod tests{
    use dusk_jubjub::{JubJubScalar};

    #[test]
    fn test_mux3_native() {
        let points = (0..8u64).map(|i| dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(i)).collect::<Vec<_>>();
        assert_eq!(
            super::mux3(&points, &[false, false, false]), // 0b000
            points[0]
        );
        assert_eq!(
            super::mux3(&points, &[true, false, false]),  // 0b001
            points[1]
        );
        assert_eq!(
            super::mux3(&points, &[false, true, false]),  // 0b010
            points[2]
        );
        assert_eq!(
            super::mux3(&points, &[true, true, false]),   // 0b011
            points[3]
        );
        assert_eq!(
            super::mux3(&points, &[false, false, true]),  // 0b100
            points[4]
        );
        assert_eq!(
            super::mux3(&points, &[true, false, true]),   // 0b101
            points[5]
        );
        assert_eq!(
            super::mux3(&points, &[false, true, true]),   // 0b110
            points[6]
        );
        assert_eq!(
            super::mux3(&points, &[true, true, true]),    // 0b111
            points[7]
        );
    }
}