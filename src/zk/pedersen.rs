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
/// * `s`: selection bits
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

/// calcualte 4-bit window using lookup table. First three bit looks up the table, and the last bit conditionally negate the output. 
fn pedersen_4bit_window(ladder: &PrecomputedBases, bits: &[bool]) -> JubJubExtended {
    assert_eq!(bits.len(), 4);
    let mut selected_base = mux3(&ladder.powers_of_p, &bits[..3]);
    if bits[3] {
        selected_base = selected_base.neg();
    }
    selected_base
}

fn mul_point_with_bool_gadget(composer: &mut StandardComposer, point: JubJubExtended, bit: Variable) -> Point {
    let temp = composer.add_affine_to_circuit_description(point.into()).into();
    composer.conditional_select_identity(bit, temp)
}

/// calculate the sum of points
/// Requires 2 * num_points constraints
fn point_sum_gadget(composer: &mut StandardComposer, points: &[Point]) -> Point {
    points[1..].iter().fold(points[0], |acc, point| composer.point_addition_gate(acc, *point))
}

/// Calculate mux3 using 3-bit lookup table (constraint version)
/// We assume that the bits are already constrained by boolean. 
/// 
/// * `c`: constant data
/// * `s`: selection bits
pub fn mux3_gadget(composer: &mut StandardComposer, c: &[JubJubExtended], s: &[Variable]) -> Point {
    assert_eq!(c.len(), 8);
    assert_eq!(s.len(), 3);

    let s10 = composer.mul(BlsScalar::one(), s[1], s[0], BlsScalar::zero() , None);

    let a210 = mul_point_with_bool_gadget(composer, c[7]-c[6]-c[5]+c[4] - c[3]+c[2]+c[1]-c[0], s10);
    let a21 = mul_point_with_bool_gadget(composer, c[6]-c[4]-c[2]+c[0], s[1]);
    let a20 = mul_point_with_bool_gadget(composer, c[5]-c[4]-c[1]+c[0], s[0]);
    let a2 = composer.add_affine_to_circuit_description((c[4]-c[0]).into());

    let a10 = mul_point_with_bool_gadget(composer, c[3]-c[2]-c[1]+c[0], s10);
    let a1 = mul_point_with_bool_gadget(composer, c[2]-c[0], s[1]);
    let a0 = mul_point_with_bool_gadget(composer, c[1]-c[0], s[0]);
    let a = composer.add_affine_to_circuit_description((c[0]).into());

    // addition phase
    let signal_before_select = point_sum_gadget(composer, &[a210, a21, a20, a2]);
    let signal_after_select = composer.conditional_select_identity(s[2], signal_before_select);
    let out = point_sum_gadget(composer, &[signal_after_select, a10, a1, a0, a]);

    out
}

/// perdersen 4-bit window gadgets using lookup table
fn pedersen_4bit_window_gadget(composer: &mut StandardComposer, ladder: &PrecomputedBases, bits: &[Variable]) -> Point {
    assert_eq!(bits.len(), 4);
    let selected_base = mux3_gadget(composer, &ladder.powers_of_p, &bits[..3]);
    let selected_base_negated = composer.point_negation_gate(selected_base);

    composer.conditional_point_select(selected_base_negated, selected_base, bits[3])
}


#[cfg(test)]
mod tests{
    use dusk_bls12_381::BlsScalar;
    use dusk_jubjub::{JubJubExtended, JubJubScalar};
    use dusk_plonk::{constraint_system::helper::gadget_tester, prelude::{Point, StandardComposer}}; 

    use super::{PrecomputedBases, mux3, mux3_gadget, pedersen_4bit_window, pedersen_4bit_window_gadget};

    #[test]
    fn test_mux3_native() {
        let points = (0..8u64).map(|i| dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(i)).collect::<Vec<_>>();
        assert_eq!(
            mux3(&points, &[false, false, false]), // 0b000
            points[0]
        );
        assert_eq!(
            mux3(&points, &[true, false, false]),  // 0b001
            points[1]
        );
        assert_eq!(
            mux3(&points, &[false, true, false]),  // 0b010
            points[2]
        );
        assert_eq!(
            mux3(&points, &[true, true, false]),   // 0b011
            points[3]
        );
        assert_eq!(
            mux3(&points, &[false, false, true]),  // 0b100
            points[4]
        );
        assert_eq!(
            mux3(&points, &[true, false, true]),   // 0b101
            points[5]
        );
        assert_eq!(
            mux3(&points, &[false, true, true]),   // 0b110
            points[6]
        );
        assert_eq!(
            mux3(&points, &[true, true, true]),    // 0b111
            points[7]
        );
    }

    fn test_three_bit_gadget_on_bit(composer: &mut StandardComposer, c: &[JubJubExtended], s: &[bool]) {
        let expected = mux3(c, s);
        let bits_var = s.iter().map(|b| composer.add_input(if *b {BlsScalar::one()} else {
            BlsScalar::zero()
        })).collect::<Vec<_>>();
        let actual = mux3_gadget(composer, c, &bits_var);
        composer.assert_equal_public_point(actual, expected.into());

    }

    fn test_pedersen_window_on_bit(composer: &mut StandardComposer, c: &PrecomputedBases, s: &[bool]) {
        let expected = pedersen_4bit_window(c, s);
        let bits_var = s.iter().map(|b| composer.add_input(if *b {BlsScalar::one()} else {
            BlsScalar::zero()
        })).collect::<Vec<_>>();
        let actual = pedersen_4bit_window_gadget(composer, c, &bits_var);
        composer.assert_equal_public_point(actual, expected.into());
    }



    #[test]
    fn test_three_bit_mux_gadget() {
        gadget_tester(|composer|{
            let points = (0..8u64).map(|i| dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(i)).collect::<Vec<_>>();
            test_three_bit_gadget_on_bit(composer, &points, &[false, false, false]);
            test_three_bit_gadget_on_bit(composer, &points, &[true, false, false]);
            test_three_bit_gadget_on_bit(composer, &points, &[false, true, false]);
            test_three_bit_gadget_on_bit(composer, &points, &[true, true, false]);
            test_three_bit_gadget_on_bit(composer, &points, &[false, false, true]);
            test_three_bit_gadget_on_bit(composer, &points, &[true, false, true]);
            test_three_bit_gadget_on_bit(composer, &points, &[false, true, true]);
            test_three_bit_gadget_on_bit(composer, &points, &[true, true, true]);
        }, 1000).unwrap();
    }

    #[test]
    fn three_bit_constraints_stat() {
        let mut composer = StandardComposer::new();
        let composer = &mut composer;
        let points = (0..8u64).map(|i| dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(i)).collect::<Vec<_>>();
        test_three_bit_gadget_on_bit(composer, &points, &[false, false, false]);
        test_three_bit_gadget_on_bit(composer, &points, &[true, false, false]);
        test_three_bit_gadget_on_bit(composer, &points, &[false, true, false]);
        test_three_bit_gadget_on_bit(composer, &points, &[true, true, false]);
        test_three_bit_gadget_on_bit(composer, &points, &[false, false, true]);
        test_three_bit_gadget_on_bit(composer, &points, &[true, false, true]);
        test_three_bit_gadget_on_bit(composer, &points, &[false, true, true]);
        test_three_bit_gadget_on_bit(composer, &points, &[true, true, true]);
        println!("mux3 constraints size: {}", composer.circuit_size() / 8);
    }

    fn pedersen_window_gadget_test_template(composer: &mut StandardComposer) {
        let base = PrecomputedBases::new(dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(6666u64));
        test_pedersen_window_on_bit(composer, &base, &[false, false, false, false]);
        test_pedersen_window_on_bit(composer, &base, &[true, false, false, false]);
        test_pedersen_window_on_bit(composer, &base, &[false, true, false, false]);
        test_pedersen_window_on_bit(composer, &base, &[true, true, false, false]);
        test_pedersen_window_on_bit(composer, &base, &[false, false, true, false]);
        test_pedersen_window_on_bit(composer, &base, &[true, false, true, false]);
        test_pedersen_window_on_bit(composer, &base, &[false, true, true, false]);
        test_pedersen_window_on_bit(composer, &base, &[true, true, true, false]);
        test_pedersen_window_on_bit(composer, &base, &[false, false, false, true]);
        test_pedersen_window_on_bit(composer, &base, &[true, false, false, true]);
        test_pedersen_window_on_bit(composer, &base, &[false, true, false, true]);
        test_pedersen_window_on_bit(composer, &base, &[true, true, false, true]);
        test_pedersen_window_on_bit(composer, &base, &[false, false, true, true]);
        test_pedersen_window_on_bit(composer, &base, &[true, false, true, true]);
        test_pedersen_window_on_bit(composer, &base, &[false, true, true, true]);
        test_pedersen_window_on_bit(composer, &base, &[true, true, true, true]);
    }

    #[test]
    fn test_pedersen_window_gadget() {
        gadget_tester(|composer|{
            pedersen_window_gadget_test_template(composer);
        }, 2000).unwrap();
    }

    #[test]
    fn pedersen_window_gadget_stat() {
        let mut composer = StandardComposer::new();
        pedersen_window_gadget_test_template(&mut composer);
        println!("pedersen window constraints size: {}", composer.circuit_size() / 16);
    }
}