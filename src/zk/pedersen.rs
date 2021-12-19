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

use ark_ec::PairingEngine;
use ark_ec::{
    models::TEModelParameters as Parameters,
    twisted_edwards_extended::{GroupAffine, GroupProjective},
    ProjectiveCurve,
};
use ark_ff::PrimeField;
use ark_plonk::constraint_system::{StandardComposer, Variable};
use ark_plonk::prelude::Point;
use num_traits::identities::One;
use num_traits::Zero;
use std::{marker::PhantomData, ops::Add};
const NUM_BITS_PER_CHUNK: usize = 4;
// we use 3-bit lookup tables for the pedersen hash, each chunk is 4-bits.
const BASE_SIZE: usize = 1 << (NUM_BITS_PER_CHUNK - 1); // should be 8

#[derive(Clone, Copy)]
/// Precomputed powers of P..BASE_SIZE*P
pub struct PrecomputedBases<P: Parameters> {
    powers_of_p: [GroupAffine<P>; BASE_SIZE],
}
/// Pedersen Ladder contains precomputed powers
/// of a group generator G, for different windows
/// of bits
pub struct PedersenLadder<E: PairingEngine, P: Parameters<BaseField = E::Fr>> {
    rows: Vec<PrecomputedBases<P>>,
    _engine: PhantomData<E>,
}
// /// Quad langth 4. Incoming bits = 256.
// /// numbers of windows needed 256/4 + 1 = 65.
// /// With the last window deciding if the outcome is odd or even
// /// many ladders
// ///
// /// Hash ladder is a struct which contains two Pedersen ladders
// pub struct HashLadder<E: PairingEngine, P: Parameters<BaseField = E::Fr>> {
//     first_table: PedersenLadder<E, P>,
//     second_table: PedersenLadder<E, P>,
//     _engine: PhantomData<E>,
// }

// impl<E: PairingEngine, P: Parameters<BaseField = E::Fr>> HashLadder<E, P> {
//     /// Construct Hash Ladder
//     pub fn new(
//         p: GroupProjective<P>,
//         p_prime: GroupProjective<P>,
//         num_bases: usize,
//         num_bases_prime: usize,
//     ) -> Self {
//         Self {
//             first_table: PedersenLadder::new(p, num_bases),
//             second_table: PedersenLadder::new(p_prime, num_bases_prime),
//             _engine: PhantomData,
//         }
//     }
// }

impl<E: PairingEngine, P: Parameters<BaseField = E::Fr>> PedersenLadder<E, P> {
    /// Construct Pedersen Ladder
    pub fn new(p: GroupProjective<P>, num_bases: usize) -> Self {
        // we have p*(2^(5*0)), p*(2^(5*1)), p*(2^(5*2))), ..., p*(2^(5*(num_base-1)))) as each base
        let base_point_step = E::Fr::from((2 as u64).pow(5 as u32));
        let mut current_base_point = E::Fr::one();

        let bases = (0..num_bases)
            .into_iter()
            .map(|_| {
                let result = PrecomputedBases::new(p.mul(current_base_point.into_repr()));
                current_base_point = current_base_point * base_point_step;
                result
            })
            .collect();

        Self {
            rows: bases,
            _engine: PhantomData,
        }
    }
}

fn point_mul<P: Parameters>(
    mut point: GroupProjective<P>,
    scalar: P::ScalarField,
) -> GroupProjective<P> {
    point *= scalar;
    point
}

impl<P: Parameters> PrecomputedBases<P> {
    /// Construct set of bases
    pub fn new(base_point: GroupProjective<P>) -> Self {
        let bases_vec = (0..BASE_SIZE)
            .into_iter()
            .map(|i| ({ point_mul(base_point, P::ScalarField::from((i + 1) as u64)) }).into())
            .collect::<Vec<_>>();

        let mut bases: [GroupAffine<P>; BASE_SIZE] =
            [GroupAffine::<P>::from(base_point).into(); BASE_SIZE];
        bases.copy_from_slice(bases_vec.as_slice());

        Self { powers_of_p: bases }
    }
}

pub fn mux3<T: Copy>(c: &[T], s: &[bool]) -> T {
    assert_eq!(c.len(), 8);
    assert_eq!(s.len(), 3);
    // treat s is little endian, convert s to usize
    let s_usize = s
        .iter()
        .enumerate()
        .map(|(i, &b)| (b as usize) << i)
        .sum::<usize>();
    c[s_usize]
}

/// calculate
/// s10 * v1 + s1 * v2 + s0 * v3 + v4
fn mux3_subgadget<E: PairingEngine, P: Parameters<BaseField = E::Fr>>(
    composer: &mut StandardComposer<E, P>,
    v1: E::Fr,
    v2: E::Fr,
    v3: E::Fr,
    v4: E::Fr,
    s10: Variable,
    s1: Variable,
    s0: Variable,
) -> Variable {
    composer.big_add((v1, s10), (v2, s1), Some((v3, s0)), v4, None)
}

/// Calculate mux3 using 3-bit lookup table (constraint version)
/// We assume that the bits are already constrained by boolean.
///
/// * `c`: constant data
/// * `s`: selection bits
pub fn mux3_variable_gadget<E: PairingEngine, P: Parameters<BaseField = E::Fr>>(
    composer: &mut StandardComposer<E, P>,
    s10: Variable,
    c: &[E::Fr],
    s: &[Variable],
) -> Variable {
    assert_eq!(c.len(), 8);
    assert_eq!(s.len(), 3);

    let left = {
        let v1 = c[7] - c[6] - c[5] + c[4] - c[3] + c[2] + c[1] - c[0];
        let v2 = c[6] - c[4] - c[2] + c[0];
        let v3 = c[5] - c[4] - c[1] + c[0];
        let v4 = c[4] - c[0];
        let s0 = s[0];
        let s1 = s[1];
        let s10 = s10;
        // s10 * v1 + s1 * v2 + s0 * v3 + v4
        mux3_subgadget(composer, v1, v2, v3, v4, s10, s1, s0)
    };

    let right = {
        let v1 = c[3] - c[2] - c[1] + c[0];
        let v2 = c[2] - c[0];
        let v3 = c[1] - c[0];
        let v4 = c[0];
        let s0 = s[0];
        let s1 = s[1];
        let s10 = s10;
        // s10 * v1 + s1 * v2 + s0 * v3 + v4
        mux3_subgadget(composer, v1, v2, v3, v4, s10, s1, s0)
    };

    // left * s[2] + right
    composer.big_mul(
        E::Fr::one(),
        left,
        s[2],
        Some((E::Fr::one(), right)),
        E::Fr::zero(),
        None,
    )
}

pub fn mux3_point_gadget<E: PairingEngine, P: Parameters<BaseField = E::Fr>>(
    composer: &mut StandardComposer<E, P>,
    c: &[GroupAffine<P>],
    s: &[Variable],
) -> Point<E, P> {
    assert_eq!(c.len(), 8);
    assert_eq!(s.len(), 3);

    let (xs, ys): (Vec<_>, Vec<_>) = c.iter().map(|p| (p.x, p.y)).unzip();

    let s10 = composer.mul(E::Fr::one(), s[1], s[0], E::Fr::zero(), None);

    let x = mux3_variable_gadget(composer, s10, &xs, &s);
    let y = mux3_variable_gadget(composer, s10, &ys, &s);

    Point::new(x, y)
}

/// calcualte 4-bit window using lookup table. First three bit looks up the table, and the last bit conditionally negate the output.
fn pedersen_4bit_chunk<E: PairingEngine, P: Parameters<BaseField = E::Fr>>(
    bases: &PrecomputedBases<P>,
    bits: &[bool],
) -> GroupAffine<P> {
    let raw = mux3(&bases.powers_of_p, &bits[..3]);
    if bits[3] {
        -raw
    } else {
        raw
    }
}

/// perdersen 4-bit window gadgets using lookup table
pub fn pedersen_4bit_chunk_gadget<E: PairingEngine, P: Parameters<BaseField = E::Fr>>(
    composer: &mut StandardComposer<E, P>,
    bases: &PrecomputedBases<P>,
    bits: &[Variable],
) -> Point<E, P> {
    let raw = mux3_point_gadget(composer, &bases.powers_of_p, &bits[..3]);
    composer.conditional_point_neg(bits[3], raw)
}

pub fn pedersen_window<E: PairingEngine, P: Parameters<BaseField = E::Fr>>(
    ladder: &PedersenLadder<E, P>,
    bits: &[bool],
) -> GroupProjective<P> {
    let expected_bits = NUM_BITS_PER_CHUNK * ladder.rows.len();
    assert_eq!(bits.len(), expected_bits);

    // for each chunk, calculate the point and add them together
    bits.chunks(NUM_BITS_PER_CHUNK)
        .zip(ladder.rows.iter())
        .map(|(s, bases)| pedersen_4bit_chunk::<E, P>(bases, s))
        .fold(GroupProjective::zero(), |acc, p| {
            acc.add(GroupProjective::from(p))
        })
}

pub fn pedersen_window_gadget<E: PairingEngine, P: Parameters<BaseField = E::Fr>>(
    composer: &mut StandardComposer<E, P>,
    ladder: &PedersenLadder<E, P>,
    bits: &[Variable],
) -> Point<E, P> {
    let expected_bits = NUM_BITS_PER_CHUNK * ladder.rows.len();
    assert_eq!(bits.len(), expected_bits);

    let point_identity = Point::identity(composer);
    // for each chunk, calculate the point and add them together
    let points_for_each_chunk = bits
        .chunks(NUM_BITS_PER_CHUNK)
        .zip(ladder.rows.iter())
        .map(|(s, bases)| pedersen_4bit_chunk_gadget(composer, bases, s))
        .collect::<Vec<_>>();

    points_for_each_chunk
        .into_iter()
        .fold(point_identity, |acc, p| {
            composer.point_addition_gate(acc, p)
        })
}

/// Pedersen hash **without** padding. We assume that the input is already padded to the correct length.
///
/// **Invariant**:
/// - `input.len() == NUM_BITS_PER_CHUNK * num_chunks_in_window * ladders.len()`. Here `NUM_BITS_PER_CHUNK` is 4.
/// - for each `ladder`, `ladder.rows.len() == num_chunks_in_window`
pub fn pedersen_hash<E: PairingEngine, P: Parameters<BaseField = E::Fr>>(
    num_chunks_in_window: usize,
    ladders: &[PedersenLadder<E, P>],
    input: &[bool],
) -> GroupProjective<P> {
    assert_eq!(input.len(), 4 * num_chunks_in_window * ladders.len());
    assert!(ladders.iter().all(|l| l.rows.len() == num_chunks_in_window));

    let num_bits_in_window = num_chunks_in_window * NUM_BITS_PER_CHUNK;
    let point_identity = GroupProjective::zero();
    input
        .chunks(num_bits_in_window)
        .zip(ladders.iter())
        .map(|(s, l)| pedersen_window(l, s))
        .fold(point_identity, |acc, p| acc.add(p))
}

pub fn pedersen_hash_gadget<E: PairingEngine, P: Parameters<BaseField = E::Fr>>(
    num_chunks_in_window: usize,
    composer: &mut StandardComposer<E, P>,
    ladders: &[PedersenLadder<E, P>],
    input: &[Variable],
) -> Point<E, P> {
    assert_eq!(input.len(), 4 * num_chunks_in_window * ladders.len());
    assert!(ladders.iter().all(|l| l.rows.len() == num_chunks_in_window));

    let num_bits_in_window = num_chunks_in_window * NUM_BITS_PER_CHUNK;
    let point_identity = Point::identity(composer);

    let points_for_each_window = input
        .chunks(num_bits_in_window)
        .zip(ladders.iter())
        .map(|(s, l)| pedersen_window_gadget(composer, l, s))
        .collect::<Vec<_>>();

    points_for_each_window
        .into_iter()
        .fold(point_identity, |acc, p| {
            composer.point_addition_gate(acc, p)
        })
}
#[cfg(test)]
mod tests {
    // `gadget_tester` is not public in `ark-plonk` yet. Test is disabled.

    // use dusk_bls12_381::BlsScalar;
    // use dusk_jubjub::{GENERATOR_EXTENDED, JubJubAffine, JubJubScalar};
    // use dusk_plonk::{constraint_system::helper::gadget_tester, prelude::{StandardComposer}};
    // use rand::{Rng, SeedableRng, prelude::StdRng};

    // use crate::zk::pedersen::{mux3, pedersen_window, pedersen_window_gadget};

    // use super::{NUM_BITS_PER_CHUNK, PedersenLadder, PrecomputedBases, mux3_point_gadget, mux3_variable_gadget, pedersen_4bit_chunk, pedersen_4bit_chunk_gadget};

    // #[test]
    // fn test_mux3_native() {
    //     let points = (0..8u64).map(|i| BlsScalar::from(i)).collect::<Vec<_>>();
    //     assert_eq!(
    //         mux3(&points, &[false, false, false]), // 0b000
    //         points[0]
    //     );
    //     assert_eq!(
    //         mux3(&points, &[true, false, false]),  // 0b001
    //         points[1]
    //     );
    //     assert_eq!(
    //         mux3(&points, &[false, true, false]),  // 0b010
    //         points[2]
    //     );
    //     assert_eq!(
    //         mux3(&points, &[true, true, false]),   // 0b011
    //         points[3]
    //     );
    //     assert_eq!(
    //         mux3(&points, &[false, false, true]),  // 0b100
    //         points[4]
    //     );
    //     assert_eq!(
    //         mux3(&points, &[true, false, true]),   // 0b101
    //         points[5]
    //     );
    //     assert_eq!(
    //         mux3(&points, &[false, true, true]),   // 0b110
    //         points[6]
    //     );
    //     assert_eq!(
    //         mux3(&points, &[true, true, true]),    // 0b111
    //         points[7]
    //     );
    // }

    // fn test_three_bit_gadget_on_bit(composer: &mut StandardComposer, c: &[BlsScalar], s: &[bool]) {
    //     let expected = mux3(c, s);
    //     let bits_var = s.iter().map(|b| composer.add_input(if *b {BlsScalar::one()} else {
    //         BlsScalar::zero()
    //     })).collect::<Vec<_>>();
    //     let s10 = composer.mul(BlsScalar::one(), bits_var[1], bits_var[0], BlsScalar::zero() , None);
    //     let actual = mux3_variable_gadget(composer, s10, c, &bits_var);
    //     composer.constrain_to_constant(actual, expected, None);

    // }

    // fn test_three_bit_point_gadget_on_bit(composer: &mut StandardComposer, c: &[JubJubAffine], s: &[bool]) {
    //     let expected = mux3(c, s);
    //     let bits_var = s.iter().map(|b| composer.add_input(if *b {BlsScalar::one()} else {
    //         BlsScalar::zero()
    //     })).collect::<Vec<_>>();
    //     let actual = mux3_point_gadget(composer, c, &bits_var);
    //     composer.assert_equal_public_point(actual, expected);
    // }

    // fn test_pedersen_window_on_bit(composer: &mut StandardComposer, c: &PrecomputedBases, s: &[bool], enforce: bool) {
    //     let expected = pedersen_4bit_chunk(c, s);
    //     let bits_var = s.iter().map(|b| composer.add_input(if *b {BlsScalar::one()} else {
    //         BlsScalar::zero()
    //     })).collect::<Vec<_>>();
    //     let actual = pedersen_4bit_chunk_gadget(composer, c, &bits_var);
    //     if enforce {
    //         composer.assert_equal_public_point(actual, expected.into());
    //     }
    // }

    // /// Return little endian representations of 0..end
    // fn little_endian_range(end: usize, bit_size: usize) -> Vec<Vec<bool>> {
    //     (0..end).map(|i| {
    //         // convert i to little endian
    //         (0..bit_size).map(|shift| (i >> shift) & 1 == 1).collect::<Vec<_>>()
    //     }).collect()
    // }

    // #[test]
    // fn test_three_bit_mux_gadget() {
    //     gadget_tester(|composer|{
    //         let data = (0..8u64).map(|i| BlsScalar::from(i)).collect::<Vec<_>>();
    //         little_endian_range(8, 3).iter().for_each(|s| {
    //             test_three_bit_gadget_on_bit(composer, &data, &s);
    //         });
    //     }, 100).unwrap();
    // }

    // #[test]
    // fn three_bit_constraints_stat() {
    //     let mut composer = StandardComposer::new();
    //     let composer = &mut composer;
    //     let points = (0..8u64).map(|i| BlsScalar::from(i)).collect::<Vec<_>>();
    //     little_endian_range(8, 3).iter().for_each(|s| {
    //         test_three_bit_gadget_on_bit(composer, &points, &s);
    //     });
    //     println!("mux3 constraints size: {}", composer.circuit_size() / 8);
    // }

    // #[test]
    // fn test_three_bit_point_mux_gadget() {
    //     gadget_tester(|composer|{
    //         let data = (0..8u64).map(|i| (GENERATOR_EXTENDED * JubJubScalar::from(i)).into()).collect::<Vec<_>>();
    //         little_endian_range(8, 3).iter().for_each(|s| {
    //             test_three_bit_point_gadget_on_bit(composer, &data, &s);
    //         });
    //     }, 150).unwrap();
    // }

    // #[test]
    // fn three_bit_point_constraints_stat() {
    //     let mut composer = StandardComposer::new();
    //     let composer = &mut composer;
    //     let points = (0..8u64).map(|i| (GENERATOR_EXTENDED * JubJubScalar::from(i)).into()).collect::<Vec<_>>();
    //     little_endian_range(8, 3).iter().for_each(|s| {
    //         test_three_bit_point_gadget_on_bit(composer, &points, &s);
    //     });
    //     println!("mux3 point constraints size: {}", composer.circuit_size() / 8);
    // }

    // fn pedersen_chunk_gadget_test_template(composer: &mut StandardComposer, enforce: bool) {
    //     let base = PrecomputedBases::new(dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(6666u64));
    //     little_endian_range(16, 4).iter().for_each(|s| {
    //         test_pedersen_window_on_bit(composer, &base, &s, enforce);
    //     });
    // }

    // #[test]
    // fn test_pedersen_chunk_gadget() {
    //     gadget_tester(|composer|{
    //         pedersen_chunk_gadget_test_template(composer, true);
    //     }, 1000).unwrap();
    // }

    // #[test]
    // fn pedersen_chunk_gadget_stat() {
    //     let mut composer = StandardComposer::new();
    //     pedersen_chunk_gadget_test_template(&mut composer, false);
    //     println!("pedersen chunk constraints size: {}", composer.circuit_size() / 16);
    // }

    // fn pedersen_window_gadget_test_template(composer: &mut StandardComposer, enforce: bool){
    //     const NUM_CHUNKS: usize = 64;
    //     let num_bits = NUM_BITS_PER_CHUNK * NUM_CHUNKS;

    //     let mut rng = StdRng::seed_from_u64(12345);
    //     let gen = GENERATOR_EXTENDED * JubJubScalar::from(6666u64);
    //     let ladder = PedersenLadder::new(gen, NUM_CHUNKS);

    //     let bits = (0..num_bits).map(|_| rng.gen::<bool>()).collect::<Vec<_>>();
    //     let bits_var = bits.iter().map(|b| composer.add_input(if *b {BlsScalar::one()} else {
    //         BlsScalar::zero()
    //     })).collect::<Vec<_>>();

    //     let expected = pedersen_window(&ladder, &bits);
    //     let actual = pedersen_window_gadget(composer, &ladder,&bits_var);

    //     if enforce {
    //         composer.assert_equal_public_point(actual, expected.into());
    //     }
    // }

    // #[test]
    // fn test_pedersen_window_gadget() {
    //     gadget_tester(|composer|{
    //         pedersen_window_gadget_test_template(composer, true);
    //     }, 2000).unwrap();
    // }

    // #[test]
    // fn pedersen_window_gadget_stat() {
    //     let mut composer = StandardComposer::new();
    //     pedersen_window_gadget_test_template(&mut composer, false);
    //     println!("pedersen window constraints size: {}", composer.circuit_size());
    // }
}
