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

//! Gadget implementations

use super::AllocatedScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::constraint_system::ecc::Point;
use dusk_plonk::constraint_system::StandardComposer;

use dusk_plonk::prelude::*;

/// Function to calculate in-circuit pedersen commitment
pub fn commitment_gadget(
    composer: &mut StandardComposer,
    value: Variable,
    blinder: Variable,
) -> Point {
    // computer value * generator
    let p1 = composer.fixed_base_scalar_mul(value, GENERATOR_EXTENDED);

    // computer value * generator_nums
    let p2 = composer.fixed_base_scalar_mul(blinder, GENERATOR_NUMS_EXTENDED);

    // compute p1 + p2
    composer.point_addition_gate(p1, p2)
}

// Function to calculate in-circuit variable length pedersen commitment
pub fn variable_length_pedersen_commitment_gadget(
    composer: &mut StandardComposer,
    value_variables: Vec<Variable>,
    blinder_variables: Vec<Variable>,
) -> Point {
    // Conduct fixed length pedersen commitment over individual m/r pairs, and accumulate in output_point
    let mut output_point = commitment_gadget(composer, value_variables[0], blinder_variables[0]);
    for i in 1..value_variables.len() {
        let tmp_point = commitment_gadget(composer, value_variables[i], blinder_variables[i]);
        // TODO: Not sure whether we should accumulate with point_addition_gate.
        output_point = composer.point_addition_gate(output_point, tmp_point);
    }
    output_point
}

/// Returns 1 if a = b and zero otherwise.
///
/// # NOTE
/// If you need to check equality constraining it, this function is not intended for it,
/// instead we recommend to use `composer.assert_equals()` or `composer.constraint_to_constant()`
/// functions from `dusk-plonk` crate which will introduce less constraints to your circuit.
pub fn maybe_equal(
    composer: &mut StandardComposer,
    a: AllocatedScalar,
    b: AllocatedScalar,
) -> Variable {
    // u = a - b
    let u = {
        let q_l_a = (BlsScalar::one(), a.var);
        let q_r_b = (-BlsScalar::one(), b.var);
        let q_c = BlsScalar::zero();

        composer.add(q_l_a, q_r_b, q_c, None)
    };

    // compute z = inverse of u.
    // This is zero for zero and non-zero otherwise
    let u_scalar = a.scalar - b.scalar;
    let u_inv_scalar = u_scalar.invert().unwrap_or(BlsScalar::zero());
    let z = composer.add_input(u_inv_scalar);

    // y = 1 - uz
    let y = composer.mul(-BlsScalar::one(), z, u, BlsScalar::one(), None);

    // yu = 0
    {
        let a = y;
        let b = u;
        let c = u;
        let q_m = BlsScalar::one();
        let q_o = BlsScalar::zero();
        let q_c = BlsScalar::zero();

        composer.mul_gate(a, b, c, q_m, q_o, q_c, None);
    }
    y
}

/// Returns a 0 or a 1, if the value lies within the specified range
/// We do this by decomposing the scalar and showing that it can be represented in x amount of bits
fn range_proof(composer: &mut StandardComposer, value: AllocatedScalar, num_bits: u64) -> Variable {
    let (is_equal, _value_bits) = scalar_decomposition_gadget(composer, num_bits as usize, value);
    is_equal
}

/// Returns a 1 if min_range <= x < max_range and zero otherwise
pub fn range_check(
    composer: &mut StandardComposer,
    min_range: BlsScalar,
    max_range: BlsScalar,
    witness: AllocatedScalar,
) -> Variable {
    // Upper bound check
    let (y1, num_bits_pow_2) = max_bound(composer, max_range, witness);

    // Lower bound check
    let y2 = min_bound(composer, min_range, witness, num_bits_pow_2);

    // Computes y1 * y2
    // If both lower and upper bound checks are true,
    // then this will return 1 otherwise it returns 0
    composer.mul(BlsScalar::one(), y1, y2, BlsScalar::zero(), None)
}

/// Returns a 0 or a 1, if the witness is greater than or equal to the minimum bound
/// The statement a <= x  , implies x - a >= 0 , for all values x,a
/// Instead of proving x - a is positive for all values in the field, it is sufficient to prove
/// it is positive for a specific power of two.
/// This power of two must be large enough to cover the whole range of values x and a can take
/// Therefore it must be the closest power of two, to the upper bound
/// In this case, the upper bound is a witness, hence the Prover and Verifier will need to know in advance
/// The maximum number of bits that the witness could be  
pub fn min_bound(
    composer: &mut StandardComposer,
    min_range: BlsScalar,
    witness: AllocatedScalar,
    num_bits: u64,
) -> Variable {
    // Compute x - a in the circuit
    let x_min_a_var = {
        let q_l_a = (BlsScalar::one(), witness.var);
        let q_r_b = (BlsScalar::zero(), witness.var); // XXX: Expose composer.zero()
        let q_c = -min_range;

        composer.add(q_l_a, q_r_b, q_c, None)
    };

    // Compute witness assignment value for x - a
    let x_min_a_scalar = witness.scalar - min_range;

    let x_min_a = AllocatedScalar {
        var: x_min_a_var,
        scalar: x_min_a_scalar,
    };
    range_proof(composer, x_min_a, num_bits)
}

/// Returns a 0 or a 1, if the witness is greater than the maximum bound
/// x < b which implies that b - x - 1 >= 0
/// Note that since the maximum bound is public knowledge
/// the num_bits can be computed
pub fn max_bound(
    composer: &mut StandardComposer,
    max_range: BlsScalar,
    witness: AllocatedScalar,
) -> (Variable, u64) {
    let max_range = max_range - BlsScalar::one();

    // Since the upper bound is public, we can compute the number of bits in the closest power of two
    let num_bits_pow_2 = num_bits_closest_power_of_two(max_range);

    // Compute b - x in the circuit
    let b_minus_x_var = {
        let q_l_a = (-BlsScalar::one(), witness.var);
        let q_r_b = (BlsScalar::zero(), witness.var); // XXX: Expose composer.zero()
        let q_c = max_range;

        composer.add(q_l_a, q_r_b, q_c, None)
    };

    // Compute witness assignment value for b - x
    let b_minus_x_scalar = max_range - witness.scalar;

    let b_prime_plus_x = AllocatedScalar {
        var: b_minus_x_var,
        scalar: b_minus_x_scalar,
    };

    (
        range_proof(composer, b_prime_plus_x, num_bits_pow_2),
        num_bits_pow_2,
    )
}

/// Decomposes a witness and constraints it to be equal to it's bit representation
/// Returns a 0 or 1 if the witness can be represented in the specified number of bits
/// This effectively makes it a rangeproof. If the witness can be represented in less than x bits, then
/// It must be with the range of [0, 2^x)
fn scalar_decomposition_gadget(
    composer: &mut StandardComposer,
    num_bits: usize,
    witness: AllocatedScalar,
) -> (Variable, Vec<Variable>) {
    // Decompose the bits
    let scalar_bits = scalar_to_bits(&witness.scalar);

    // Add all the bits into the composer
    let scalar_bits_var: Vec<Variable> = scalar_bits
        .iter()
        .map(|bit| composer.add_input(BlsScalar::from(*bit as u64)))
        .collect();

    // Take the first n bits
    let scalar_bits_var = scalar_bits_var[..num_bits].to_vec();

    // Now ensure that the bits correctly accumulate to the witness given
    // XXX: Expose a method called .zero() on composer
    let mut accumulator = AllocatedScalar {
        var: composer.add_witness_to_circuit_description(BlsScalar::zero()),
        scalar: BlsScalar::zero(),
    };

    for (power, bit) in scalar_bits_var.iter().enumerate() {
        composer.boolean_gate(*bit);

        let two_pow = BlsScalar::from(2).pow(&[power as u64, 0, 0, 0]);
        let q_l_a = (two_pow, *bit);
        let q_r_b = (BlsScalar::one(), accumulator.var);
        let q_c = BlsScalar::zero();

        accumulator.var = composer.add(q_l_a, q_r_b, q_c, None);
        accumulator.scalar += two_pow * BlsScalar::from(scalar_bits[power] as u64);
    }

    let is_equal = maybe_equal(composer, accumulator, witness);

    (is_equal, scalar_bits_var)
}

// Decompose a `BlsScalar` into its 256-bit representation.
fn scalar_to_bits(scalar: &BlsScalar) -> [u8; 256] {
    let mut res = [0u8; 256];
    let bytes = scalar.to_bytes();
    for (byte, bits) in bytes.iter().zip(res.chunks_mut(8)) {
        bits.iter_mut()
            .enumerate()
            .for_each(|(i, bit)| *bit = (byte >> i) & 1)
    }
    res
}

// Count the minimum amount of bits necessary to represent a `BlsScalar`.
fn bits_count(mut scalar: BlsScalar) -> u64 {
    scalar = scalar.reduce();
    let mut counter = 1u64;
    while scalar > BlsScalar::one().reduce() {
        scalar.divn(1);
        counter += 1;
    }
    counter
}

// Returns the number of bits of the closest power of two
// to the scalar and the closest power of two
fn num_bits_closest_power_of_two(scalar: BlsScalar) -> u64 {
    let num_bits = bits_count(scalar);
    let closest_pow_of_two = BlsScalar::pow_of_2(num_bits);
    bits_count(closest_pow_of_two)
}
