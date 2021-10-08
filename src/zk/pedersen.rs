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


use crate::zk::gadgets::*;
use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_poseidon::*;
use dusk_plonk::prelude::*;

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

pub fn pedersen_hash(composer: &mut StandardComposer, encoded_values: &[Variable]) -> (Point, Point) {

    for i in 0..50 {
        let base = composer.add_witness_to_circuit_description((BlsScalar::from(32));
        let two_five_j = composer.big_mul(BlsScalar::::from(2), , b, q_4_d, q_c, pi); 
        let mut point_1 = composer.big_add_gate(a, b, c, d, q_l, q_r, q_o, q_4, q_c, pi);
    }
    
}



mod tests {
    use std::println;

    use dusk_plonk::prelude::*; 

    use dusk_bls12_381::BlsScalar;
    use dusk_jubjub::{JubJubAffine, GENERATOR, GENERATOR_NUMS};
    use crate::zk::pedersen::encode;

    #[test]
    fn predict_circuit_size() {
        let composer = &mut StandardComposer::new();

        let variable = composer.add_witness_to_circuit_description(BlsScalar::from(7)); 

        for _ in 0..64 {
            let encoding = encode(composer, [variable; 4]);
        }

        // Make these points private inputs in the circuit
        // two points P and P', where P != P'
        let point_a = composer.add_affine_to_circuit_description(GENERATOR);
        let point_b = composer.add_affine_to_circuit_description(GENERATOR_NUMS);


        // Perform Scalar mul operations
        //let point_1 = composer.variable_base_scalar_mul(encoding, point_a);
        //let point_2 = composer.variable_base_scalar_mul(encoding, point_b);

        // Add points together inside the circuit
        for _ in 0..51 {
            composer.point_addition_gate(point_1, point_2);
        }

        println!("final circuit size is {:?}", composer.circuit_size());


    }

    // #[test]
    // fn compute_size() {
    //     let composer = &mut StandardComposer::new();
    //     let five =
    // composer.add_witness_to_circuit_description(BlsScalar::from(5));
    //     composer.big_mul((BlsScalar::one(), five), (BlsScalar::one(), five),
    // Some((BlsScalar::one(), five)), BlsScalar::zero(), None);
    //     println!(" small is {:?}", composer.circuit_size());
    // }

    // #[test]
    // fn compute_size_big() {
    //     let composer = &mut StandardComposer::new();
    //     let five =
    //         composer.add_witness_to_circuit_description(BlsScalar::from(5));
    //     let output = composer.big_mul(
    //         BlsScalar::one(),
    //         five,
    //         five,
    //         Some((BlsScalar::from(30), five)),
    //         BlsScalar::zero(),
    //         None,
    //     );
    //     println!(" big is {:?}", composer.circuit_size());
    //     println!(" value is {:?}", answer.reduce());
    // }

}