//! Correct, Naive, reference implementation of Poseidon hash function.

use crate::poseidon::{
    mds::MdsMatrices, round_constant::generate_constants, round_numbers::calc_round_numbers,
    PoseidonError,
};
use ark_ff::PrimeField;
use std::convert::TryInto;

#[derive(Clone, Debug, PartialEq)]
pub struct PoseidonConstants<F: PrimeField> {
    pub mds_matrices: MdsMatrices<F>,
    pub round_constants: Vec<F>,
    pub domain_tag: F,
    pub full_rounds: usize,
    pub half_full_rounds: usize,
    pub partial_rounds: usize,
}

impl<F: PrimeField> PoseidonConstants<F> {
    // WIDTH = arity + 1. WIDTH is the *t* in Neptune's spec
    pub fn generate<const WIDTH: usize>() -> Self {
        let arity = WIDTH - 1;
        let mds_matrices = MdsMatrices::new(WIDTH);
        let (num_full_rounds, num_partial_rounds) = calc_round_numbers(WIDTH, true);
        debug_assert_eq!(num_full_rounds % 2, 0);
        let num_half_full_rounds = num_full_rounds / 2;
        let round_constants = generate_constants(
            1, // prime field
            1, // sbox
            F::size_in_bits() as u16,
            WIDTH.try_into().expect("WIDTH is too large"),
            num_full_rounds
                .try_into()
                .expect("num_full_rounds is too large"),
            num_partial_rounds
                .try_into()
                .expect("num_partial_rounds is too large"),
        );
        let domain_tag = F::from(((1 << arity) - 1) as u64);
        PoseidonConstants {
            mds_matrices,
            round_constants,
            domain_tag,
            full_rounds: num_full_rounds,
            half_full_rounds: num_half_full_rounds,
            partial_rounds: num_partial_rounds,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Poseidon<F: PrimeField, const WIDTH: usize> {
    pub(crate) constants_offset: usize,
    pub(crate) current_round: usize,
    pub elements: [F; WIDTH],
    pos: usize,
    pub(crate) constants: PoseidonConstants<F>,
}

impl<F: PrimeField, const WIDTH: usize> Poseidon<F, WIDTH> {
    pub fn new(constants: PoseidonConstants<F>) -> Self {
        let mut elements = [F::zero(); WIDTH];
        elements[0] = constants.domain_tag;
        Poseidon {
            constants_offset: 0,
            current_round: 0,
            elements,
            pos: 1,
            constants,
        }
    }

    pub fn arity(&self) -> usize {
        WIDTH - 1
    }

    pub fn reset(&mut self) {
        self.constants_offset = 0;
        self.current_round = 0;
        self.elements[1..]
            .iter_mut()
            .for_each(|l| *l = F::from(0u64));
        self.elements[0] = self.constants.domain_tag;
        self.pos = 1;
    }

    /// input one field element to Poseidon. Return the position of the element
    /// in state.
    pub fn input(&mut self, input: F) -> Result<usize, PoseidonError> {
        // Cannot input more elements than the defined constant width
        if self.pos >= WIDTH {
            return Err(PoseidonError::FullBuffer);
        }

        // Set current element, and increase the pointer
        self.elements[self.pos] = input;
        self.pos += 1;

        Ok(self.pos - 1)
    }

    /// Output the hash
    pub fn output_hash(&mut self) -> F {
        for _ in 0..self.constants.half_full_rounds {
            self.full_round();
        }

        for _ in 0..self.constants.partial_rounds {
            self.partial_round();
        }

        for _ in 0..self.constants.half_full_rounds {
            self.full_round();
        }

        self.elements[1]
    }

    fn full_round(&mut self) {
        let pre_round_keys = self
            .constants
            .round_constants
            .iter()
            .skip(self.constants_offset)
            .map(Some);

        self.elements
            .iter_mut()
            .zip(pre_round_keys)
            .for_each(|(l, pre)| {
                *l = quintic_s_box(*l, pre.map(|x| *x), None);
            });

        self.constants_offset += self.elements.len();

        self.product_mds();
    }

    fn partial_round(&mut self) {
        self.add_round_constants();

        // apply quintic s-box to the first element
        self.elements[0] = quintic_s_box(self.elements[0], None, None);

        // Multiply by MDS
        self.product_mds();
    }

    fn add_round_constants(&mut self) {
        for (element, round_constant) in self
            .elements
            .iter_mut()
            .zip(self.constants.round_constants.iter())
            .skip(self.constants_offset)
        {
            *element += round_constant;
        }

        self.constants_offset += self.elements.len();
    }

    /// Multiply current state by MDS matrix
    fn product_mds(&mut self) {
        let matrix = &self.constants.mds_matrices.m;
        let mut result = [F::zero(); WIDTH];

        for (j, val) in result.iter_mut().enumerate() {
            for (i, row) in matrix.iter_rows().enumerate() {
                *val += row[j] * self.elements[i];
            }
        }

        self.elements = result;
    }
}

/// return (x + pre_add)^5 + post_add
fn quintic_s_box<F: PrimeField>(x: F, pre_add: Option<F>, post_add: Option<F>) -> F {
    let mut c: F = match pre_add {
        Some(a) => x + a,
        None => x,
    };
    c = c.square();
    c = c.square();
    c *= x;
    match post_add {
        Some(a) => c + a,
        None => c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::{test_rng, UniformRand};

    #[test]
    // poseidon should output something if num_inputs = arity
    fn sanity_test() {
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = PoseidonConstants::generate::<WIDTH>();
        let mut poseidon = Poseidon::<Fr, WIDTH>::new(param);
        (0..ARITY).for_each(|_| {
            let _ = poseidon.input(Fr::rand(&mut rng)).unwrap();
        });
        let _ = poseidon.output_hash();
    }

    #[test]
    #[should_panic]
    // poseidon should output something if num_inputs > arity
    fn sanity_test_failure() {
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = PoseidonConstants::generate::<WIDTH>();
        let mut poseidon = Poseidon::<Fr, WIDTH>::new(param);
        (0..(ARITY + 1)).for_each(|_| {
            let _ = poseidon.input(Fr::rand(&mut rng)).unwrap();
        });
        let _ = poseidon.output_hash();
    }
}
