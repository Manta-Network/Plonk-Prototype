//! Correct, Naive, reference implementation of Poseidon hash function.

use ark_ff::PrimeField;
use crate::poseidon::mds::MdsMatrices;
use crate::poseidon::PoseidonError;

#[derive(Clone, Debug, PartialEq)]
pub struct PoseidonConstants<F: PrimeField> {
    pub mds_matrices: MdsMatrices<F>,
    pub round_constants: Vec<F>,
    pub domain_tag: F,
    pub full_rounds: usize,
    pub half_full_rounds: usize,
    pub partial_rounds: usize,
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

    /// input one field element to Poseidon. Return the position of the element in state.
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
}

