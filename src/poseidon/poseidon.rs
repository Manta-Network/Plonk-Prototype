//! optimized poseidon

use std::fmt::Debug;
use ark_ff::PrimeField;
use crate::poseidon::matrix::Matrix;
use crate::poseidon::mds::SparseMatrix;
use crate::poseidon::poseidon_ref::PoseidonConstants;
use derivative::Derivative;
use crate::poseidon::PoseidonError;

// TODO: reduce duplicate code with `poseidon_ref`
pub trait PoseidonSpec<COM, const WIDTH: usize> {
    type Field: Debug + Clone;
    type ParameterField: PrimeField;

    fn full_round(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        const_offset: &mut usize,
        last_round: bool,
        state: &mut [Self::Field; WIDTH]
    ) {
        todo!();
    }

    fn partial_round(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        const_offset: &mut usize,
        state: &mut [Self::Field; WIDTH]
    ) {
        todo!();
    }

    fn add_round_constants(
        c: &mut COM,
        state: &mut [Self::Field; WIDTH],
        constants: &PoseidonConstants<Self::ParameterField>,
    const_offset: &mut usize
    ) {
        todo!();
    }

    fn round_product_mds(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        state: &mut [Self::Field; WIDTH]
    ) {
        todo!();
    }

    fn product_mds(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        state: &mut [Self::Field; WIDTH]
    ) {
        todo!();
    }

    fn product_mds_with_matrix(c: &mut COM, state: &mut [Self::Field; WIDTH], matrix: &Matrix<Self::ParameterField>) {
        todo!();
    }

    fn product_mds_with_sparse_matrix(c: &mut COM, state: &mut [Self::Field; WIDTH], matrix: &SparseMatrix<Self::ParameterField>) {
        todo!()
    }

    /// return (x + pre_add)^5 + post_add
    fn quintic_s_box(
        c: &mut COM,
        x: Self::Field,
        pre_add: Option<Self::ParameterField>,
        post_add: Option<Self::ParameterField>,
    ) -> Self::Field {
        let tmp = match pre_add {
            Some(a) => Self::addi(c, &x, &a),
            None => x.clone(),
        };
        Self::power_of_5(c, &tmp);
        match post_add {
            Some(a) => Self::addi(c, &tmp, &a),
            None => tmp,
        }
    }

    fn power_of_5(c: &mut COM, x: &Self::Field) -> Self::Field {
        let mut tmp = Self::mul(c, x, x); // x^2
        tmp = Self::mul(c, &tmp, &tmp); // x^4
        Self::mul(c, &tmp, x) // x^5
    }

    fn alloc(c: &mut COM, v: Self::ParameterField) -> Self::Field;
    fn zeros<const W: usize>(c: &mut COM) -> [Self::Field; W];
    fn zero(c: &mut COM) -> Self::Field {
        Self::zeros::<1>(c)[0].clone()
    }
    fn add(c: &mut COM, x: &Self::Field, y: &Self::Field) -> Self::Field;
    fn addi(c: &mut COM, a: &Self::Field, b: &Self::ParameterField) -> Self::Field;
    fn mul(c: &mut COM, x: &Self::Field, y: &Self::Field) -> Self::Field;
    fn muli(c: &mut COM, x: &Self::Field, y: &Self::ParameterField) -> Self::Field;
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct Poseidon<COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize>
where S: ?Sized {
    pub(crate) constants_offset: usize,
    pub(crate) current_round: usize,
    pub elements: [S::Field; WIDTH],
    pos: usize,
    pub(crate) constants: PoseidonConstants<S::ParameterField>
}

impl<COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize> Poseidon<COM, S, WIDTH> where S: ?Sized {
    pub fn new(c: &mut COM, constants: PoseidonConstants<S::ParameterField>) -> Self {
        let mut elements = S::zeros(c);
        elements[0] = S::alloc(c, constants.domain_tag);
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

    pub fn reset(&mut self, c: &mut COM) {
        self.constants_offset = 0;
        self.current_round = 0;
        self.elements[1..].iter_mut().for_each(|l| *l = S::zero(c));
        self.elements[0] = S::alloc(c, self.constants.domain_tag);
        self.pos = 1;
    }

    /// input one field element to Poseidon. Return the position of the element
    /// in state.
    pub fn input(&mut self, input: S::Field) -> Result<usize, PoseidonError> {
        // Cannot input more elements than the defined constant width
        if self.pos >= WIDTH {
            return Err(PoseidonError::FullBuffer);
        }

        // Set current element, and increase the pointer
        self.elements[self.pos] = input;
        self.pos += 1;

        Ok(self.pos - 1)
    }

    pub fn hash(&mut self, c: &mut COM) -> S::Field {
        S::add_round_constants(c, &mut self.elements, &self.constants, &mut self.constants_offset);

        for _ in 0..self.constants.half_full_rounds {
            S::full_round(
                c,
                &self.constants,
                &mut self.constants_offset,
                false,
                &mut self.elements,
            )
        }

        for _ in 0..self.constants.partial_rounds {
            S::partial_round(
                c,
                &self.constants,
                &mut self.constants_offset,
                &mut self.elements,
            );
        }

        // All but last full round
        for _ in 1..self.constants.half_full_rounds {
            S::full_round(
                c,
                &self.constants,
                &mut self.constants_offset,
                false,
                &mut self.elements,
            );
        }
        S::full_round(
            c,
            &self.constants,
            &mut self.constants_offset,
            true,
            &mut self.elements,
        );

        todo!("assert self.constants_offset == self.constants.compressed_round_constants.len()");

        self.elements[1].clone()
    }


}