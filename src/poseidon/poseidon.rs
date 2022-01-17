//! optimized poseidon

use crate::poseidon::constants::PoseidonConstants;
use crate::poseidon::matrix::Matrix;
use crate::poseidon::mds::SparseMatrix;
use crate::poseidon::PoseidonError;
use ark_ff::PrimeField;
use derivative::Derivative;
use std::fmt::Debug;
use std::marker::PhantomData;

// TODO: reduce duplicate code with `poseidon_ref`
pub trait PoseidonSpec<COM, const WIDTH: usize> {
    type Field: Debug + Clone;
    type ParameterField: PrimeField;

    fn full_round(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        current_round: &mut usize,
        const_offset: &mut usize,
        last_round: bool,
        state: &mut [Self::Field; WIDTH],
    ) {
        let to_take = WIDTH;
        let post_round_keys = constants
            .compressed_round_constants
            .iter()
            .skip(*const_offset)
            .take(to_take);

        if !last_round {
            let needed = *const_offset + to_take;
            assert!(
                needed <= constants.compressed_round_constants.len(),
                "Not enough preprocessed round constants ({}), need {}.",
                constants.compressed_round_constants.len(),
                needed
            );
        }

        state.iter_mut().zip(post_round_keys).for_each(|(l, post)| {
            // Be explicit that no round key is added after last round of S-boxes.
            let post_key = if last_round {
                panic!(
                    "Trying to skip last full round, but there is a key here! ({:?})",
                    post
                );
            } else {
                Some(post.clone())
            };
            Self::quintic_s_box(c, l.clone(), None, post_key);
        });

        if last_round {
            state
                .iter_mut()
                .for_each(|l| *l = Self::quintic_s_box(c, l.clone(), None, None))
        } else {
            *const_offset += to_take;
        }
        Self::round_product_mds(c, constants, current_round, state);
    }

    fn partial_round(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        current_round: &mut usize,
        const_offset: &mut usize,
        state: &mut [Self::Field; WIDTH],
    ) {
        let post_round_key = constants.compressed_round_constants[*const_offset];

        state[0] = Self::quintic_s_box(c, state[0].clone(), None, Some(post_round_key));
        *const_offset += 1;

        Self::round_product_mds(c, constants, current_round, state);
    }

    fn add_round_constants(
        c: &mut COM,
        state: &mut [Self::Field; WIDTH],
        constants: &PoseidonConstants<Self::ParameterField>,
        const_offset: &mut usize,
    ) {
        for (element, round_constant) in state.iter_mut().zip(
            constants
                .compressed_round_constants
                .iter()
                .skip(*const_offset),
        ) {
            *element = Self::addi(c, element, round_constant);
        }
        *const_offset += WIDTH;
    }

    fn round_product_mds(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        current_round: &mut usize,
        state: &mut [Self::Field; WIDTH],
    ) {
        let full_half = constants.half_full_rounds;
        let sparse_offset = full_half - 1;
        if *current_round == sparse_offset {
            Self::product_mds_with_matrix(c, state, &constants.pre_sparse_matrix)
        } else {
            if (*current_round > sparse_offset)
                && (*current_round < full_half + constants.partial_rounds)
            {
                let index = *current_round - sparse_offset - 1;
                let sparse_matrix = &constants.sparse_matrixes[index];

                Self::product_mds_with_sparse_matrix(c, state, sparse_matrix)
            } else {
                Self::product_mds(c, constants, state)
            }
        };

        *current_round += 1;
    }

    fn product_mds(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        state: &mut [Self::Field; WIDTH],
    ) {
        Self::product_mds_with_matrix(c, state, &constants.mds_matrices.m)
    }

    fn product_mds_with_matrix(
        c: &mut COM,
        state: &mut [Self::Field; WIDTH],
        matrix: &Matrix<Self::ParameterField>,
    ) {
        let mut result = Self::zeros::<WIDTH>(c);
        for (j, val) in result.iter_mut().enumerate() {
            for (i, row) in matrix.iter_rows().enumerate() {
                // *val += row[j] * state[i];
                let tmp = Self::muli(c, &state[i], &row[j]);
                *val = Self::add(c, val, &tmp);
            }
        }
        *state = result;
    }

    fn product_mds_with_sparse_matrix(
        c: &mut COM,
        state: &mut [Self::Field; WIDTH],
        matrix: &SparseMatrix<Self::ParameterField>,
    ) {
        let mut result = Self::zeros::<WIDTH>(c);

        // First column is dense.
        for (i, val) in matrix.w_hat.iter().enumerate() {
            // result[0] += w_hat[i] * state[i];
            let tmp = Self::muli(c, &state[i], &val);
            result[0] = Self::add(c, &result[0], &tmp);
        }

        for (j, val) in result.iter_mut().enumerate().skip(1) {
            // Except for first row/column, diagonals are one.
            *val = Self::add(c, val, &state[j]);

            // First row is dense.
            let tmp = Self::muli(c, &state[0], &matrix.v_rest[j - 1]);
            *val = Self::add(c, val, &tmp);
        }
        *state = result;
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
    where
        S: ?Sized,
{
    pub(crate) constants_offset: usize,
    pub(crate) current_round: usize,
    pub elements: [S::Field; WIDTH],
    pos: usize,
    pub(crate) constants: PoseidonConstants<S::ParameterField>,
}

impl<COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize> Poseidon<COM, S, WIDTH>
    where
        S: ?Sized,
{
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

    pub fn output_hash(&mut self, c: &mut COM) -> S::Field {
        S::add_round_constants(
            c,
            &mut self.elements,
            &self.constants,
            &mut self.constants_offset,
        );

        for _ in 0..self.constants.half_full_rounds {
            S::full_round(
                c,
                &self.constants,
                &mut self.current_round,
                &mut self.constants_offset,
                false,
                &mut self.elements,
            )
        }

        for _ in 0..self.constants.partial_rounds {
            S::partial_round(
                c,
                &self.constants,
                &mut self.current_round,
                &mut self.constants_offset,
                &mut self.elements,
            );
        }

        // All but last full round
        for _ in 1..self.constants.half_full_rounds {
            S::full_round(
                c,
                &self.constants,
                &mut self.current_round,
                &mut self.constants_offset,
                false,
                &mut self.elements,
            );
        }
        S::full_round(
            c,
            &self.constants,
            &mut self.current_round,
            &mut self.constants_offset,
            true,
            &mut self.elements,
        );

        assert_eq!(
            self.constants_offset,
            self.constants.compressed_round_constants.len(),
            "Constants consumed ({}) must equal preprocessed constants provided ({}).",
            self.constants_offset,
            self.constants.compressed_round_constants.len()
        );

        self.elements[1].clone()
    }
}

pub struct NativePoseidonSpec<F: PrimeField, const WIDTH: usize> {
    _field: PhantomData<F>,
}

impl<F: PrimeField, const WIDTH: usize> PoseidonSpec<(), WIDTH> for NativePoseidonSpec<F, WIDTH> {
    type Field = F;
    type ParameterField = F;

    fn alloc(_c: &mut (), v: Self::ParameterField) -> Self::Field {
        v
    }

    fn zeros<const W: usize>(_c: &mut ()) -> [Self::Field; W] {
        [F::zero(); W]
    }

    fn add(_c: &mut (), x: &Self::Field, y: &Self::Field) -> Self::Field {
        *x + *y
    }

    fn addi(_c: &mut (), a: &Self::Field, b: &Self::ParameterField) -> Self::Field {
        *a + *b
    }

    fn mul(_c: &mut (), x: &Self::Field, y: &Self::Field) -> Self::Field {
        *x * *y
    }

    fn muli(_c: &mut (), x: &Self::Field, y: &Self::ParameterField) -> Self::Field {
        *x * *y
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::PairingEngine;
    use ark_std::{test_rng, UniformRand};
    use crate::poseidon::constants::PoseidonConstants;
    use crate::poseidon::poseidon::{NativePoseidonSpec, Poseidon};
    use crate::poseidon::poseidon_ref::{NativeSpecRef, PoseidonRef};

    type E = ark_bls12_381::Bls12_381;
    type P = ark_ed_on_bls12_381::EdwardsParameters;
    type Fr = <E as PairingEngine>::Fr;


    #[test]
    fn compare_with_poseidon_ref(){
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = PoseidonConstants::generate::<WIDTH>();
        let mut poseidon = PoseidonRef::<(), NativeSpecRef<Fr>, WIDTH>::new(&mut (), param.clone());
        let inputs = (0..ARITY).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        inputs.iter().for_each(|x| {
            let _ = poseidon.input(*x).unwrap();
        });
        let hash_expected: Fr = poseidon.output_hash(&mut ());

        let mut poseidon_optimized = Poseidon::<(), NativePoseidonSpec<Fr, WIDTH>, WIDTH>::new(&mut (), param);
        inputs.iter().for_each(|x| {
            let _ = poseidon_optimized.input(*x).unwrap();
        });
        let hash_actual = poseidon_optimized.output_hash(&mut ());

        assert_eq!(hash_expected, hash_actual);
    }
}
