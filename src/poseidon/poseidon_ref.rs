//! Correct, Naive, reference implementation of Poseidon hash function.

use crate::poseidon::field::{COMArith, COMArithExt, NativeField};
use crate::poseidon::{
    mds::MdsMatrices, round_constant::generate_constants, round_numbers::calc_round_numbers,
    PoseidonError,
};
use ark_ff::PrimeField;
use std::convert::TryInto;
use std::marker::PhantomData;
use ark_ec::{PairingEngine, TEModelParameters};
use ark_plonk::prelude::{StandardComposer, Variable};

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

pub trait PoseidonSpec<COM = ()> {
    type Field: COMArithExt<COM>;
    /// return (x + pre_add)^5 + post_add
    // todo: for PLONK, we can have some specialization for s_box
    fn quintic_s_box(
        c: &mut COM,
        x: Self::Field,
        pre_add: Option<NativeField<Self::Field, COM>>,
        post_add: Option<NativeField<Self::Field, COM>>,
    ) -> Self::Field {
        let mut tmp = match pre_add {
            Some(a) => x.com_add_const(c, &a),
            None => x.clone(),
        };
        tmp = tmp.com_square(c);
        tmp = tmp.com_square(c);
        tmp.com_mul_assign(c, &x);
        match post_add {
            Some(a) => tmp.com_add_const(c, &a),
            None => tmp,
        }
    }
}

pub struct PoseidonRefNativeSpec<F: PrimeField> {
    pub _field: PhantomData<F>,
}

pub struct PoseidonRefPlonkSpec{}

impl<F: PrimeField> PoseidonSpec for PoseidonRefNativeSpec<F> {
    type Field = F;
}

impl<E, P> PoseidonSpec<StandardComposer<E, P>> for PoseidonRefPlonkSpec
    where
        E: PairingEngine,
        P: TEModelParameters<BaseField = E::Fr>,
{
    type Field = Variable;

    fn quintic_s_box(c: &mut StandardComposer<E, P>, x: Self::Field, pre_add: Option<NativeField<Self::Field, StandardComposer<E, P>>>, post_add: Option<NativeField<Self::Field, StandardComposer<E, P>>>) -> Self::Field {
        // TODO: optimize this for plonk
        let mut tmp = match pre_add {
            Some(a) => x.com_add_const(c, &a),
            None => x.clone(),
        };
        tmp = tmp.com_square(c);
        tmp = tmp.com_square(c);
        match post_add {
            Some(a) => Variable::com_arith(c).w_l(tmp).w_r(x).q_c(a).build(c),
            None => Variable::com_arith(c).w_l(tmp).w_r(x).build(c)
        }

    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Poseidon<COM, S: PoseidonSpec<COM>, const WIDTH: usize>
where
    NativeField<S::Field, COM>: PrimeField, // TODO: for now, we only support arkwork's native field. After refactoring PoseidonConstants, we can support other field libraries!
{
    pub(crate) constants_offset: usize,
    pub(crate) current_round: usize,
    pub elements: [S::Field; WIDTH],
    pos: usize,
    pub(crate) constants: PoseidonConstants<NativeField<S::Field, COM>>,
}

impl<COM, S: PoseidonSpec<COM>, const WIDTH: usize> Poseidon<COM, S, WIDTH>
where
    NativeField<S::Field, COM>: PrimeField,
{
    pub fn new(c: &mut COM, constants: PoseidonConstants<NativeField<S::Field, COM>>) -> Self {
        let mut elements =  S::Field::zeros(c);
        elements[0] = S::Field::com_alloc(c, constants.domain_tag);
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
        self.elements[1..]
            .iter_mut()
            .for_each(|l| *l = S::Field::com_zero(c));
        self.elements[0] = S::Field::com_alloc(c, self.constants.domain_tag);
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

    /// Output the hash
    pub fn output_hash(&mut self, c: &mut COM) -> S::Field {
        for _ in 0..self.constants.half_full_rounds {
            self.full_round(c);
        }

        for _ in 0..self.constants.partial_rounds {
            self.partial_round(c);
        }

        for _ in 0..self.constants.half_full_rounds {
            self.full_round(c);
        }

        self.elements[1].clone()
    }

    fn full_round(&mut self, c: &mut COM) {
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
                *l = S::quintic_s_box(c, l.clone(), pre.map(|x| *x), None);
            });

        self.constants_offset += self.elements.len();

        self.product_mds(c);
    }

    fn partial_round(&mut self, c: &mut COM) {
        self.add_round_constants(c);

        // apply quintic s-box to the first element
        self.elements[0] = S::quintic_s_box(c, self.elements[0].clone(), None, None);

        // Multiply by MDS
        self.product_mds(c);
    }

    fn add_round_constants(&mut self, c: &mut COM) {
        for (element, round_constant) in self
            .elements
            .iter_mut()
            .zip(self.constants.round_constants.iter())
            .skip(self.constants_offset)
        {
            element.com_add_const(c, round_constant);
        }

        self.constants_offset += self.elements.len();
    }

    /// Multiply current state by MDS matrix
    fn product_mds(&mut self, c: &mut COM) {
        let matrix = &self.constants.mds_matrices.m;
        let mut result = S::Field::zeros::<WIDTH>(c);

        for (j, val) in result.iter_mut().enumerate() {
            for (i, row) in matrix.iter_rows().enumerate() {
                // TODO: shall we move this to spec
                // *val += row[j] * self.elements[i]
                let updated_val = S::Field::com_arith(c)
                    .w_l(self.elements[i].clone())
                    .q_l(row[j]) // row[j] * self.elements[i]
                    .w_r(val.clone())
                    .q_r(S::Field::com_one_native())// *val
                    .build(c);
                *val = updated_val;
            }
        }

        self.elements = result;
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
        let mut poseidon = Poseidon::<(), PoseidonRefNativeSpec<Fr>, WIDTH>::new(&mut (), param);
        (0..ARITY).for_each(|_| {
            let _ = poseidon.input(Fr::rand(&mut rng)).unwrap();
        });
        let _ = poseidon.output_hash(&mut ());
    }

    #[test]
    #[should_panic]
    // poseidon should output something if num_inputs > arity
    fn sanity_test_failure() {
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = PoseidonConstants::generate::<WIDTH>();
        let mut poseidon = Poseidon::<(), PoseidonRefNativeSpec<Fr>, WIDTH>::new(&mut (), param);
        (0..(ARITY + 1)).for_each(|_| {
            let _ = poseidon.input(Fr::rand(&mut rng)).unwrap();
        });
        let _ = poseidon.output_hash(&mut ());
    }
}
