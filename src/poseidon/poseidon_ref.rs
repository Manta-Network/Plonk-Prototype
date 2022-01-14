//! Correct, Naive, reference implementation of Poseidon hash function.

use crate::poseidon::{
    mds::MdsMatrices, round_constant::generate_constants, round_numbers::calc_round_numbers,
    PoseidonError,
};

use ark_ec::{PairingEngine, TEModelParameters};
use ark_ff::PrimeField;
use derivative::Derivative;
use num_traits::{One, Zero};
use plonk_core::constraint_system::StandardComposer;
use plonk_core::prelude as plonk;
use std::convert::TryInto;
use std::fmt::Debug;
use std::marker::PhantomData;

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

pub trait PoseidonSpec<COM, const WIDTH: usize> {
    /// Field used as state
    type Field: Debug + Clone;
    /// Field used as constant paramater
    type ParameterField: PrimeField; // TODO: for now, only prime field is supported. Can be used for arkplonk and arkworks which uses the same PrimeField. For other field, we are not supporting yet.

    fn full_round(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        constants_offset: &mut usize,
        state: &mut [Self::Field; WIDTH],
    ) {
        let pre_round_keys = constants
            .round_constants
            .iter()
            .skip(*constants_offset)
            .map(Some);

        state.iter_mut().zip(pre_round_keys).for_each(|(l, pre)| {
            *l = Self::quintic_s_box(c, l.clone(), pre.map(|x| *x), None);
        });

        *constants_offset += WIDTH;

        Self::product_mds(c, constants, state);
    }

    fn partial_round(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        constants_offset: &mut usize,
        state: &mut [Self::Field; WIDTH],
    ) {
        // TODO: we can combine add_round_constants and s_box using fewer constraints
        Self::add_round_constants(c, state, constants, constants_offset);

        // apply quintic s-box to the first element
        state[0] = Self::quintic_s_box(c, state[0].clone(), None, None);

        // Multiply by MDS
        Self::product_mds(c, constants, state);
    }

    fn add_round_constants(
        c: &mut COM,
        state: &mut [Self::Field; WIDTH],
        constants: &PoseidonConstants<Self::ParameterField>,
        constants_offset: &mut usize,
    ) {
        for (element, round_constant) in state
            .iter_mut()
            .zip(constants.round_constants.iter())
            .skip(*constants_offset)
        {
            // element.com_addi(c, round_constant);
            *element = Self::addi(c, element, round_constant)
        }

        *constants_offset += WIDTH;
    }

    fn product_mds(
        c: &mut COM,
        constants: &PoseidonConstants<Self::ParameterField>,
        state: &mut [Self::Field; WIDTH],
    ) {
        let matrix = &constants.mds_matrices.m;
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

impl<COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize> Poseidon<COM, S, WIDTH> {
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

    /// Output the hash
    pub fn output_hash(&mut self, c: &mut COM) -> S::Field {
        for _ in 0..self.constants.half_full_rounds {
            S::full_round(
                c,
                &self.constants,
                &mut self.constants_offset,
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

        for _ in 0..self.constants.half_full_rounds {
            S::full_round(
                c,
                &self.constants,
                &mut self.constants_offset,
                &mut self.elements,
            )
        }

        self.elements[1].clone()
    }
}

pub struct NativeSpec<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField, const WIDTH: usize> PoseidonSpec<(), WIDTH> for NativeSpec<F> {
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

pub struct PlonkSpec;

impl<E, P, const WIDTH: usize> PoseidonSpec<plonk::StandardComposer<E, P>, WIDTH> for PlonkSpec
where
    E: PairingEngine,
    P: TEModelParameters<BaseField = E::Fr>,
{
    type Field = plonk::Variable;
    type ParameterField = E::Fr;

    fn alloc(c: &mut StandardComposer<E, P>, v: Self::ParameterField) -> Self::Field {
        c.add_input(v)
    }

    fn zeros<const W: usize>(c: &mut StandardComposer<E, P>) -> [Self::Field; W] {
        [c.zero_var(); W]
    }

    fn add(c: &mut StandardComposer<E, P>, x: &Self::Field, y: &Self::Field) -> Self::Field {
        c.arithmetic_gate(|g| g.witness(*x, *y, None).add(E::Fr::one(), E::Fr::one()))
    }

    fn addi(
        c: &mut StandardComposer<E, P>,
        a: &Self::Field,
        b: &Self::ParameterField,
    ) -> Self::Field {
        let zero = c.zero_var();
        c.arithmetic_gate(|g| {
            g.witness(*a, zero, None)
                .add(E::Fr::one(), E::Fr::zero())
                .constant(*b)
        })
    }

    fn mul(c: &mut StandardComposer<E, P>, x: &Self::Field, y: &Self::Field) -> Self::Field {
        c.arithmetic_gate(|q| q.witness(*x, *y, None).mul(E::Fr::one()))
    }

    fn muli(
        c: &mut StandardComposer<E, P>,
        x: &Self::Field,
        y: &Self::ParameterField,
    ) -> Self::Field {
        let zero = c.zero_var();
        c.arithmetic_gate(|g| g.witness(*x, zero, None).add(*y, E::Fr::zero()))
    }
}

mod r1cs {
    use crate::poseidon::poseidon_ref::PoseidonSpec;
    use ark_ff::PrimeField;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use std::convert::TryInto;

    pub struct R1csSpec<F: PrimeField, const WIDTH: usize> {
        _field: F,
    }

    impl<F: PrimeField, const WIDTH: usize> PoseidonSpec<ConstraintSystemRef<F>, WIDTH>
        for R1csSpec<F, WIDTH>
    {
        type Field = FpVar<F>;
        type ParameterField = F;

        fn alloc(c: &mut ConstraintSystemRef<F>, v: Self::ParameterField) -> Self::Field {
            FpVar::new_witness(c.clone(), || Ok(v)).unwrap()
        }

        fn zeros<const W: usize>(_c: &mut ConstraintSystemRef<F>) -> [Self::Field; W] {
            vec![FpVar::zero(); W].try_into().unwrap()
        }

        fn add(_c: &mut ConstraintSystemRef<F>, x: &Self::Field, y: &Self::Field) -> Self::Field {
            x + y
        }

        fn addi(
            _c: &mut ConstraintSystemRef<F>,
            a: &Self::Field,
            b: &Self::ParameterField,
        ) -> Self::Field {
            a + FpVar::Constant(*b)
        }

        fn mul(_c: &mut ConstraintSystemRef<F>, x: &Self::Field, y: &Self::Field) -> Self::Field {
            x * y
        }

        fn muli(
            c: &mut ConstraintSystemRef<F>,
            x: &Self::Field,
            y: &Self::ParameterField,
        ) -> Self::Field {
            x * FpVar::Constant(*y)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    type E = ark_bls12_381::Bls12_381;
    type P = ark_ed_on_bls12_381::EdwardsParameters;
    type Fr = <E as PairingEngine>::Fr;
    use crate::poseidon::poseidon_ref::r1cs::R1csSpec;
    use ark_std::{test_rng, UniformRand};

    #[test]
    // poseidon should output something if num_inputs = arity
    fn sanity_test() {
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = PoseidonConstants::generate::<WIDTH>();
        let mut poseidon = Poseidon::<(), NativeSpec<Fr>, WIDTH>::new(&mut (), param.clone());
        let inputs = (0..ARITY).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        inputs.iter().for_each(|x| {
            let _ = poseidon.input(*x).unwrap();
        });
        let native_hash: Fr = poseidon.output_hash(&mut ());

        let mut c = StandardComposer::<E, P>::new();
        let inputs_var = inputs.iter().map(|x| c.add_input(*x)).collect::<Vec<_>>();
        let mut poseidon_circuit = Poseidon::<_, PlonkSpec, WIDTH>::new(&mut c, param);
        inputs_var.iter().for_each(|x| {
            let _ = poseidon_circuit.input(*x).unwrap();
        });
        let plonk_hash = poseidon_circuit.output_hash(&mut c);

        c.check_circuit_satisfied();

        let expected = c.add_input(native_hash);
        c.assert_equal(expected, plonk_hash);

        c.check_circuit_satisfied();
        println!(
            "circuit size for WIDTH {} poseidon: {}",
            WIDTH,
            c.circuit_size()
        )
    }

    #[test]
    // poseidon should output something if num_inputs = arity
    fn sanity_test_r1cs() {
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = PoseidonConstants::generate::<WIDTH>();
        let mut poseidon = Poseidon::<(), NativeSpec<Fr>, WIDTH>::new(&mut (), param.clone());
        let inputs = (0..ARITY).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        inputs.iter().for_each(|x| {
            let _ = poseidon.input(*x).unwrap();
        });
        let native_hash: Fr = poseidon.output_hash(&mut ());

        let mut cs = ConstraintSystem::new_ref();
        let mut poseidon_var =
            Poseidon::<_, R1csSpec<Fr, WIDTH>, WIDTH>::new(&mut cs, param.clone());
        let inputs_var = inputs
            .iter()
            .map(|x| R1csSpec::<_, WIDTH>::alloc(&mut cs, *x))
            .collect::<Vec<_>>();
        inputs_var.iter().for_each(|x| {
            let _ = poseidon_var.input(x.clone()).unwrap();
        });

        let hash_var = poseidon_var.output_hash(&mut cs);

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(hash_var.value().unwrap(), native_hash);
        println!(
            "circuit size for WIDTH {} r1cs: {}",
            WIDTH,
            cs.num_constraints()
        )
    }

    #[test]
    #[should_panic]
    // poseidon should output something if num_inputs > arity
    fn sanity_test_failure() {
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = PoseidonConstants::generate::<WIDTH>();
        let mut poseidon = Poseidon::<(), NativeSpec<Fr>, WIDTH>::new(&mut (), param);
        (0..(ARITY + 1)).for_each(|_| {
            let _ = poseidon.input(Fr::rand(&mut rng)).unwrap();
        });
        let _ = poseidon.output_hash(&mut ());
    }
}
