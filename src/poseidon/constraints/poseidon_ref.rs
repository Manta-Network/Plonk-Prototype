use std::marker::PhantomData;
use ark_ec::{PairingEngine, TEModelParameters};
use ark_plonk::prelude::*;
use crate::poseidon::matrix::Matrix;
use crate::poseidon::poseidon_ref::PoseidonConstants;

// pub struct MDSMatricesVar<E: PairingEngine, P: TEModelParameters<BaseField=E::Fr>>{
//     pub m: Vec<Vec<Variable>>
// }

#[derive(Clone, Debug, PartialEq)]
pub struct PoseidonConstantsVar<E: PairingEngine, P: TEModelParameters<BaseField=E::Fr>> {
    pub mds: Matrix<Variable>,
    pub round_constants: Vec<Variable>,
    pub domain_tag: Variable,
    pub full_rounds: usize,
    pub half_full_rounds: usize,
    pub partial_rounds: usize,
    _parameter: PhantomData<(E, P)>,
}

impl<E: PairingEngine, P: TEModelParameters<BaseField=E::Fr>> PoseidonConstantsVar<E, P> {
    pub fn from_native(cs: &mut StandardComposer<E, P>, native: &PoseidonConstants<E::Fr>) -> Self {
        let mds = Matrix::from_native(cs, &native.mds_matrices.m);
        todo!()
    }
}
