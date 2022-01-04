mod poseidon_ref;

use crate::poseidon::matrix::Matrix;
use ark_ec::{PairingEngine, TEModelParameters};
use ark_plonk::prelude::*;

impl Matrix<Variable> {
    pub fn from_native<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>(
        cs: &mut StandardComposer<E, P>,
        matrix: &Matrix<E::Fr>,
    ) -> Self {
        matrix
            .iter_rows()
            .map(|row| row.iter().map(|x| cs.add_input(*x)).collect::<Vec<_>>())
            .collect::<Matrix<_>>()
    }
}
