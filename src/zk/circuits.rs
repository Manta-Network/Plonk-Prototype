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

//! Circuits implementations

use crate::zk::gadgets::*;
use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::constraint_system::ecc::Point;
use dusk_plonk::constraint_system::StandardComposer;
use dusk_poseidon::*;

use dusk_plonk::prelude::*;
pub struct MockCircuit {
    note_value: Variable,
    private_key: Variable,
    hash_inputs: Vec<Variable>,

    public_key: JubJubAffine,
}

impl MockCircuit {
    /// Function to create new note
    pub fn new(
        note_value: Variable,
        private_key: Variable,
        hash_inputs: Vec<Variable>,
        public_key: JubJubAffine,
    ) -> MockCircuit {
        Self {
            note_value,
            private_key,
            hash_inputs,
            public_key,
        }
    }

    /// Assert the note value is sufficient to complete a transaction and it's gas cost
    pub fn valid_balance(
        &self,
        composer: &mut StandardComposer,
        tx_value: BlsScalar,
        gas_fee: BlsScalar,
    ) {
        let total_tx = tx_value + gas_fee;
        let alloc_value = self.note_value.into();
        let output = min_bound(composer, total_tx, alloc_value, 30u64);
    }

    /// Make a proof about public key ownership
    pub fn prove_ownership(&self, composer: &mut StandardComposer) {
        let circuit_pk = composer.fixed_base_scalar_mul(self.private_key, GENERATOR_EXTENDED);
        composer.assert_equal_public_point(circuit_pk, self.public_key);
    }

    /// Constrains a puclic hash to a private one, to prove ownership of fields within the circuit
    pub fn check_hash_inputs(&self, composer: &mut StandardComposer, public_hash: BlsScalar) {
        let hash = sponge::gadget(composer, &self.hash_inputs);
        composer.constrain_to_constant(hash, BlsScalar::zero(), Some(-public_hash));
    }
}
