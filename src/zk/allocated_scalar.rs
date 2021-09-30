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

//! Scalar Conversions
use dusk_plonk::{
    bls12_381::BlsScalar,
    constraint_system::{StandardComposer, Variable},
};

/// An allocated scalar holds the underlying witness assignment for the Prover
/// and a dummy value for the verifier
#[derive(Copy, Clone, Debug)]
pub struct AllocatedScalar {
    /// Variable associated to the `Scalar`.
    pub var: Variable,
    /// Scalar associated to the `Variable`
    pub scalar: BlsScalar,
}

impl AllocatedScalar {
    /// Allocates a BlsScalar into the constraint system as a witness
    pub fn allocate(composer: &mut StandardComposer, scalar: BlsScalar) -> AllocatedScalar {
        let var = composer.add_input(scalar);
        AllocatedScalar { var, scalar }
    }
}
