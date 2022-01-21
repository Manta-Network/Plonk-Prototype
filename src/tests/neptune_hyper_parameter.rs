// use neptune::poseidon::*;
use crate::poseidon::constants::PoseidonConstants;
use crate::poseidon::mds::{factor_to_sparse_matrixes, MdsMatrices, SparseMatrix};
use crate::tests::conversion::{cast_field, cast_matrix, cast_vector};
use ark_ec::PairingEngine;
use ark_ff::{Field as ArkField, PrimeField as ArkPrimeField};
use blstrs::Scalar as Fr;
use ff::PrimeField;
use generic_array::{sequence::GenericSequence, typenum, ArrayLength, GenericArray};
use neptune::poseidon::{
    Arity, HashMode, Poseidon as NeptunePoseidon, PoseidonConstants as NeptunePoseidonConstants,
};
use neptune::Strength;

type ArkFr = <ark_bls12_381::Bls12_381 as PairingEngine>::Fr;

#[cfg(test)]
pub(crate) fn collect_neptune_constants<A>(
    strength: Strength,
) -> (NeptunePoseidonConstants<Fr, A>, PoseidonConstants<ArkFr>)
where
    A: Arity<Fr>,
{
    let constants = NeptunePoseidonConstants::<Fr, A>::new_with_strength(strength);
    let constants_cloned = constants.clone();
    let mds_matrices = constants.mds_matrices.m;
    let round_constants = constants.round_constants;
    let compressed_round_constants = constants.compressed_round_constants;
    let pre_sparse_matrix = constants.pre_sparse_matrix;
    let sparse_matrixes = constants.sparse_matrixes;
    let domain_tag = constants.domain_tag;

    let arity = A::to_usize();
    let width = arity + 1;

    let ark_mds_matrices_m = cast_matrix(mds_matrices);
    let ark_mds_matrices = MdsMatrices::derive_mds_matrices(ark_mds_matrices_m);

    let ark_round_constants = cast_vector(round_constants);
    let ark_compressed_round_constants = cast_vector(compressed_round_constants);
    let ark_pre_sparse_matrix = cast_matrix(pre_sparse_matrix);

    let num_sparse_matrix = sparse_matrixes.len();
    let mut ark_sparse_matrixes = Vec::with_capacity(num_sparse_matrix);
    for mat in sparse_matrixes {
        let w_hat = mat.w_hat;
        let v_rest = mat.v_rest;

        let ark_w_hat = cast_vector(w_hat);
        let ark_v_rest = cast_vector(v_rest);

        let single_sparse_matrix = SparseMatrix {
            w_hat: ark_w_hat,
            v_rest: ark_v_rest,
        };
        ark_sparse_matrixes.push(single_sparse_matrix);
    }

    let ark_domain_tag = cast_field(domain_tag);

    let ark_const = PoseidonConstants {
        mds_matrices: ark_mds_matrices,
        round_constants: ark_round_constants,
        domain_tag: ark_domain_tag,
        full_rounds: constants.full_rounds,
        half_full_rounds: constants.half_full_rounds,
        partial_rounds: constants.partial_rounds,
        compressed_round_constants: ark_compressed_round_constants,
        pre_sparse_matrix: ark_pre_sparse_matrix,
        sparse_matrixes: ark_sparse_matrixes,
    };
    (constants_cloned, ark_const)
}

#[test]
fn convert_neptune_constants_test() {
    collect_neptune_constants::<typenum::U2>(Strength::Standard);
    collect_neptune_constants::<typenum::U4>(Strength::Standard);
    collect_neptune_constants::<typenum::U8>(Strength::Standard);
    collect_neptune_constants::<typenum::U11>(Strength::Standard);
    collect_neptune_constants::<typenum::U16>(Strength::Standard);
    collect_neptune_constants::<typenum::U24>(Strength::Standard);
    collect_neptune_constants::<typenum::U36>(Strength::Standard);

    collect_neptune_constants::<typenum::U2>(Strength::Strengthened);
    collect_neptune_constants::<typenum::U4>(Strength::Strengthened);
    collect_neptune_constants::<typenum::U8>(Strength::Strengthened);
    collect_neptune_constants::<typenum::U11>(Strength::Strengthened);
    collect_neptune_constants::<typenum::U16>(Strength::Strengthened);
    collect_neptune_constants::<typenum::U24>(Strength::Strengthened);
    collect_neptune_constants::<typenum::U36>(Strength::Strengthened);
}
