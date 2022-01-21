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
use HashMode::{Correct, OptimizedDynamic, OptimizedStatic};

type ArkFr = <ark_bls12_381::Bls12_381 as PairingEngine>::Fr;

// // TODO: Import from neptune code src/lib.rs
// #[cfg(test)]
// pub(crate) fn scalar_from_u64s(parts: [u64; 4]) -> Fr {
//     let mut le_bytes = [0u8; 32];
//     le_bytes[0..8].copy_from_slice(&parts[0].to_le_bytes());
//     le_bytes[8..16].copy_from_slice(&parts[1].to_le_bytes());
//     le_bytes[16..24].copy_from_slice(&parts[2].to_le_bytes());
//     le_bytes[24..32].copy_from_slice(&parts[3].to_le_bytes());
//     let mut repr = <Fr as PrimeField>::Repr::default();
//     repr.as_mut().copy_from_slice(&le_bytes[..]);
//     Fr::from_repr_vartime(repr).expect("u64s exceed BLS12-381 scalar field modulus")
// }

// pub struct PoseidonConstants<F: PrimeField> {
//     pub mds_matrices: MdsMatrices<F>,
//     pub round_constants: Vec<F>,
//     pub compressed_round_constants: Vec<F>,
//     pub pre_sparse_matrix: Matrix<F>,
//     pub sparse_matrixes: Vec<SparseMatrix<F>>,
//     pub domain_tag: F,
//     pub full_rounds: usize,
//     pub half_full_rounds: usize,
//     pub partial_rounds: usize,
// }

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

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use blstrs::Scalar as Fr;
//     use ff::Field;
//     use generic_array::typenum;

//
// #[test]
// fn hash_values() {
//     hash_values_cases(Strength::Standard);
//     hash_values_cases(Strength::Strengthened);
// }
//
// fn hash_values_cases(strength: Strength) {
//     hash_values_aux::<typenum::U2>(strength);
//     hash_values_aux::<typenum::U4>(strength);
//     hash_values_aux::<typenum::U8>(strength);
//     hash_values_aux::<typenum::U11>(strength);
//     hash_values_aux::<typenum::U16>(strength);
//     hash_values_aux::<typenum::U24>(strength);
//     hash_values_aux::<typenum::U36>(strength);
// }
//
// /// Simple test vectors to ensure results don't change unintentionally in development.
// fn hash_values_aux<A>(strength: Strength)
// where
//     A: Arity<Fr>,
// {
// let constants = NeptunePoseidonConstants::<Fr, A>::new_with_strength(strength);
// let mut p = NeptunePoseidon::<Fr, A>::new(&constants);
// let mut p2 = NeptunePoseidon::<Fr, A>::new(&constants);
// let mut p3 = NeptunePoseidon::<Fr, A>::new(&constants);
// let mut p4 = NeptunePoseidon::<Fr, A>::new(&constants);

//     let test_arity = constants.arity();
//     for n in 0..test_arity {
//         let scalar = Fr::from(n as u64);
//         p.input(scalar).unwrap();
//         p2.input(scalar).unwrap();
//         p3.input(scalar).unwrap();
//         p4.input(scalar).unwrap();
//     }

//     let digest = p.hash();
//     let digest2 = p2.hash_in_mode(Correct);
//     let digest3 = p3.hash_in_mode(OptimizedStatic);
//     let digest4 = p4.hash_in_mode(OptimizedDynamic);
//     assert_eq!(digest, digest2);
//     assert_eq!(digest, digest3);
//     assert_eq!(digest, digest4);

//     let expected = match strength {
//         Strength::Standard => {
//             // Currently secure round constants.
//             match test_arity {
//                 2 => scalar_from_u64s([
//                     0x2e203c369a02e7ff,
//                     0xa6fba9339d05a69d,
//                     0x739e0fd902efe161,
//                     0x396508d75e76a56b,
//                 ]),
//                 4 => scalar_from_u64s([
//                     0x019814ff6662075d,
//                     0xfb6b4605bf1327ec,
//                     0x00db3c6579229399,
//                     0x58a54b10a9e5848a,
//                 ]),
//                 8 => scalar_from_u64s([
//                     0x2a9934f56d38a5e6,
//                     0x4b682e9d9cc4aed9,
//                     0x1201004211677077,
//                     0x2394611da3a5de55,
//                 ]),
//                 11 => scalar_from_u64s([
//                     0xcee3bbc32b693163,
//                     0x09f3dcd8ccb08fc1,
//                     0x6ca537e232ebe87a,
//                     0x0c0fc1b2e5227f28,
//                 ]),
//                 16 => scalar_from_u64s([
//                     0x1291c74060266d37,
//                     0x5b8dbc6d30680a6f,
//                     0xc1c2fb5a6f871e63,
//                     0x2d3ae2663381ae8a,
//                 ]),
//                 24 => scalar_from_u64s([
//                     0xd7ef3569f585b321,
//                     0xc3e779f6468815b1,
//                     0x066f39bf783f3d9f,
//                     0x63beb8831f11ae15,
//                 ]),
//                 36 => scalar_from_u64s([
//                     0x4473606dfa4e8140,
//                     0x75cd368df8a8ac3c,
//                     0x540a30e03c10bbaa,
//                     0x699303082a6e5d5f,
//                 ]),
//                 _ => {
//                     dbg!(digest, test_arity);
//                     panic!("Arity lacks test vector: {}", test_arity)
//                 }
//             }
//         }
//         Strength::Strengthened =>
//         // Strengthened round constants.
//         {
//             match test_arity {
//                 2 => scalar_from_u64s([
//                     0x3abccd9afc5729b1,
//                     0x31662bb49883a7dc,
//                     0x2a0ae894f8500373,
//                     0x5f3027eb2ef4f4b8,
//                 ]),
//                 4 => scalar_from_u64s([
//                     0x3ff99d0422e647ee,
//                     0xad9fc9ebbb1515e1,
//                     0x8f57e5ab121004ce,
//                     0x40223b87a6bd4508,
//                 ]),
//                 8 => scalar_from_u64s([
//                     0xfffbca3d9ffcda00,
//                     0x7e4929e97170e2ae,
//                     0xfdbbbd4b1b984b9b,
//                     0x1367e3ced3e2edcb,
//                 ]),
//                 11 => scalar_from_u64s([
//                     0x29d77677fef45927,
//                     0x39062662a7311a7a,
//                     0xa8650443f7bf09c1,
//                     0x7344835ba9059929,
//                 ]),
//                 16 => scalar_from_u64s([
//                     0x48f16b2a7fa48951,
//                     0xbf999529774a192f,
//                     0x273664a5bf751815,
//                     0x6f53127e18f90e54,
//                 ]),
//                 24 => scalar_from_u64s([
//                     0xce136f2a6675f44b,
//                     0x0bf949d57c82de03,
//                     0xeab0b00318558589,
//                     0x70015999f995274e,
//                 ]),
//                 36 => scalar_from_u64s([
//                     0x80098c6336781a9a,
//                     0x591e29eb290a5b8e,
//                     0xd26ff2e8c5dd73e4,
//                     0x41d1adc5ece688c0,
//                 ]),
//                 _ => {
//                     dbg!(digest, test_arity);
//                     panic!("Arity lacks test vector: {}", test_arity)
//                 }
//             }
//         }
//     };
//     dbg!(test_arity);
//     assert_eq!(expected, digest);
// }
//
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

// }
