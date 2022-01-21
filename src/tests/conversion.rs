//! Conversion from `ff` bls-381-fr to `ark-ff` bls-381-fr
use ark_ec::PairingEngine;
use ark_ff::{Field as ArkField, PrimeField as ArkPrimeField};
use blstrs::Scalar as Fr;
use ff::Field;
use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use crate::poseidon::matrix::Matrix;

type ArkFr = <ark_bls12_381::Bls12_381 as PairingEngine>::Fr;

pub fn cast_field(x: Fr) -> ArkFr {
    let repr = x.to_bytes_le();
    ArkFr::from_le_bytes_mod_order(&repr)
}

pub fn cast_vector(x: Vec<Fr>) -> Vec<ArkFr> {
    x.into_iter().map(cast_field).collect()
}

pub fn cast_matrix(x: Vec<Vec<Fr>>) -> Matrix<ArkFr> {
    x.into_iter().map(cast_vector).collect()
}

#[test]
fn test_conversion() {
    let x = Fr::from(0x12345678u64);
    let x_expected = ArkFr::from(0x12345678u64);
    let x_actual = cast_field(x);
    assert_eq!(x_expected, x_actual);

    let mut rng = StdRng::seed_from_u64(0x12345678);
    for _ in 0..1000{
        let a = Fr::random(&mut rng);
        let a_ark = cast_field(a);
        let b = Fr::random(&mut rng);
        let b_ark = cast_field(b);

        let k = rng.next_u64();
        let c = a.square() + b.square() + Fr::from(k);
        let c_ark_expected = cast_field(c);
        let c_ark_actual = a_ark.square() + b_ark.square() + ArkFr::from(k);
        assert_eq!(c_ark_expected, c_ark_actual);
    }
}