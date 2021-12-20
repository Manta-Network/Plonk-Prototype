// Implmenetation for sbox in plaintext and circuit.
// This implementation will be used in poseidon hash.
// Code borrows largely from https://github.com/webb-tools/arkworks-gadgets/tree/master/arkworks-utils/src/poseidon
use ark_plonk::constraint_system::{StandardComposer, Variable};
use ark_plonk::error::Error;
use ark_plonk::proof_system::{Proof, Prover, ProverKey, Verifier, VerifierKey};
use ark_plonk::circuit::{self, Circuit, PublicInputValue, VerifierData, verify_proof, FeIntoPubInput, GeIntoPubInput};

use ark_poly_commit::kzg10::KZG10;
use num_traits::{One, Zero};
use ark_ec::models::TEModelParameters;
use ark_ec::{
    PairingEngine, ProjectiveCurve,
};
use ark_poly::univariate::DensePolynomial;
use ark_poly_commit::kzg10::{self, Powers, UniversalParams};
use ark_poly_commit::sonic_pc::SonicKZG10;
use ark_poly_commit::PolynomialCommitment;
use ark_serialize::*;
use ark_ff::PrimeField;


// A native S-Box that can be used with Poseidon. Currently support only x^5.
fn sbox_native<
    E: PairingEngine
>(elem: E::Fr) -> E::Fr {
    let sqr = elem * elem;
    let fourth_power = sqr * sqr;
    fourth_power * elem
}


// A circuit S-Box that can be used with Poseidon. Currently support only x^5.
fn sbox_gadget<
    E: PairingEngine,
    P: TEModelParameters<BaseField = E::Fr>,
>(composer: &mut StandardComposer<E, P>, elem_var: Variable) -> Variable {
    let square_var = composer.mul(E::Fr::one(), elem_var, elem_var, E::Fr::zero(), None);
    let fourth_power_var = composer.mul(E::Fr::one(), square_var, square_var, E::Fr::zero(), None);
    composer.mul(E::Fr::one(), fourth_power_var, elem_var, E::Fr::zero(), None)
}


#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    
    #[derive(derivative::Derivative)]
    #[derivative(Debug(bound = ""), Default(bound = ""))]
    pub struct TestCircuit<
        E: PairingEngine,
    > {
        elem: E::Fr,
    }

    impl<E, P> Circuit<E, P> for TestCircuit<E>
    where
        E: PairingEngine,
        P: TEModelParameters<BaseField = E::Fr>,
    {
        const CIRCUIT_ID: [u8; 32] = [0xff; 32];

        fn gadget(
            &mut self,
            composer: &mut StandardComposer<E, P>,
        ) -> Result<(), Error> {
            // Call gadget
            let elem_var = composer.add_input(self.elem);
            let sbox_var = sbox_gadget(composer, elem_var);

            // Call native
            let sbox_target = sbox_native::<E>(self.elem);
            let sbox_target_var = composer.add_input(sbox_target);

            composer.assert_equal(sbox_var, sbox_target_var);
            Ok(())
        }

        fn padded_circuit_size(&self) -> usize {
            1 << 11
        }
    }

    fn test_full<E: PairingEngine, P: TEModelParameters<BaseField = E::Fr>>() -> Result<(), Error> {
        use rand_core::OsRng;

        // Generate CRS
        let pp = KZG10::<E, DensePolynomial<E::Fr>>::setup(
                1 << 12,
                false,
                &mut OsRng,
        )?;

        let mut circuit = TestCircuit::<E>::default();

        // Compile the circuit
        let (pk_p, verifier_data) = circuit.compile(&pp)?;

        // Prover POV
        // Example1
        let proof = {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let rand_num:u16 = rng.gen();
            let mut circuit: TestCircuit<E> = TestCircuit {
                    elem: E::Fr::from(rand_num),
                };

                circuit.gen_proof(&pp, pk_p, b"Test")?
        };

        let public_inputs: Vec<PublicInputValue<P>> = vec![];
        
        let VerifierData { key, pi_pos } = verifier_data;

        assert!(verify_proof::<E, P>(
                &pp,
                key,
                &proof,
                &public_inputs,
                &pi_pos,
                b"Test",
        )
        .is_ok());

        Ok(())
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_full_on_Bls12_381() -> Result<(), Error> {
        test_full::<Bls12_381, ark_ed_on_bls12_381::EdwardsParameters>()
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_full_on_Bls12_377() -> Result<(), Error> {
        test_full::<Bls12_377, ark_ed_on_bls12_377::EdwardsParameters>()
    }
}