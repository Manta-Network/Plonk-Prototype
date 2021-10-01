use dusk_plonk::prelude::*;
use rand_core::OsRng;

// Implement a circuit that check variable length pedersen commitment
// Input:
//    1) m: a variable length input
//    2) r: a random secret
// Output:
//    1) a point o = g^m*h^r
#[derive(Debug, Default)]
pub struct TestCircuit {
    m_scalars: Vec<JubJubScalar>,
    r_scalars: Vec<JubJubScalar>,
    target_o_point: JubJubAffine,
}

impl Circuit for TestCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(
        &mut self,
        composer: &mut StandardComposer,
    ) -> Result<(), Error> {
        assert_eq!(m_scalars.len(), r_scalars.len());

        // Convert JubJubScalar inputs into circuit variables
        let m_variables = Vec<Variable>;
        let r_variables = Vec<Variable>;
        for m in &self.m_scalars {
            m_variable = composer.add_input(m);
            m_variables.push(m_variable);
        }
        for r in &self.r_scalars {
            r_variable = composer.add_input(r);
            r_variables.push(r_variable);
        }

        // Compute variable length pedersen commitment
        output_point = variable_length_pedersen_commitment_gadget(composer, m_variables, r_variables);

        // Check that output_point equals to the o_scalar (from input)
        composer.assert_equal_public_point(output_point, self.target_o_point);
        Ok(())
    }
    fn padded_circuit_size(&self) -> usize {
        1 << 11
    }
}


// Function to calculate plaintext fixed length pedersen commitment
// Use this function to validate the circuit result.
pub fn plain_fixed_length_pedersen_commitment(
    value: JubJubScalar, blinder_variables: JubJubScalar,
) -> JubJubAffine {
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(value_variables[0]);
    let p2 = dusk_jubjub::GENERATOR_NUMS_EXTENDED * JubJubScalar::from(blinder_variables[0]);
    p1+p2
}


// Function to calculate plaintext variable length pedersen commitment
// Use this function to validate the circuit result.
pub fn plain_variable_length_pedersen_commitment(
    values: Vec<JubJubScalar>,
    blinders: Vec<JubJubScalar>,
) -> JubJubAffine {
    // Conduct fixed length pedersen commitment over individual m/r pairs, and accumulate in output_point
    let output_point = plain_fixed_length_pedersen_commitment(values[0], blinders[0]);
    for i in 1..values.len() {
        let tmp_point = plain_fixed_length_pedersen_commitment(values[i], blinders[i]);
        output_point = output_point + tmp_point;
    }
    output_point
}


// Now let's use the Circuit we've just implemented!

let pp = PublicParameters::setup(1 << 12, &mut OsRng).unwrap();
// Initialize the circuit
let mut circuit = TestCircuit::default();
// Compile the circuit
let (pk, vd) = circuit.compile(&pp).unwrap();
// Prover POV
let proof = {
    let mut m_scalars: Vec<JubJubScalar> = Vec::new();
    let mut r_scalars: Vec<JubJubScalar> = Vec::new();
    for i in 0..5 {
        m_scalars.push(JubJubScalar::from(i as u128));
        r_scalars.push(JubJubScalar::from(2*i as u128))
    }

    let target_o_point = plain_variable_length_pedersen_commitment(m_scalars, r_scalars);

    let mut circuit = TestCircuit {
        m_scalars: m_scalars,
        r_scalars: r_scalars,
        target_o_point: JubJubAffine::from(target_o_point),
    };
    circuit.gen_proof(&pp, &pk, b"Test").unwrap()
};
// Verifier POV
let public_inputs: Vec<PublicInputValue> = vec![
    JubJubAffine::from(target_o_point)
    .into(),
];
circuit::verify_proof(
    &pp,
    &vd.key(),
    &proof,
    &public_inputs,
    &vd.pi_pos(),
    b"Test",
).unwrap();