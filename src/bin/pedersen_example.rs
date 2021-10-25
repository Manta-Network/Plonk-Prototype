use dusk_plonk::prelude::*;
use plonk_prototype::zk::gadgets::*;
use rand_core::OsRng;

// Implement a circuit that check variable length pedersen commitment
// Input:
//    1) m: a variable length input
//    2) r: a random secret
// Output:
//    1) a point o = g^m*h^r
#[derive(Debug, Default)]
pub struct TestCircuit {
    // m_scalars: Vec<JubJubScalar>,
    m_scalars: Vec<JubJubScalar>,
    r_scalars: Vec<JubJubScalar>,
    target_o_point: JubJubAffine,
}

impl Circuit for TestCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(&mut self, composer: &mut StandardComposer) -> Result<(), Error> {
        assert_eq!(self.m_scalars.len(), self.r_scalars.len());

        println!("m_scalars.len(): {}", self.m_scalars.len());

        // Convert JubJubScalar inputs into circuit variables
        let mut m_variables: Vec<Variable> = Vec::new();
        let mut r_variables: Vec<Variable> = Vec::new();
        for i in 0..self.m_scalars.len() {
            let m_variable = composer.add_input(self.m_scalars[i].into());
            m_variables.push(m_variable);
            println!("m_variables.len(): {}", m_variables.len());
        }
        for i in 0..self.r_scalars.len() {
            let r_variable = composer.add_input(self.r_scalars[i].into());
            r_variables.push(r_variable);
        }

        println!("m_variables.len(): {}", m_variables.len());

        // // Compute variable length pedersen commitment
        let output_point =
            variable_length_pedersen_commitment_gadget(composer, m_variables, r_variables);

        // // Check that output_point equals to the o_scalar (from input)
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
    value: JubJubScalar,
    blinder: JubJubScalar,
) -> JubJubAffine {
    let p1 = dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(value[0]);
    let p2 = dusk_jubjub::GENERATOR_NUMS_EXTENDED * JubJubScalar::from(blinder[0]);
    let p: JubJubAffine = (p1 + p2).into();
    p
}

// Function to calculate plaintext variable length pedersen commitment
// Use this function to validate the circuit result.
pub fn plain_variable_length_pedersen_commitment(
    values: &Vec<JubJubScalar>,
    blinders: &Vec<JubJubScalar>,
) -> JubJubAffine {
    // Conduct fixed length pedersen commitment over individual m/r pairs, and accumulate in output_point
    let mut output_point = plain_fixed_length_pedersen_commitment(values[0], blinders[0]);
    for i in 1..values.len() {
        let tmp_point = plain_fixed_length_pedersen_commitment(values[i], blinders[i]);
        // TODO: Not sure how to accumulate points in plaintext
        // output_point = output_point + tmp_point;
    }
    output_point
}

fn main() {
    let mut m_scalars_vec: Vec<JubJubScalar> = Vec::new();
    let mut r_scalars_vec: Vec<JubJubScalar> = Vec::new();
    for i in 0..5 {
        m_scalars_vec.push(JubJubScalar::from(i as u64));
        r_scalars_vec.push(JubJubScalar::from(2 * i as u64));
        println!("m_scalars_vec.len(): {}", m_scalars_vec.len());
    }

    // Now let's use the Circuit we've just implemented!
    let pp = PublicParameters::setup(1 << 12, &mut OsRng).unwrap();
    // Initialize the circuit
    let mut circuit = TestCircuit::default();
    // Compile the circuit
    let (pk, vd) = circuit.compile(&pp).unwrap();
    // Prover POV
    println!("before plain. m_scalars_vec.len(): {}", m_scalars_vec.len());
    let target_o_point = plain_variable_length_pedersen_commitment(&m_scalars_vec, &r_scalars_vec);
    println!("after plain. m_scalars_vec.len(): {}", m_scalars_vec.len());

    let proof = {
        let mut circuit = TestCircuit {
            m_scalars: m_scalars_vec,
            r_scalars: r_scalars_vec,
            target_o_point: JubJubAffine::from(target_o_point),
        };
        circuit.gen_proof(&pp, &pk, b"Test").unwrap()
    };
    // Verifier POV
    let public_inputs: Vec<PublicInputValue> = vec![JubJubAffine::from(target_o_point).into()];
    circuit::verify_proof(
        &pp,
        &vd.key(),
        &proof,
        &public_inputs,
        &vd.pi_pos(),
        b"Test",
    )
    .unwrap();
}
