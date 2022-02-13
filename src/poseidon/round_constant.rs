use ark_ff::{PrimeField};
use crate::poseidon::lfsr::GrainLFSR;

/// return round constants, and return the LFSR used to generate MDS matrix
pub fn generate_round_constants<F: PrimeField>(
    prime_num_bits: u64,
    width: usize,
    r_f: usize,
    r_p: usize,
) -> (Vec<F>, GrainLFSR) {
    let num_constants = (r_f + r_p) * width;
    let mut lfsr = GrainLFSR::new(prime_num_bits, width, r_f, r_p);
    (lfsr.get_field_elements_rejection_sampling(num_constants), lfsr)
}


