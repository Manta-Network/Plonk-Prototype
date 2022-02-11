use ark_ff::{BigInteger, FpParameters, PrimeField};

pub fn generate_round_constants<F: PrimeField>(
    prime_num_bits: u64,
    width: usize,
    r_f: usize,
    r_p: usize,
) -> Vec<F> {
    let num_constants = (r_f + r_p) * width;
    let mut lfsr = GrainLFSR::new(prime_num_bits, width, r_f, r_p);
    lfsr.get_field_elements_rejection_sampling(num_constants)
}

fn append_bits<T: Into<u128>>(state: &mut [bool; 80], head: &mut usize, n: usize, from: T) {
    let val = from.into() as u128;
    for i in (0..n).rev() {
        state[*head] = ((val >> i) & 1 != 0);
        *head += 1;
        *head %= 80;
    }
}

// adapted from: https://github.com/arkworks-rs/sponge/blob/51d6fc9aac1fa69f44a04839202b5de828584ed8/src/poseidon/grain_lfsr.rs
struct GrainLFSR {
    state: [bool; 80],
    prime_num_bits: u64,
    head: usize,
}

impl GrainLFSR {
    pub fn new(prime_num_bits: u64, width: usize, r_f: usize, r_p: usize) -> Self {
        let mut init_sequence = [false; 80];
        let mut head = 0;
        // b0, b1 describes the field
        append_bits(&mut init_sequence, &mut head, 2, 1u8);
        // b2...=b5 describes s-box: we always use non-inverse s-box
        append_bits(&mut init_sequence, &mut head, 4, 0b00001u8);
        // b6...=b17 describes prime_num_bits
        append_bits(&mut init_sequence, &mut head, 12, prime_num_bits);
        // b18...=b29 describes width
        append_bits(&mut init_sequence, &mut head, 12, width as u16);
        // b30..=39 describes r_f (num_full_rounds)
        append_bits(&mut init_sequence, &mut head, 10, r_f as u16);
        // b40..=49 describes r_p (num_partial_rounds)
        append_bits(&mut init_sequence, &mut head, 10, r_p as u16);
        // b50..=79 describes the constant 1
        append_bits(
            &mut init_sequence,
            &mut head,
            30,
            0b111111111111111111111111111111u128,
        );
        let mut res = GrainLFSR {
            state: init_sequence,
            prime_num_bits,
            head,
        };
        res.init();
        res

    }

    fn update(&mut self) -> bool {
        let new_bit =
            self.bit(62) ^ self.bit(51) ^ self.bit(38) ^ self.bit(23) ^ self.bit(13) ^ self.bit(0);
        self.state[self.head] = new_bit;
        self.head += 1;
        self.head %= 80;
        new_bit
    }

    fn init(&mut self) {
        for _ in 0..160 {
            self.update();
        }
    }

    #[inline]
    fn bit(&self, index: usize) -> bool {
        self.state[(index + self.head) % 80]
    }

    pub fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let mut res = Vec::new();

        for _ in 0..num_bits {
            // Obtain the first bit
            let mut new_bit = self.update();

            // Loop until the first bit is true
            while new_bit == false {
                // Discard the second bit
                let _ = self.update();
                // Obtain another first bit
                new_bit = self.update();
            }

            // Obtain the second bit
            res.push(self.update());
        }

        res
    }

    pub fn get_field_elements_rejection_sampling<F: PrimeField>(
        &mut self,
        num_elems: usize,
    ) -> Vec<F> {
        assert_eq!(F::Params::MODULUS_BITS as u64, self.prime_num_bits);

        let mut res = Vec::new();
        for _ in 0..num_elems {
            // Perform rejection sampling
            loop {
                // Obtain n bits and make it most-significant-bit first
                let mut bits = self.get_bits(self.prime_num_bits as usize);
                bits.reverse();

                // Construct the number
                let bigint = F::BigInt::from_bits_le(&bits);

                if let Some(f) = F::from_repr(bigint) {
                    res.push(f);
                    break;
                }
            }
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use crate::poseidon::round_constant::GrainLFSR;
    use ark_bls12_381::Fr;
    use ark_ff::field_new;

    #[test]
    fn test_grain_lfsr_consistency() {

        // git clone https://extgit.iaik.tugraz.at/krypto/hadeshash.git
        // sage code/generate_parameters_grain.sage 1 0 255 3 8 31 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

        let mut lfsr = GrainLFSR::new(255, 3, 8, 31);
        assert_eq!(
            lfsr.get_field_elements_rejection_sampling::<Fr>(1)[0],
            field_new!(
                Fr,
                "27117311055620256798560880810000042840428971800021819916023577129547249660720"
            )
        );
        assert_eq!(
            lfsr.get_field_elements_rejection_sampling::<Fr>(1)[0],
            field_new!(
                Fr,
                "51641662388546346858987925410984003801092143452466182801674685248597955169158"
            )
        );
    }
}
