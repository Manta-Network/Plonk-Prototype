use crate::merkle_tree::{BinaryHashFunction, HashFunction, UnaryHashFunction};
use crate::poseidon::poseidon::{Poseidon, PoseidonSpec};

macro_rules! impl_hash_arity {
    ($arity: expr) => {
        impl<'a, COM, S: PoseidonSpec<COM, { $arity + 1 }>> HashFunction<COM, $arity>
            for Poseidon<'a, COM, S, { $arity + 1 }>
        {
            type Input = S::Field;
            type Output = S::Field;

            fn hash_in(&self, input: [&Self::Input; $arity], compiler: &mut COM) -> Self::Output {
                let mut this = self.clone();
                for x in input {
                    this.input(x.clone()).unwrap(); // TODO: handle error
                }
                this.output_hash(compiler)
            }
        }
    };
}

// before `const_expr` feature gets stabilized, we manually implement hash functions for each arity
impl_hash_arity!(1);
impl_hash_arity!(2);
impl_hash_arity!(3);
impl_hash_arity!(4);
impl_hash_arity!(5);
impl_hash_arity!(6);
impl_hash_arity!(7);
impl_hash_arity!(8);

impl<'a, COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize> UnaryHashFunction<COM> for Poseidon<'a, COM, S, WIDTH> {
    type Input = S::Field;
    type Output = S::Field;

    fn hash_in(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output {
        let mut this = self.clone();
        this.input(input.clone()).unwrap(); // TODO: handle error
        this.output_hash(compiler)
    }
}

impl<'a, COM, S: PoseidonSpec<COM, 3>> BinaryHashFunction<COM> for Poseidon<'a, COM, S, 3> {
    type Left = S::Field;
    type Right = S::Field;
    type Output = S::Field;

    fn hash_in(&self, lhs: &Self::Left, rhs: &Self::Right, compiler: &mut COM) -> Self::Output {
        <Self as HashFunction<COM, 2>>::hash_in(self, [lhs, rhs], compiler)
    }
}


#[cfg(test)]
mod tests {
    use crate::merkle_tree::BinaryHashFunction;
    use crate::poseidon::constants::PoseidonConstants;
    use crate::poseidon::poseidon::{NativeSpec, Poseidon};
    use ark_bls12_381::Fr;
    use ark_ff::field_new;

    #[test]
    fn test_hash() {
        let params = PoseidonConstants::generate::<3>();
        let poseidon =
            Poseidon::<_, NativeSpec<Fr, 3>, 3>::new(&mut (), &params);
        let inputs = [field_new!(Fr, "1"), field_new!(Fr, "2")];
        let output = poseidon.hash(&inputs[0], &inputs[1]);
        let expected = field_new!(
            Fr,
            "13469396364901763595452591099956641926259481376691266681656453586107981422876"
        );
        assert_eq!(output, expected);
    }
}
