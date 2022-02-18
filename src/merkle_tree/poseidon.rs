use crate::merkle_tree::{BinaryHashFunction, HashFunction, InnerHash, LeafHash, UnaryHashFunction};
use crate::poseidon::constants::PoseidonConstants;
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

impl<'a, COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize> UnaryHashFunction<COM>
    for Poseidon<'a, COM, S, WIDTH>
{
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

pub struct PoseidonStateless<COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize> {
    _marker: std::marker::PhantomData<(COM, S)>,
}

impl<COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize> PoseidonStateless<COM, S, WIDTH> {
    pub fn start_state<'a>(
        c: &mut COM,
        param: &'a PoseidonConstants<S::ParameterField>,
    ) -> Poseidon<'a, COM, S, WIDTH> {
        Poseidon::<COM, S, WIDTH>::new(c, param)
    }
}

impl<COM, S: PoseidonSpec<COM, 3>> InnerHash<COM> for PoseidonStateless<COM, S, 3> {
    type LeafDigest = S::Field;
    type Parameters = PoseidonConstants<S::ParameterField>;
    type Output = S::Field;

    fn join_in(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        compiler: &mut COM,
    ) -> Self::Output {
        let state = PoseidonStateless::start_state(compiler, parameters);
        <Poseidon<COM, S, 3> as BinaryHashFunction::<COM>>::hash_in(&state, lhs, rhs, compiler)
    }

    fn join_leaves_in(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        compiler: &mut COM,
    ) -> Self::Output {
        Self::join_in(parameters, lhs, rhs, compiler)
    }
}

impl< COM, S: PoseidonSpec<COM, WIDTH>, const WIDTH: usize> LeafHash<COM>
for PoseidonStateless< COM, S, WIDTH>
{
    type Leaf = S::Field;
    type Parameters = PoseidonConstants<S::ParameterField>;
    type Output = S::Field;

    fn digest_in(parameters: &Self::Parameters, leaf: &Self::Leaf, compiler: &mut COM) -> Self::Output {
        let state = PoseidonStateless::start_state(compiler, parameters);
        <Poseidon<COM, S, WIDTH> as UnaryHashFunction::<COM>>::hash_in(&state, leaf, compiler)
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
        let poseidon = Poseidon::<_, NativeSpec<Fr, 3>, 3>::new(&mut (), &params);
        let inputs = [field_new!(Fr, "1"), field_new!(Fr, "2")];
        let output = poseidon.hash(&inputs[0], &inputs[1]);
        let expected = field_new!(
            Fr,
            "13469396364901763595452591099956641926259481376691266681656453586107981422876"
        );
        assert_eq!(output, expected);
    }
}
