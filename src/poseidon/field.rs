//! Library independent specification for field trait.
//! `COM` is `()` when the field is in native, and is constraint synthesizer
//! when the field is a variable.
use ark_ec::{PairingEngine, TEModelParameters};
use ark_ff::PrimeField;
use ark_plonk::prelude::*;
use num_traits::One;
use std::marker::PhantomData;

pub trait COMArith<COM = ()>: Sized {
    // I added `com_` prefix here to avoid conflict with num_traits. Any suggestion
    // is welcome!
    /// additive identity
    fn com_zero(c: &mut COM) -> Self;
    /// add two field elements
    fn com_add(&self, b: &Self, c: &mut COM) -> Self;
    /// multiply field element by `-1`
    fn com_neg(&self, c: &mut COM) -> Self;
    /// subtract two field elements
    fn com_mul(&self, other: &Self,c: &mut COM) -> Self;
    fn com_add_assign(&mut self, other: &Self, c: &mut COM) {
        *self = self.com_add(other, c);
    }
}

pub trait COMOne<COM = ()>: COMArith<()> + Sized {
    /// multiplicative identity
    fn com_one(c: &mut COM) -> Self;
}

pub trait COMPower<COM = ()>: COMArith<()> + Sized {
    type Scalar;
    fn com_pow(&self, exp: &Self::Scalar, c: &mut COM) -> Self;
}

pub trait COMArithExt<COM = ()>: COMArith<COM> + Sized {
    type Native: COMArith<()> + COMOne<()>;
    type PublicInput;
    fn __make_arith_gate(c: &mut COM, config: ArithExtBuilder<Self, COM>) -> Self;
    fn com_arith(c: &mut COM) -> ArithExtBuilder<Self, COM> {
        ArithExtBuilder::new(c)
    }
}

/// `(w_l * w_r) * q_m + a * q_l + b * q_r + w_4 * q_4 + q_c + PI + q_o * c = 0`
/// where output is `c`
pub struct ArithExtBuilder<F: COMArithExt<COM>, COM = ()> {
    w_l: F,
    w_r: F,
    q_m: F::Native,
    q_l: F::Native,
    q_r: F::Native,
    q_c: F::Native,
    q_o: F::Native,
    q_4_w_4: Option<(F::Native, F)>,
    pi: Option<F::PublicInput>,
    _compiler: PhantomData<COM>,
}

impl<F: COMArithExt<COM>, COM> ArithExtBuilder<F, COM> {
    pub(crate) fn new(c: &mut COM) -> Self {
        Self {
            w_l: F::com_zero(c),
            w_r: F::com_zero(c),
            q_m: F::Native::com_zero(&mut ()),
            q_l: F::Native::com_zero(&mut ()),
            q_r: F::Native::com_zero(&mut ()),
            q_c: F::Native::com_zero(&mut ()),
            q_o: F::Native::com_one(&mut ()).com_neg(&mut ()),
            q_4_w_4: None,
            pi: None,
            _compiler: PhantomData,
        }
    }

    pub fn w_l(mut self, w_l: F) -> Self {
        self.w_l = w_l;
        self
    }

    pub fn w_r(mut self, w_r: F) -> Self {
        self.w_r = w_r;
        self
    }

    pub fn q_m(mut self, q_m: F::Native) -> Self {
        self.q_m = q_m;
        self
    }

    pub fn q_l(mut self, q_l: F::Native) -> Self {
        self.q_l = q_l;
        self
    }

    pub fn q_r(mut self, q_r: F::Native) -> Self {
        self.q_r = q_r;
        self
    }

    pub fn q_c(mut self, q_c: F::Native) -> Self {
        self.q_c = q_c;
        self
    }

    pub fn q4w4(mut self, q_4_w_4: (F::Native, F)) -> Self {
        self.q_4_w_4 = Some(q_4_w_4);
        self
    }

    pub fn pi(mut self, pi: F::PublicInput) -> Self {
        self.pi = Some(pi);
        self
    }

    pub fn q_o(mut self, q_o: F::Native) -> Self {
        self.q_o = q_o;
        self
    }

    pub fn build(self, c: &mut COM) -> F {
        F::__make_arith_gate(c, self)
    }
}

impl<F: PrimeField> COMArith<()> for F {
    fn com_zero(_c: &mut ()) -> Self {
        F::zero()
    }

    fn com_add(&self, b: &Self, _c: &mut ()) -> Self {
        *self + *b
    }

    fn com_neg(&self, _c: &mut ()) -> Self {
        -*self
    }

    fn com_mul(&self, other: &Self, _c: &mut ()) -> Self {
        *self * *other
    }
}

impl<F: PrimeField> COMOne<()> for F {
    fn com_one(_c: &mut ()) -> Self {
        F::one()
    }
}

impl<E, P> COMArith<StandardComposer<E, P>> for Variable
where
    E: PairingEngine,
    P: TEModelParameters<BaseField = E::Fr>,
{
    fn com_zero(c: &mut StandardComposer<E, P>) -> Self {
        c.zero_var()
    }

    fn com_add(&self, b: &Self, c: &mut StandardComposer<E, P>) -> Self {
        c.arithmetic_gate(|g| g.witness(*self, *b, None))
    }

    fn com_neg(&self, c: &mut StandardComposer<E, P>) -> Self {
        let zero = c.zero_var();
        c.arithmetic_gate(|g| {
            g.witness(*self, zero, None)
                .add(E::Fr::one(), E::Fr::from(0u64))
        })
    }

    fn com_mul(&self, other: &Self, c: &mut StandardComposer<E, P>) -> Self {
        c.arithmetic_gate(|g| {
            g.witness(*self, *other, None)
                .mul(E::Fr::one())
        })
    }

}

impl<F: PrimeField> COMArithExt<()> for F {
    type Native = F;
    type PublicInput = F;

    fn __make_arith_gate(_c: &mut (), config: ArithExtBuilder<Self, ()>) -> Self {
        let mut result = F::zero();
        result += (config.w_l * config.w_r) * config.q_m;
        result += config.q_l * config.w_l;
        result += config.q_r * config.w_r;
        result += config.q_4_w_4.map_or(F::zero(), |(q_4, w_4)| q_4 * w_4);
        result += config.q_c;
        result += config.pi.unwrap_or(F::zero());

        // now result = - q_o * c, we want c = (-result) / q_o
        let q_o_inv = F::inverse(&config.q_o).unwrap();
        (-result) * q_o_inv
    }
}

impl<E, P> COMArithExt<StandardComposer<E, P>> for Variable
where
    E: PairingEngine,
    P: TEModelParameters<BaseField = E::Fr>,
{
    type Native = E::Fr;
    type PublicInput = E::Fr;

    fn __make_arith_gate(
        c: &mut StandardComposer<E, P>,
        config: ArithExtBuilder<Self, StandardComposer<E, P>>,
    ) -> Self {
        c.arithmetic_gate(|g| {
            g.witness(config.w_l, config.w_r, None)
            .mul(config.q_m);
            .add(config.q_l, config.q_r);
            if let Some((q_4, w_4)) = config.q_4_w_4 {
                g.fan_in_3(q_4, w_4);
            };
            g.constant(config.q_c);
            g.out(config.q_o);
            if let Some(pi) = config.pi {
                g.constant(pi);
            }
            g
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn sanity_check_on_native() {
        // calculate 3xy + 2x + y + 1
        let mut rng = test_rng();
        let x = Fr::rand(&mut rng);
        let y = Fr::rand(&mut rng);
        let expected = (Fr::from(3u64) * x * y) + (Fr::from(2u64) * x) + y + Fr::one();
        let actual = Fr::com_arith(&mut ())
            .w_l(x)
            .w_r(y)
            .q_m(3u64.into())
            .q_l(2u64.into())
            .q_r(Fr::one())
            .q_c(Fr::one())
            .build(&mut ());

        assert_eq!(expected, actual);
    }
}
