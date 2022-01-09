//! Library independent specification for field trait.
//! `COM` is `()` when the field is in native, and is constraint synthesizer
//! when the field is a variable.
use ark_ec::{PairingEngine, TEModelParameters};
use ark_ff::PrimeField;
use ark_plonk::prelude::*;
use num_traits::One;
use std::marker::PhantomData;

pub trait COMArith<COM = ()>: Sized {
    /// additive identity
    fn zero(c: &mut COM) -> Self;
    /// add two field elements
    fn add(c: &mut COM, a: &Self, b: &Self) -> Self;
    /// multiply field element by `-1`
    fn neg(c: &mut COM, a: &Self) -> Self;
    /// subtract two field elements
    fn mul(c: &mut COM, a: &Self, b: &Self) -> Self;
    fn add_assign(c: &mut COM, a: &mut Self, b: &Self) {
        *a = Self::add(c, a, b);
    }
}

pub trait COMOne<COM = ()>: COMArith<()> + Sized {
    /// multiplicative identity
    fn one(c: &mut COM) -> Self;
}

pub trait COMPower<COM = ()>: COMArith<()> + Sized {
    type Scalar;
    fn pow(c: &mut COM, a: &Self, b: &Self::Scalar) -> Self;
}

pub trait COMArithExt<COM = ()>: COMArith<COM> + Sized {
    type Native: COMArith<()> + COMOne<()>;
    type PublicInput;
    fn __make_arith_gate(c: &mut COM, config: ArithExtBuilder<Self, COM>) -> Self;
    fn arith(c: &mut COM) -> ArithExtBuilder<Self, COM> {
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
            w_l: F::zero(c),
            w_r: F::zero(c),
            q_m: F::Native::zero(&mut ()),
            q_l: F::Native::zero(&mut ()),
            q_r: F::Native::zero(&mut ()),
            q_c: F::Native::zero(&mut ()),
            q_o: F::Native::one(&mut ()),
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
    fn zero(_c: &mut ()) -> Self {
        F::zero()
    }

    fn add(_c: &mut (), a: &Self, b: &Self) -> Self {
        a.add(b)
    }

    fn neg(_c: &mut (), a: &Self) -> Self {
        a.neg()
    }

    fn mul(_c: &mut (), a: &Self, b: &Self) -> Self {
        a.mul(b)
    }
}

impl<F: PrimeField> COMOne<()> for F {
    fn one(_c: &mut ()) -> Self {
        F::one()
    }
}

impl<E, P> COMArith<StandardComposer<E, P>> for Variable
where
    E: PairingEngine,
    P: TEModelParameters<BaseField = E::Fr>,
{
    fn zero(c: &mut StandardComposer<E, P>) -> Self {
        c.zero_var()
    }

    fn add(c: &mut StandardComposer<E, P>, a: &Self, b: &Self) -> Self {
        c.arithmetic_gate(|g| g.witness(*a, *b, None))
    }

    /// Simply calling neg is inefficient.
    fn neg(c: &mut StandardComposer<E, P>, a: &Self) -> Self {
        let zero = c.zero_var();
        c.arithmetic_gate(|g| {
            g.witness(*a, zero, None)
                .add(<<E as PairingEngine>::Fr as One>::one(), E::Fr::from(0u64))
        })
    }

    fn mul(c: &mut StandardComposer<E, P>, a: &Self, b: &Self) -> Self {
        c.arithmetic_gate(|g| {
            g.witness(*a, *b, None)
                .mul(<<E as PairingEngine>::Fr as One>::one())
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
            g.witness(config.w_l, config.w_r, None);
            g.mul(config.q_m);
            g.add(config.q_l, config.q_r);
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
