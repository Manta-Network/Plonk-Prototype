// This code is identical from https://github.com/Manta-Network/manta-rs/blob/setup-manta-rs/manta-crypto/src/hash.rs
// So that, poseidon implementation can be easily moved to manta-rs

pub mod poseidon;

use crate::Native;

/// Hash Function
pub trait HashFunction<COM, const ARITY: usize> {
    /// Input Type
    type Input: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `input` in the given `compiler`.
    fn hash_in(&self, input: [&Self::Input; ARITY], compiler: &mut COM) -> Self::Output;

    /// Computes the hash over `input`.
    #[inline]
    fn hash(&self, input: [&Self::Input; ARITY]) -> Self::Output
    where
        COM: Native,
    {
        self.hash_in(input, &mut COM::compiler())
    }
}

/// Unary Hash Function
pub trait UnaryHashFunction<COM = ()> {
    /// Input Type
    type Input: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `input` in the given `compiler`.
    fn hash_in(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output;

    /// Computes the hash over `input`.
    #[inline]
    fn hash(&self, input: &Self::Input) -> Self::Output
    where
        COM: Native,
    {
        self.hash_in(input, &mut COM::compiler())
    }
}

/// Binary Hash Function
pub trait BinaryHashFunction<COM = ()> {
    /// Left Input Type
    type Left: ?Sized;

    /// Right Input Type
    type Right: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `lhs` and `rhs` in the given `compiler`.
    fn hash_in(&self, lhs: &Self::Left, rhs: &Self::Right, compiler: &mut COM) -> Self::Output;

    /// Computes the hash over `lhs` and `rhs`.
    #[inline]
    fn hash(&self, lhs: &Self::Left, rhs: &Self::Right) -> Self::Output
    where
        COM: Native,
    {
        self.hash_in(lhs, rhs, &mut COM::compiler())
    }
}
