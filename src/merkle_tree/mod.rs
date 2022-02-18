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

/// Merkle Tree Leaf Hash
pub trait LeafHash<COM = ()> {
    /// Leaf Type
    type Leaf: ?Sized;

    /// Leaf Hash Parameters Type
    type Parameters;

    /// Leaf Hash Output Type
    type Output;

    /// Computes the digest of the `leaf` using `parameters` inside the given `compiler`.
    fn digest_in(
        parameters: &Self::Parameters,
        leaf: &Self::Leaf,
        compiler: &mut COM,
    ) -> Self::Output;

    /// Computes the digest of the `leaf` using `parameters`.
    #[inline]
    fn digest(parameters: &Self::Parameters, leaf: &Self::Leaf) -> Self::Output
        where
            COM: Native,
    {
        Self::digest_in(parameters, leaf, &mut COM::compiler())
    }
}

/// Merkle Tree Inner Hash
pub trait InnerHash<COM = ()> {
    /// Leaf Digest Type
    type LeafDigest;

    /// Inner Hash Parameters Type
    type Parameters;

    /// Inner Hash Output Type
    type Output;

    /// Combines two inner digests into a new inner digest using `parameters` inside the given
    /// `compiler`.
    fn join_in(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        compiler: &mut COM,
    ) -> Self::Output;

    /// Combines two inner digests into a new inner digest using `parameters`.
    #[inline]
    fn join(parameters: &Self::Parameters, lhs: &Self::Output, rhs: &Self::Output) -> Self::Output
        where
            COM: Native,
    {
        Self::join_in(parameters, lhs, rhs, &mut COM::compiler())
    }

    /// Combines two [`LeafDigest`](Self::LeafDigest) values into an inner digest inside the given
    /// `compiler`.
    fn join_leaves_in(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        compiler: &mut COM,
    ) -> Self::Output;

    /// Combines two [`LeafDigest`](Self::LeafDigest) values into an inner digest.
    #[inline]
    fn join_leaves(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
    ) -> Self::Output
        where
            COM: Native,
    {
        Self::join_leaves_in(parameters, lhs, rhs, &mut COM::compiler())
    }
}

