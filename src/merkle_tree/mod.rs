//! code adapted from https://github.com/Manta-Network/manta-rs/blob/setup-manta-rs/manta-crypto/src/merkle_tree/tree.rs

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
    fn join(parameters: &Self::Parameters, lhs: &Self::Output, rhs: &Self::Output) -> Self::Output {
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
}
