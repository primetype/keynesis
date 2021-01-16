use crate::passport::block::Hash;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Hash, Clone)]
pub enum Previous {
    /// denote a block that does not have a previous block
    ///
    /// this means the given block is a genesis block.
    None,
    /// The previous block of the given block
    ///
    /// This allows to make sure we have a blockchain that is up
    /// to date with current requirements, but also make sure that
    /// the given block is valid in the context of the past history
    ///
    /// i.e. the block's proof will need to match against the
    /// initially authorized authors. Also the Block's actions will
    /// need to be valid based on the state of the blockchain
    /// at the given hash.
    Previous(Hash),
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{Arbitrary, Gen};

    impl Arbitrary for Previous {
        fn arbitrary(g: &mut Gen) -> Self {
            if bool::arbitrary(g) {
                Previous::None
            } else {
                Previous::Previous(Hash::arbitrary(g))
            }
        }
    }
}
