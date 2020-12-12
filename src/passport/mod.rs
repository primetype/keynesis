/*!
Identity passport, this is the set of keys that can be used to
authenticate a user. The passport is managed by the owner of the
associated keys only. Making it a permission blockchain.

*/

pub mod block;
mod builder;
pub mod ledger;

pub use self::builder::PassportMut;
use self::{
    block::{Block, Time},
    ledger::Ledger,
};
use crate::{
    key::{
        curve25519::{self, PublicKey},
        ed25519,
    },
    noise::{HandshakeStateError, N},
    Seed,
};
use block::BlockSlice;
use cryptoxide::blake2b::Blake2b;
use rand_core::{CryptoRng, RngCore};
use std::{convert::TryFrom as _, vec};
use thiserror::Error;

pub struct LightPassport(Ledger);

pub struct Passport {
    ledger: Ledger,

    blockchain: Vec<Block>,
}

#[derive(Debug, Error)]
pub enum PassportError {
    #[error("Error while updating the ledger")]
    Ledger(
        #[source]
        #[from]
        ledger::LedgerError,
    ),

    #[error("Invalid Block")]
    Block(
        #[source]
        #[from]
        block::BlockError,
    ),

    #[error("Invalid entry")]
    Entry(
        #[source]
        #[from]
        block::EntryError,
    ),

    #[error("Cannot decode the private key, passphrase or key invalid")]
    CannotDecodeMsg(
        #[source]
        #[from]
        HandshakeStateError,
    ),

    #[error("Shared Key Incompatible")]
    Curve25519(
        #[source]
        #[from]
        curve25519::SecretKeyError,
    ),

    #[error("No shared key found for this configuration")]
    NoSharedKeyFound,
}

impl LightPassport {
    pub fn new(block: BlockSlice) -> Result<Self, PassportError> {
        Ledger::new(block).map(Self).map_err(PassportError::from)
    }

    pub fn update(&mut self, block: BlockSlice) -> Result<(), PassportError> {
        self.0 = self.0.apply(block)?;
        Ok(())
    }

    /// get the `Passport` shared key
    ///
    /// This key is a key that all the master keys are aware of and can
    /// be used. Every time a master key is added or removed, a new key
    /// is generated. Please use the most recent version, otherwise the
    /// recipient may not see the new keys
    pub fn shared_key(&self) -> Option<&(Time, PublicKey)> {
        self.0.shared_key()
    }
}

impl Passport {
    /// create a new passport
    ///
    /// the alias is the alias that is going to be associated to the given
    /// key (`author`). The `author` will be automatically added as one of
    /// the master key of the passport.
    ///
    /// Calling this function will create a new shared key that will be
    /// automatically shared to the `author`'s key. The `author` can then
    /// decode the `shared_key` _secret_ with the `author` key and the
    /// `passphrase`.
    ///
    pub fn create<RNG>(
        rng: &mut RNG,
        alias: &str,
        author: &ed25519::SecretKey,
        passphrase: Seed,
    ) -> Result<Self, PassportError>
    where
        RNG: CryptoRng + RngCore,
    {
        let mut builder = builder::PassportBuilder::new();

        builder.add_master_key(alias, author)?;
        builder.rotate_shared_key(rng, passphrase)?;

        builder.finalize(author)
    }

    pub(crate) fn new(block: Block) -> Result<Self, PassportError> {
        let ledger = Ledger::new(block.as_slice())?;
        let blockchain = vec![block];

        Ok(Self { blockchain, ledger })
    }

    pub fn as_mut(&mut self) -> PassportMut<'_> {
        PassportMut::new(self)
    }

    pub fn into_light_passport(self) -> LightPassport {
        LightPassport(self.ledger)
    }

    /// get the `Passport` shared key
    ///
    /// This key is a key that all the master keys are aware of and can
    /// be used. Every time a master key is added or removed, a new key
    /// is generated. Please use the most recent version, otherwise the
    /// recipient may not see the new keys
    pub fn shared_key(&self) -> Option<&(Time, PublicKey)> {
        self.ledger.shared_key()
    }

    /// access the shared key (associated to the public key given in parameter) with
    /// the master key and passphrase.
    ///
    /// This function will go through every entries of every block and will attempt to
    /// decode any keys that matches the given parameters, stopping at the first successful
    /// decrypt.
    ///
    pub fn unshield_shared_key(
        &self,
        shared_key: &PublicKey,
        master_key: &ed25519::SecretKey,
        passphrase: Seed,
    ) -> Result<curve25519::SecretKey, PassportError> {
        let passphrase = Some(passphrase);
        for entry in self
            .blockchain
            .iter()
            .rev()
            .map(|b| b.content().iter())
            .flatten()
        {
            let pub_key = master_key.public_key();
            if let Some(entry) = entry.set_shared_key() {
                if &entry.key() == shared_key {
                    let msg = entry.messages().find_map(|(index, msg)| {
                        if index == &pub_key.as_ref()[..8] {
                            Some(msg)
                        } else {
                            None
                        }
                    });

                    if let Some(msg) = msg {
                        let n = N::<ed25519::SecretKey, Blake2b, _>::new((), &passphrase, &[]);
                        let key = n.receive(&master_key, msg)?;

                        let key = curve25519::SecretKey::try_from(key.as_ref())?;

                        return Ok(key);
                    }
                }
            }
        }

        Err(PassportError::NoSharedKeyFound)
    }

    pub fn blocks(&self) -> &[Block] {
        self.blockchain.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_passport() {
        let mut rng = Seed::from([0; 32]).into_rand_chacha();

        let author = ed25519::SecretKey::new(&mut rng);
        let passphrase = Seed::generate(&mut rng);
        let alias = "device1";

        let passport = Passport::create(&mut rng, alias, &author, passphrase.clone())
            .expect("Create a valid passport");
        let (_, pub_key) = passport.shared_key().expect("should always be true");

        let shared_key = passport
            .unshield_shared_key(pub_key, &author, passphrase)
            .expect("Decode the key");

        assert_eq!(pub_key, &shared_key.public_key());
    }

    #[test]
    #[should_panic]
    fn remove_last_master_key() {
        let mut rng = Seed::from([0; 32]).into_rand_chacha();

        let author = ed25519::SecretKey::new(&mut rng);
        let passphrase = Seed::generate(&mut rng);
        let alias = "device1";

        let mut passport = Passport::create(&mut rng, alias, &author, passphrase.clone())
            .expect("Create a valid passport");
        let (_, pub_key) = passport.shared_key().expect("should always be true");

        let shared_key = passport
            .unshield_shared_key(pub_key, &author, passphrase)
            .expect("Decode the key");

        assert_eq!(pub_key, &shared_key.public_key());

        passport
            .as_mut()
            .remove_master_key(&author.public_key())
            .unwrap();
    }
}
