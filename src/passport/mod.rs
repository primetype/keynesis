/*!
Identity passport, this is the set of keys that can be used to
authenticate a user. The passport is managed by the owner of the
associated keys only. Making it a permission blockchain.

*/

pub mod block;
pub mod ledger;

use self::{
    block::{Block, BlockMut, Time},
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
use block::EntryMut;
use cryptoxide::blake2b::Blake2b;
use rand_core::{CryptoRng, RngCore};
use std::{convert::TryFrom as _, vec};
use thiserror::Error;

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
        let mut block = BlockMut::new();
        block.version(block::Version::CURRENT);
        block.time(block::Time::now());
        block.previous(&block::Previous::None);

        // set alias to the block's author
        {
            let mut entry = vec![0; block::EntryType::RegisterMasterKey.size(&[])];
            let entry = EntryMut::new_register_master_key(&mut entry, alias)?;
            let entry = entry.finalize(author);
            block.push(entry)?;
        }

        // create entry with new shared secret key
        {
            let new_key = curve25519::SecretKey::new(rng);
            let mut entry = Vec::with_capacity(256);
            let mut entry = EntryMut::new_set_shared_key(&mut entry, &new_key.public_key());
            entry.share_with(rng, &new_key, &author.public_key(), &Some(passphrase))?;
            let entry = entry.finalize()?;
            block.push(entry)?;
        }

        // finalize the block
        let block = block.finalize(author);

        let ledger = Ledger::new(block.as_slice())?;
        let blockchain = vec![block];

        Ok(Self { blockchain, ledger })
    }

    /// remove a `master_key`
    ///
    /// This function removes the master key from the `master_key` set. Meaning
    /// no block will be allowed to be created from this `master_key` again.
    /// the `shared_key` will be rotated too, excluding the `master_key` from
    /// the recipient list
    pub fn remove_master_key<RNG>(
        &mut self,
        rng: &mut RNG,
        author: &ed25519::SecretKey,
        master_key: &ed25519::PublicKey,
        passphrase: Seed,
    ) -> Result<&Block, PassportError>
    where
        RNG: CryptoRng + RngCore,
    {
        let mut block = BlockMut::new();
        block.version(block::Version::CURRENT);
        block.time(block::Time::now());
        block.previous(&block::Previous::Previous(self.ledger.hash()));

        // set alias to the block's author
        {
            let mut entry = vec![0; block::EntryType::DeregisterMasterKey.size(&[])];
            let entry = EntryMut::new_deregister_master_key(&mut entry, master_key);
            let entry = entry.finalize(author);
            block.push(entry)?;
        }

        let entry = self.rotate_shared_key_(
            rng,
            passphrase,
            self.ledger
                .active_master_keys()
                .iter()
                .map(|k| k.as_ref())
                // make sure the master_key we are removing is not one
                // of the key we are going to share the `shared_key` with
                .filter(|pk| *pk != master_key),
        )?;
        block.push(entry.as_slice())?;

        let block = block.finalize(author);

        self.ledger = self.ledger.apply(block.as_slice())?;
        self.blockchain.push(block);

        Ok(self.blockchain.last().expect("we just added a block"))
    }

    /// add a master key to the passport
    ///
    /// This function will automatically rotate the shared key and encrypt
    /// the secret key to all the master keys of the passport.
    ///
    pub fn add_master_key<RNG>(
        &mut self,
        rng: &mut RNG,
        author: &ed25519::SecretKey,

        // todo: only wants the registration entry here, not the secret key
        master_key: &ed25519::SecretKey,
        alias: &str,
        passphrase: Seed,
    ) -> Result<&Block, PassportError>
    where
        RNG: CryptoRng + RngCore,
    {
        let mut block = BlockMut::new();
        block.version(block::Version::CURRENT);
        block.time(block::Time::now());
        block.previous(&block::Previous::Previous(self.ledger.hash()));

        // set alias to the block's author
        {
            let mut entry = vec![0; block::EntryType::RegisterMasterKey.size(&[])];
            let entry = EntryMut::new_register_master_key(&mut entry, alias)?;
            let entry = entry.finalize(master_key);
            block.push(entry)?;
        }

        let entry = self.rotate_shared_key_(
            rng,
            passphrase,
            self.ledger
                .active_master_keys()
                .iter()
                .map(|k| k.as_ref())
                // include the newly added master key in the set of key to share
                // the new shared key with
                .chain(std::iter::once(&master_key.public_key())),
        )?;
        block.push(entry.as_slice())?;

        let block = block.finalize(author);

        self.ledger = self.ledger.apply(block.as_slice())?;
        self.blockchain.push(block);

        Ok(self.blockchain.last().expect("we just added a block"))
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

    /// force rotating the shared secret key
    ///
    /// Event though we might not add/remove master keys, after a certain
    /// time it might be worth considering rotating the shared key.
    ///
    pub fn rotate_shared_key<RNG>(
        &mut self,
        rng: &mut RNG,
        author: &ed25519::SecretKey,
        passphrase: Seed,
    ) -> Result<&Block, PassportError>
    where
        RNG: CryptoRng + RngCore,
    {
        let mut block = BlockMut::new();
        block.version(block::Version::CURRENT);
        block.time(block::Time::now());
        block.previous(&block::Previous::Previous(self.ledger.hash()));

        let entry = self.rotate_shared_key_(
            rng,
            passphrase,
            self.ledger.active_master_keys().iter().map(|k| k.as_ref()),
        )?;
        block.push(entry.as_slice())?;

        let block = block.finalize(author);

        self.ledger = self.ledger.apply(block.as_slice())?;
        self.blockchain.push(block);

        Ok(self.blockchain.last().expect("we just added a block"))
    }

    fn rotate_shared_key_<'a, RNG>(
        &'a self,
        rng: &mut RNG,
        passphrase: Seed,
        keys: impl Iterator<Item = &'a PublicKey>,
    ) -> Result<block::Entry, PassportError>
    where
        RNG: CryptoRng + RngCore,
    {
        let new_key = curve25519::SecretKey::new(rng);
        let mut entry = Vec::with_capacity(256);
        let mut entry = EntryMut::new_set_shared_key(&mut entry, &new_key.public_key());
        let passphrase = Some(passphrase);
        for key in keys {
            //self.ledger.active_master_keys().iter() {
            entry.share_with(rng, &new_key, key, &passphrase)?;
        }
        let entry = entry.finalize()?;
        Ok(entry.to_entry())
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
            .unshield_shared_key(pub_key, &author, passphrase.clone())
            .expect("Decode the key");

        assert_eq!(pub_key, &shared_key.public_key());

        passport
            .remove_master_key(&mut rng, &author, &author.public_key(), passphrase)
            .unwrap();

        assert!(passport.ledger.active_master_keys().is_empty());
    }

    #[test]
    fn remove_master_key() {
        let mut rng = Seed::from([0; 32]).into_rand_chacha();

        let author = ed25519::SecretKey::new(&mut rng);
        let passphrase = Seed::generate(&mut rng);
        let alias = "device1";

        let mut passport = Passport::create(&mut rng, alias, &author, passphrase.clone())
            .expect("Create a valid passport");
        let (_, pub_key) = passport.shared_key().expect("should always be true");

        let shared_key = passport
            .unshield_shared_key(pub_key, &author, passphrase.clone())
            .expect("Decode the key");

        assert_eq!(pub_key, &shared_key.public_key());

        let author2 = ed25519::SecretKey::new(&mut rng);
        passport
            .add_master_key(&mut rng, &author, &author2, "device2", passphrase.clone())
            .unwrap();

        passport
            .remove_master_key(&mut rng, &author, &author.public_key(), passphrase)
            .unwrap();

        assert!(passport
            .ledger
            .active_master_keys()
            .contains(&author2.public_key()));
    }
}
