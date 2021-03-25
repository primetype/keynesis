use crate::{
    key::{curve25519, ed25519},
    passport::{
        block::{self, BlockMut, EntryMut, EntrySlice, Hash},
        Ledger, Passport, PassportError,
    },
    Seed,
};
use rand_core::{CryptoRng, RngCore};

#[derive(Default)]
pub struct PassportBuilder {
    block: BlockMut,
    keys: Vec<ed25519::PublicKey>,
}

pub struct PassportMut<'a> {
    passport: &'a mut Passport,
    ledger: Ledger,
    block: BlockMut,
}

impl PassportBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// push a raw entry in the passport
    pub fn push(&mut self, entry: EntrySlice) -> Result<(), PassportError> {
        self.block.push(entry)?;

        Ok(())
    }

    /// rotate the shared key
    ///
    /// create and add a new entry that create a new shared key and rotate it to every
    /// of the registered master key (including the one that have just been added in)
    /// the current process of creating this block.
    ///
    /// If you add more entries to register master keys in this block, they will not
    /// be able to retrieve the shared key. If you deregister a master key after
    /// rotating the shared key, they will still have access to the master key
    /// (so long they have the passphrase).
    ///
    pub fn rotate_shared_key<RNG>(
        &mut self,
        mut rng: RNG,
        passphrase: Seed,
    ) -> Result<(), PassportError>
    where
        RNG: CryptoRng + RngCore,
    {
        let new_key = curve25519::SecretKey::new(&mut rng);
        let mut entry = Vec::with_capacity(256);
        let mut entry = EntryMut::new_set_shared_key(&mut entry, &new_key.public_key());
        let passphrase = Some(passphrase);
        for key in self.keys.iter() {
            entry.share_with(&mut rng, &new_key, key, &passphrase)?;
        }
        let entry = entry.finalize()?;
        self.push(entry)
    }

    /// add a master key to the passport
    ///
    /// This function will automatically rotate the shared key and encrypt
    /// the secret key to all the master keys of the passport.
    ///
    pub fn add_master_key(
        &mut self,
        alias: &str,
        master_key: &ed25519::SecretKey,
    ) -> Result<(), PassportError> {
        let mut entry = vec![0; block::EntryType::RegisterMasterKey.size(&[])];
        let entry = EntryMut::new_register_master_key(&mut entry, alias, Hash::ZERO)?;
        let entry = entry.finalize(master_key);
        self.keys.push(master_key.public_key());
        self.push(entry)
    }

    pub fn finalize(self, author: &ed25519::SecretKey) -> Result<Passport, PassportError> {
        let Self { mut block, .. } = self;

        block.version(block::Version::CURRENT);
        block.time(block::Time::now());
        block.previous(&block::Previous::None);

        let block = block.finalize(author);

        Passport::new(block.as_slice())
    }
}

impl<'a> PassportMut<'a> {
    pub fn new(passport: &'a mut Passport) -> Self {
        let ledger = passport.ledger.clone();
        let block = BlockMut::new();

        Self {
            passport,
            ledger,
            block,
        }
    }

    /// push a raw entry in the passport
    pub fn push(&mut self, entry: EntrySlice) -> Result<(), PassportError> {
        self.ledger.apply_entry(entry)?;
        self.block.push(entry)?;

        Ok(())
    }

    /// remove a master key from the passport
    ///
    /// when using this, don't forget to rotate the shared key, otherwise
    /// this key will still have access to the shared key (so long they have
    /// the passphrase)
    pub fn remove_master_key(
        &mut self,
        master_key: &ed25519::PublicKey,
    ) -> Result<(), PassportError> {
        let mut entry = vec![0; block::EntryType::DeregisterMasterKey.size(&[])];
        let entry = EntryMut::new_deregister_master_key(&mut entry, master_key);
        let entry = entry.finalize();

        self.push(entry)
    }

    /// rotate the shared key
    ///
    /// create and add a new entry that create a new shared key and rotate it to every
    /// of the registered master key (including the one that have just been added in)
    /// the current process of creating this block.
    ///
    /// If you add more entries to register master keys in this block, they will not
    /// be able to retrieve the shared key. If you deregister a master key after
    /// rotating the shared key, they will still have access to the master key
    /// (so long they have the passphrase).
    ///
    pub fn rotate_shared_key<RNG>(
        &mut self,
        mut rng: RNG,
        passphrase: Seed,
    ) -> Result<(), PassportError>
    where
        RNG: CryptoRng + RngCore,
    {
        let new_key = curve25519::SecretKey::new(&mut rng);
        let mut entry = Vec::with_capacity(256);
        let mut entry = EntryMut::new_set_shared_key(&mut entry, &new_key.public_key());
        let passphrase = Some(passphrase);
        for key in self.ledger.active_master_keys() {
            entry.share_with(&mut rng, &new_key, key, &passphrase)?;
        }
        let entry = entry.finalize()?;
        self.push(entry)
    }

    pub fn finalize(self, author: &ed25519::SecretKey) -> Result<&'a mut Passport, PassportError> {
        let Self {
            passport,
            mut block,
            ledger: _,
        } = self;

        block.version(block::Version::CURRENT);
        block.time(block::Time::now());
        block.previous(&block::Previous::Previous(passport.ledger.hash()));

        let block = block.finalize(author);

        let ledger = passport.ledger.apply(block.as_slice())?;

        passport.ledger = ledger;
        passport.blockchain.push(block.as_slice());

        Ok(passport)
    }
}
