use crate::{
    key::ed25519::PublicKey,
    passport::block::{
        entry::{DeregisterMasterKeySlice, RegisterMasterKeySlice, SetSharedKeySlice},
        BlockSlice, ContentSlice, EntrySlice, Hash, HeaderSlice, Previous, Time,
    },
};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Ledger {
    on_block: Hash,
    on_author: PublicKey,
    id: Hash,
    at_time: Time,
    active_master_keys: HashSet<Arc<PublicKey>>,
    active_master_keys_by_alias: BTreeMap<String, Arc<PublicKey>>,
    shared_key: Option<(Time, PublicKey)>,
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("Cannot apply the block, previous hash does not match the state of the ledger")]
    PreviousHashMisMatch,

    #[error("The block author is not authorized to update the ledger")]
    PrivilegeError,

    #[error("Invalid entry time")]
    InvalidEntryTime,

    #[error("Cannot register a master key after it had timedout")]
    CannotRegisterMasterKeyPassedRegistrationTimeout,

    #[error("Cannot register master key on a different passport")]
    CannotRegisterMasterKeyWrongPassportId,

    #[error("Cannot deregister a master key that is not active")]
    CannotDeregisterMasterKey,

    #[error("The master key was already set")]
    MasterKeyAlreadySet,

    #[error("The master key's alias was already set")]
    MasterKeyAliasAlreadySet,
}

impl Ledger {
    /// create a new ledger from the given block. The author of the block
    /// is automatically registered as a master key
    ///
    /// By design it is possible to have initial block content in the first block
    /// so it is possible to add more extra data/entries in the block when creating
    /// the `Passport` for the first time.
    ///
    /// # Errors
    ///
    /// If the block has a `Previous`, this function will error.
    /// if the block content's does not apply successfully it will error.
    ///
    pub fn new(block: BlockSlice<'_>) -> Result<Self, LedgerError> {
        let header = block.header();
        let mut ledger = Self {
            on_block: header.hash(),
            on_author: header.author(),
            id: header.hash(),
            at_time: header.time(),
            active_master_keys: HashSet::new(),
            active_master_keys_by_alias: BTreeMap::new(),
            shared_key: None,
        };

        ledger.apply_content(block.content())?;

        if !ledger.active_master_keys().contains(&header.author()) {
            unimplemented!()
        }

        Ok(ledger)
    }

    /// get the tip of the Ledger. this is the state of the ledger
    /// at the given block's hash
    pub fn hash(&self) -> Hash {
        self.on_block
    }

    /// the unique identifier of the passport (the first block's ID)
    pub fn id(&self) -> Hash {
        self.id
    }

    /// get the time that was associated to the block
    pub fn time(&self) -> Time {
        self.at_time
    }

    /// get the list of active master keys
    pub fn active_master_keys(&self) -> &HashSet<Arc<PublicKey>> {
        &self.active_master_keys
    }

    /// get the
    pub fn shared_key(&self) -> Option<&(Time, PublicKey)> {
        self.shared_key.as_ref()
    }

    /// apply the given block to the `Ledger`
    ///
    /// This function does not modify the current state of the ledger but
    /// instead creates a new one on success.
    pub fn apply(&self, block: BlockSlice<'_>) -> Result<Self, LedgerError> {
        let mut ledger = self.apply_header(block.header())?;

        ledger.apply_content(block.content())?;

        Ok(ledger)
    }

    pub(crate) fn apply_header(&self, header: HeaderSlice<'_>) -> Result<Self, LedgerError> {
        if let Previous::Previous(previous) = header.previous() {
            if previous != self.on_block {
                return Err(LedgerError::PreviousHashMisMatch);
            }
        } else {
            return Err(LedgerError::PreviousHashMisMatch);
        }

        if !self.active_master_keys.contains(&header.author()) {
            return Err(LedgerError::PrivilegeError);
        }

        let mut ledger = self.clone();
        ledger.on_block = header.hash();
        ledger.on_author = header.author();
        ledger.at_time = header.time();
        Ok(ledger)
    }

    fn apply_content(&mut self, content: ContentSlice<'_>) -> Result<(), LedgerError> {
        for entry in content {
            self.apply_entry(entry)?;
        }

        Ok(())
    }

    pub(crate) fn apply_entry(&mut self, entry: EntrySlice) -> Result<(), LedgerError> {
        if let Some(master_key) = entry.register_master_key() {
            self.apply_register_master_key(master_key)?
        } else if let Some(deregister) = entry.deregister_master_key() {
            self.apply_deregister_master_key(deregister)?
        } else if let Some(shared_key) = entry.set_shared_key() {
            self.apply_shared_key(shared_key)?
        } else {
            unimplemented!()
        }

        Ok(())
    }

    fn apply_register_master_key(
        &mut self,
        entry: RegisterMasterKeySlice<'_>,
    ) -> Result<(), LedgerError> {
        if self.at_time < entry.created_at() {
            return Err(LedgerError::InvalidEntryTime);
        }
        if self.at_time > entry.registration_timeout() {
            return Err(LedgerError::CannotRegisterMasterKeyPassedRegistrationTimeout);
        }

        // if the author of the block is the same as the author of the entry
        //
        // * this way we prevent passport being created with master key from other passport
        //   (they need to sign something with a private key too)
        // * otherwise passport's ID needs to match the one referenced in the entry
        //   so no one can just replay the entry in a random passport
        if self.on_author != entry.key() && self.id != entry.passport() {
            return Err(LedgerError::CannotRegisterMasterKeyWrongPassportId);
        }

        let key = Arc::new(entry.key());

        if !self.active_master_keys.insert(Arc::clone(&key)) {
            return Err(LedgerError::MasterKeyAlreadySet);
        }
        if self
            .active_master_keys_by_alias
            .insert(entry.alias().into_owned(), key)
            .is_some()
        {
            return Err(LedgerError::MasterKeyAliasAlreadySet);
        }

        Ok(())
    }

    fn apply_deregister_master_key(
        &mut self,
        entry: DeregisterMasterKeySlice<'_>,
    ) -> Result<(), LedgerError> {
        if self.at_time < entry.created_at() {
            return Err(LedgerError::InvalidEntryTime);
        }

        if self.active_master_keys.remove(&entry.key()) {
            if self.active_master_keys.is_empty() {
                Err(LedgerError::CannotDeregisterMasterKey)
            } else {
                Ok(())
            }
        } else {
            Err(LedgerError::CannotDeregisterMasterKey)
        }
    }

    fn apply_shared_key(&mut self, entry: SetSharedKeySlice<'_>) -> Result<(), LedgerError> {
        if self.at_time < entry.created_at() {
            return Err(LedgerError::InvalidEntryTime);
        }

        let key = entry.key();
        let time = entry.created_at();

        self.shared_key = Some((time, key));

        Ok(())
    }
}
