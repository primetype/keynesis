use crate::{
    key::ed25519::PublicKey,
    passport::block::{
        entry::{DeregisterMasterKeySlice, RegisterMasterKeySlice},
        BlockSlice, ContentSlice, Hash, HeaderSlice, Previous, Time,
    },
};
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Ledger {
    on_block: Hash,
    at_time: Time,
    active_master_keys: BTreeSet<PublicKey>,
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

    #[error("Cannot deregister a master key that is not active")]
    CannotDeregisterMasterKey,

    #[error("The master key was already set")]
    MasterKeyAlreadySet,
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
    pub fn new(block: &BlockSlice<'_>) -> Result<Self, LedgerError> {
        let header = block.header();
        let mut ledger = Self {
            on_block: header.hash(),
            at_time: header.time(),
            active_master_keys: BTreeSet::new(),
        };

        ledger.active_master_keys.insert(header.author());

        ledger.apply_content(block.content())?;

        Ok(ledger)
    }

    /// get the tip of the Ledger. this is the state of the ledger
    /// at the given block's hash
    pub fn hash(&self) -> Hash {
        self.on_block
    }

    /// get the time that was associated to the block
    pub fn time(&self) -> Time {
        self.at_time
    }

    /// get the list of active master keys
    pub fn active_master_keys(&self) -> &BTreeSet<PublicKey> {
        &self.active_master_keys
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

    fn apply_header(&self, header: HeaderSlice<'_>) -> Result<Self, LedgerError> {
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
        ledger.at_time = header.time();
        Ok(ledger)
    }

    fn apply_content(&mut self, content: ContentSlice<'_>) -> Result<(), LedgerError> {
        for entry in content {
            if let Some(master_key) = entry.register_master_key() {
                self.apply_register_master_key(master_key)?
            } else if let Some(deregister) = entry.deregister_master_key() {
                self.apply_deregister_master_key(deregister)?
            }
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

        if self.active_master_keys.insert(entry.key()) {
            return Err(LedgerError::MasterKeyAlreadySet);
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
        if !self.active_master_keys.contains(&entry.author()) {
            return Err(LedgerError::PrivilegeError);
        }

        if self.active_master_keys.remove(&entry.key()) {
            Ok(())
        } else {
            Err(LedgerError::CannotDeregisterMasterKey)
        }
    }
}
