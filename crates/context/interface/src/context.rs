//! Context trait and related types.
pub use crate::journaled_state::StateLoad;
use crate::{
    result::FromStringError, Block, Cfg, Database, Host, JournalTr, LocalContextTr, Transaction,
};
use auto_impl::auto_impl;
use primitives::StorageValue;
use std::string::String;

/// Trait that defines the context of the EVM execution.
///
/// This trait is used to access the environment and state of the EVM.
/// It is used to access the transaction, block, configuration, database, journal, and chain.
/// It is also used to set the error of the EVM.
///
/// All function has a `*_mut` variant except the function for [`ContextTr::tx`] and [`ContextTr::block`].
#[auto_impl(&mut, Box)]
pub trait ContextTr: Host {
    /// Block type
    type Block: Block;
    /// Transaction type
    type Tx: Transaction;
    /// Configuration type
    type Cfg: Cfg;
    /// Database type
    type Db: Database;
    /// Journal type
    type Journal: JournalTr<Database = Self::Db>;
    /// Chain type
    type Chain;
    /// Local context type
    type Local: LocalContextTr;

    /// Get the transaction
    fn tx(&self) -> &Self::Tx;
    /// Get the block
    fn block(&self) -> &Self::Block;
    /// Get the configuration
    fn cfg(&self) -> &Self::Cfg;
    /// Get the journal
    fn journal(&self) -> &Self::Journal;
    /// Get the journal mutably
    fn journal_mut(&mut self) -> &mut Self::Journal;
    /// Get the journal reference
    fn journal_ref(&self) -> &Self::Journal {
        self.journal()
    }
    /// Get the database
    fn db(&self) -> &Self::Db;
    /// Get the database mutably
    fn db_mut(&mut self) -> &mut Self::Db;
    /// Get the database reference
    fn db_ref(&self) -> &Self::Db {
        self.db()
    }
    /// Get the chain
    fn chain(&self) -> &Self::Chain;
    /// Get the chain mutably
    fn chain_mut(&mut self) -> &mut Self::Chain;
    /// Get the chain reference
    fn chain_ref(&self) -> &Self::Chain {
        self.chain()
    }
    /// Get the local context
    fn local(&self) -> &Self::Local;
    /// Get the local context mutably
    fn local_mut(&mut self) -> &mut Self::Local;
    /// Get the local context reference
    fn local_ref(&self) -> &Self::Local {
        self.local()
    }
    /// Get the error
    fn error(&mut self) -> &mut Result<(), ContextError<<Self::Db as Database>::Error>>;
    /// Get the transaction and journal. It is used to efficiently load access list
    /// into journal without copying them from transaction.
    fn tx_journal_mut(&mut self) -> (&Self::Tx, &mut Self::Journal);
    /// Get the transaction and local context. It is used to efficiently load initcode
    /// into local context without copying them from transaction.
    fn tx_local_mut(&mut self) -> (&Self::Tx, &mut Self::Local);
}

/// Inner Context error used for Interpreter to set error without returning it frm instruction
#[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ContextError<DbError> {
    /// Database error.
    Db(DbError),
    /// Custom string error.
    Custom(String),
}

impl<DbError> FromStringError for ContextError<DbError> {
    fn from_string(value: String) -> Self {
        Self::Custom(value)
    }
}

impl<DbError> From<DbError> for ContextError<DbError> {
    fn from(value: DbError) -> Self {
        Self::Db(value)
    }
}

/// Represents the result of an `sstore` operation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SStoreResult {
    /// Value of the storage when it is first read
    pub original_value: StorageValue,
    /// Current value of the storage
    pub present_value: StorageValue,
    /// New value that is set
    pub new_value: StorageValue,
}

impl SStoreResult {
    /// Returns `true` if the new value is equal to the present value.
    #[inline]
    pub fn is_new_eq_present(&self) -> bool {
        self.new_value == self.present_value
    }

    /// Returns `true` if the original value is equal to the present value.
    #[inline]
    pub fn is_original_eq_present(&self) -> bool {
        self.original_value == self.present_value
    }

    /// Returns `true` if the original value is equal to the new value.
    #[inline]
    pub fn is_original_eq_new(&self) -> bool {
        self.original_value == self.new_value
    }

    /// Returns `true` if the original value is zero.
    #[inline]
    pub fn is_original_zero(&self) -> bool {
        self.original_value.is_zero()
    }

    /// Returns `true` if the present value is zero.
    #[inline]
    pub fn is_present_zero(&self) -> bool {
        self.present_value.is_zero()
    }

    /// Returns `true` if the new value is zero.
    #[inline]
    pub fn is_new_zero(&self) -> bool {
        self.new_value.is_zero()
    }
}

/// Result of a selfdestruct action
///
/// Value returned are needed to calculate the gas spent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SelfDestructResult {
    /// Whether the account had a value.
    pub had_value: bool,
    /// Whether the target account exists.
    pub target_exists: bool,
    /// Whether the account was previously destroyed.
    pub previously_destroyed: bool,
}

/// Trait for setting the transaction and block in the context.
pub trait ContextSetters: ContextTr {
    /// Set the transaction
    fn set_tx(&mut self, tx: Self::Tx);
    /// Set the block
    fn set_block(&mut self, block: Self::Block);
}
