//! Willys receipts via BankID, as a `ReceiptSource`.
//!
//! Uses undocumented endpoints on willys.se and will break when they redesign.
//! That is expected: raw responses are archived before parsing, so a break
//! costs a parser rewrite, never data.

pub mod auth;
pub mod browser_auth;
pub mod client;
pub mod endpoints;
pub mod parse;
pub mod session;
pub mod source;

pub use session::WillysSession;
pub use source::Willys;
