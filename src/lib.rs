//! Axfood-family (Willys, Hemköp) receipts via BankID, as a `ReceiptSource`.
//!
//! Uses undocumented endpoints, confirmed identical (same Hybris backend)
//! across both chains' domains, and will break when Axfood redesigns. That
//! is expected: raw responses are archived before parsing, so a break costs
//! a parser rewrite, never data.

pub mod auth;
pub mod browser_auth;
pub mod chain;
pub mod client;
pub mod endpoints;
pub mod parse;
pub mod session;
pub mod source;

pub use chain::Chain;
pub use session::AxfoodSession;
pub use source::AxfoodSource;
