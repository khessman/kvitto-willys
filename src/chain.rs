//! What varies between Axfood chains — everything else (endpoint paths,
//! BankID flow, CSRF handling) is confirmed identical across `willys.se` and
//! `hemkop.se`: same Hybris instance, same `/axfood/rest/...` contract, same
//! `csrf.badormissing` shape. Only the domain, cookie scope and receipt
//! defaults differ.

use kvitto_core::{SourceId, HEMKOP, WILLYS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Willys,
    Hemkop,
}

impl Chain {
    pub fn base(&self) -> &'static str {
        match self {
            Chain::Willys => "https://www.willys.se",
            Chain::Hemkop => "https://www.hemkop.se",
        }
    }

    pub fn source_id(&self) -> SourceId {
        match self {
            Chain::Willys => WILLYS,
            Chain::Hemkop => HEMKOP,
        }
    }

    /// Substring match against a `Set-Cookie` domain, so cookies from the
    /// wrong Axfood-family site never leak into this chain's session.
    pub fn cookie_domain(&self) -> &'static str {
        match self {
            Chain::Willys => "willys.se",
            Chain::Hemkop => "hemkop.se",
        }
    }

    /// Fallback store name when a receipt's own header line is missing.
    pub fn default_store_name(&self) -> &'static str {
        match self {
            Chain::Willys => "Willys",
            Chain::Hemkop => "Hemköp",
        }
    }
}
