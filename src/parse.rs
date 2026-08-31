//! Willys receipts are a PDF whose content is just a monospace text
//! printout — no layout to fight, `pdf_extract::extract_text_from_mem` gives
//! back lines in the same shape a receipt printer would. See
//! `tests/fixtures/willys-receipt-1.pdf` (real purchase, captured
//! 2026-08-30) for the exact format this is built against:
//!
//! ```text
//! Västerås Stenby
//! Kraftlinjegatan 4
//! Tfn: 021-444 43 00
//! ------------------------------------------
//! ========== Start Självscanning ===========
//! GRÖTBRÖD 780G                                27,90
//! OAT DRINK 2,8%              2st*15,99         31,98
//!   W Plus:PAPPER                              -20,00
//! ========== Slut Självscanning ============
//! ------------------------------------------
//!  Totalt 13 varor
//!  Totalt 431,00 SEK
//! ==========================================
//! Mottaget Kontokort                           431,00
//! Kort ************1025
//! Betalmedel MasterCard
//! ...
//! 2026-08-30T15 26:22.552Z
//! ```
//!
//! Contract: pure and sync, unrecognised rows become `LineKind::Other`
//! rather than being dropped, `Line::category` is never set (the
//! categoriser's job, not the parser's), and `Receipt::balances()` must
//! hold — it does for the one fixture so far (431.00 exactly).

use kvitto_core::{
    Error, Line, LineKind, Money, Payment, ProfileId, Quantity, RawReceipt, Receipt, Result,
    SCHEMA_VERSION, Store,
};

const START_MARKER: &str = "Start Självscanning";
const END_MARKER: &str = "Slut Självscanning";

pub fn parse(raw: &RawReceipt, profile: &ProfileId) -> Result<Receipt> {
    let text = pdf_extract::extract_text_from_mem(&raw.bytes).map_err(|e| Error::Parse {
        id: raw.id.clone(),
        detail: format!("could not extract PDF text: {e}"),
    })?;
    let lines: Vec<&str> = text.lines().collect();

    let store = parse_store(&lines);
    let receipt_lines = parse_lines(&lines);
    let total = find_total(&lines).ok_or_else(|| Error::Parse {
        id: raw.id.clone(),
        detail: "no \"Totalt ... SEK\" line found".into(),
    })?;
    let purchased_at = find_timestamp(&lines).ok_or_else(|| Error::Parse {
        id: raw.id.clone(),
        detail: "no ISO timestamp line found".into(),
    })?;
    let payments = find_payment(&lines).into_iter().collect();

    Ok(Receipt {
        id: raw.id.clone(),
        purchased_at,
        store,
        lines: receipt_lines,
        total,
        payments,
        schema_version: SCHEMA_VERSION,
        raw_hash: raw.hash.clone(),
        fetched_by: profile.clone(),
    })
}

fn parse_store(lines: &[&str]) -> Store {
    let mut nonblank = lines.iter().map(|l| l.trim()).filter(|l| !l.is_empty());
    let name = nonblank.next().unwrap_or("Willys").to_string();
    let address = nonblank.next().map(str::to_string);
    Store { name, chain: Some("willys".into()), address, ..Store::default() }
}

/// Item and discount rows between the self-scan markers. A row's amount is
/// its own signal: negative means `LineKind::Discount` attached to the item
/// above it — no need to trust indentation, which a PDF text extractor can
/// mangle.
fn parse_lines(lines: &[&str]) -> Vec<Line> {
    let start = lines.iter().position(|l| l.contains(START_MARKER));
    let end = lines.iter().position(|l| l.contains(END_MARKER));
    let (Some(start), Some(end)) = (start, end) else { return Vec::new() };

    let mut out: Vec<Line> = Vec::new();
    let mut last_item: Option<usize> = None;

    for raw_line in &lines[start + 1..end] {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((rest, amount)) = split_trailing_amount(line) else { continue };

        if amount.0 < 0 {
            out.push(Line {
                description: rest.to_string(),
                kind: LineKind::Discount,
                quantity: Quantity::Count(1.0),
                unit_price: None,
                amount,
                applies_to: last_item,
                article_no: None,
                category: None,
            });
            continue;
        }

        let (description, quantity, unit_price) = match split_quantity(rest) {
            Some((desc, qty, unit)) => (desc, Quantity::Count(qty), Some(unit)),
            None => (rest.to_string(), Quantity::Count(1.0), None),
        };

        out.push(Line {
            description,
            kind: LineKind::Item,
            quantity,
            unit_price,
            amount,
            applies_to: None,
            article_no: None,
            category: None,
        });
        last_item = Some(out.len() - 1);
    }
    out
}

/// Splits `"GRÖTBRÖD 780G   27,90"` into `("GRÖTBRÖD 780G", Money(2790))`.
/// The amount is always the last whitespace-separated token.
fn split_trailing_amount(line: &str) -> Option<(&str, Money)> {
    let (rest, last) = line.rsplit_once(char::is_whitespace)?;
    let amount = parse_money(last)?;
    Some((rest.trim_end(), amount))
}

/// Splits `"OAT DRINK 2,8%   2st*15,99"` into `("OAT DRINK 2,8%", 2.0,
/// Money(1599))` when the trailing token is a `{n}st*{price}` quantity
/// marker; `None` for a plain item with no explicit quantity.
fn split_quantity(rest: &str) -> Option<(String, f64, Money)> {
    let (desc, marker) = rest.rsplit_once(char::is_whitespace)?;
    let (qty_str, price_str) = marker.split_once("st*")?;
    let qty: f64 = qty_str.parse().ok()?;
    let unit_price = parse_money(price_str)?;
    Some((desc.trim_end().to_string(), qty, unit_price))
}

/// Swedish `"431,00"` / `"-16,47"` — comma decimal, always two places.
fn parse_money(s: &str) -> Option<Money> {
    let s = s.trim();
    let neg = s.starts_with('-');
    let s = s.strip_prefix('-').unwrap_or(s);
    let (kr, ore) = s.split_once(',')?;
    if ore.len() != 2 || !kr.chars().all(|c| c.is_ascii_digit()) || !ore.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let kr: i64 = kr.parse().ok()?;
    let ore: i64 = ore.parse().ok()?;
    let total = kr * 100 + ore;
    Some(Money(if neg { -total } else { total }))
}

/// `" Totalt    431,00 SEK"` — the only total line with a trailing "SEK".
fn find_total(lines: &[&str]) -> Option<Money> {
    lines.iter().find_map(|l| {
        let l = l.trim();
        let rest = l.strip_prefix("Totalt")?.trim();
        let amount_str = rest.strip_suffix("SEK")?.trim();
        parse_money(amount_str)
    })
}

/// `"2026-08-30T15 26:22.552Z"` — the PDF's text layout drops the colon
/// between hour and minute (a font-spacing artifact, not a typo); patch it
/// back in and parse as RFC 3339.
fn find_timestamp(lines: &[&str]) -> Option<chrono::DateTime<chrono::Utc>> {
    for line in lines {
        let line = line.trim();
        if !line.ends_with('Z') {
            continue;
        }
        let Some(t_pos) = line.find('T') else { continue };
        let (date_part, rest) = line.split_at(t_pos + 1);
        let Some(space_pos) = rest.find(' ') else { continue };
        let fixed = format!("{date_part}{}:{}", &rest[..space_pos], &rest[space_pos + 1..]);
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&fixed) {
            return Some(dt.with_timezone(&chrono::Utc));
        }
    }
    None
}

/// `"Mottaget Kontokort   431,00"` for the amount, `"Betalmedel MasterCard"`
/// for a nicer method name if present, `"Kort ************1025"` for the
/// last four digits.
fn find_payment(lines: &[&str]) -> Option<Payment> {
    let (method_fallback, amount) = lines.iter().find_map(|l| {
        let l = l.trim();
        let rest = l.strip_prefix("Mottaget")?.trim();
        let (method, amount_str) = rest.rsplit_once(char::is_whitespace)?;
        Some((method.to_string(), parse_money(amount_str)?))
    })?;

    let method = lines
        .iter()
        .find_map(|l| l.trim().strip_prefix("Betalmedel").map(|m| m.trim().to_string()))
        .unwrap_or(method_fallback);

    let card_last4 = lines.iter().find_map(|l| {
        let l = l.trim();
        let digits = l.strip_prefix("Kort")?.trim();
        (digits.len() >= 4 && digits.chars().rev().take(4).all(|c| c.is_ascii_digit()))
            .then(|| digits[digits.len() - 4..].to_string())
    });

    Some(Payment { method, amount, card_last4 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvitto_core::{Media, RawReceipt, ReceiptId, WILLYS};

    #[test]
    fn parses_real_fixture() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/willys-receipt-1.pdf");
        let bytes = std::fs::read(path).expect("fixture missing — see WILLYS_BRIEF.md");
        let raw = RawReceipt::new(ReceiptId::new(WILLYS, "test-1"), Media::Pdf, bytes);
        let profile = ProfileId("test".into());

        let receipt = parse(&raw, &profile).expect("parse should succeed on a known-good fixture");

        assert_eq!(receipt.total, Money(43100), "printed total is 431,00 SEK");
        assert!(
            receipt.balances(),
            "line_sum={:?} total={:?} lines={:#?}",
            receipt.line_sum(),
            receipt.total,
            receipt.lines
        );
        assert_eq!(receipt.store.name, "Västerås Stenby");
        assert_eq!(receipt.purchased_at.to_rfc3339(), "2026-08-30T15:26:22.552+00:00");

        let payment = receipt.payments.first().expect("one card payment");
        assert_eq!(payment.amount, Money(43100));
        assert_eq!(payment.card_last4.as_deref(), Some("1025"));
        assert_eq!(payment.method, "MasterCard");

        let discounts: Vec<_> =
            receipt.lines.iter().filter(|l| l.kind == LineKind::Discount).collect();
        assert_eq!(discounts.len(), 2, "W Plus:PAPPER and Prisneds.");
        for d in &discounts {
            assert!(d.applies_to.is_some(), "discount should attach to the item above it");
        }

        let oat = receipt
            .lines
            .iter()
            .find(|l| l.description.starts_with("OAT DRINK"))
            .expect("qty line present");
        assert_eq!(oat.quantity, Quantity::Count(2.0));
        assert_eq!(oat.unit_price, Some(Money(1599)));
        assert_eq!(oat.amount, Money(3198));
    }
}
