//! Axfood receipts (Willys, Hemköp) are a PDF whose content is just a
//! monospace text printout — no layout to fight,
//! `pdf_extract::extract_text_from_mem` gives back lines in the same shape a
//! receipt printer would. See `tests/fixtures/willys-receipt-1.pdf` (real
//! Willys purchase, captured 2026-08-30) and
//! `tests/fixtures/hemkop-receipt-1.pdf` (real Hemköp purchase, captured
//! 2026-08-30) for the two formats this is built against:
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
//! Hemköp's cashier-checkout receipts skip the Självscanning markers, carry
//! *two* `Totalt ... SEK` lines (pre- and post-coupon), combine the payment
//! method and card digits on one line, and have no ISO timestamp at all —
//! only a bare `YYYY-MM-DD HH:MM:SS` terminal timestamp:
//!
//! ```text
//! MALMABERG
//! ------------------------------------------
//! RÅGKAKA 6P                                   22,66
//!   +PANT ENG PET >1L                           3,00
//! ------------------------------------------
//!   Totalt 3 varor                         116,63 SEK
//! Mottaget Kupong
//!   Bonuscheck                                 15,00
//! ------------------------------------------
//!  Totalt                                  101,63 SEK
//! Mottaget Kontokort                           101,63
//! Debit Mastercard                    ************1025
//! ...
//! 2026-08-30 13:43:54              TSI: E800
//! ```
//!
//! Both shapes bound the item block the same way — between the first two
//! `---`-only divider lines — so no chain-specific branch is needed there:
//! the `Start/Slut Självscanning` markers are just extra lines inside that
//! span, silently skipped since they have no trailing money token.
//!
//! Contract: pure and sync, unrecognised rows become `LineKind::Other`
//! rather than being dropped, `Line::category` is never set (the
//! categoriser's job, not the parser's), and `Receipt::balances()` must
//! hold — it does for both fixtures.

use crate::chain::Chain;
use kvitto_core::{
    Error, Line, LineKind, Money, Payment, ProfileId, Quantity, RawReceipt, Receipt, Result,
    SCHEMA_VERSION, Store,
};

pub fn parse(raw: &RawReceipt, profile: &ProfileId, chain: Chain) -> Result<Receipt> {
    let text = pdf_extract::extract_text_from_mem(&raw.bytes).map_err(|e| Error::Parse {
        id: raw.id.clone(),
        detail: format!("could not extract PDF text: {e}"),
    })?;
    let lines: Vec<&str> = text.lines().collect();

    let store = parse_store(&lines, chain);
    let receipt_lines = parse_lines(&lines);
    let total = find_total(&lines).ok_or_else(|| Error::Parse {
        id: raw.id.clone(),
        detail: "no \"Totalt ... SEK\" line found".into(),
    })?;
    let purchased_at = find_timestamp(&lines).ok_or_else(|| Error::Parse {
        id: raw.id.clone(),
        detail: "no timestamp line found".into(),
    })?;
    let payments = find_payments(&lines);

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

fn parse_store(lines: &[&str], chain: Chain) -> Store {
    let mut nonblank = lines.iter().map(|l| l.trim()).filter(|l| !l.is_empty());
    let name = nonblank.next().unwrap_or(chain.default_store_name()).to_string();
    let address = nonblank.next().map(str::to_string);
    Store { name, chain: Some(chain.source_id().to_string()), address, ..Store::default() }
}

/// A line consisting only of dashes — the divider both chains use to bound
/// the item block, before and after.
fn is_divider(line: &str) -> bool {
    let l = line.trim();
    l.len() > 5 && l.chars().all(|c| c == '-')
}

/// Item and discount rows between the first two divider lines. A row's
/// amount is its own signal: negative means `LineKind::Discount` attached to
/// the item above it — no need to trust indentation, which a PDF text
/// extractor can mangle.
fn parse_lines(lines: &[&str]) -> Vec<Line> {
    let start = lines.iter().position(|l| is_divider(l));
    let end = start.and_then(|s| lines[s + 1..].iter().position(|l| is_divider(l)).map(|i| s + 1 + i));
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

/// `" Totalt    431,00 SEK"` — the *first* such line. Hemköp's
/// cashier-checkout receipts print a second one further down after a coupon
/// payment is deducted, but that's a running balance, not the merchandise
/// total — the first line is the one item rows actually sum to (a coupon is
/// just another `Payment`, see `find_payments`). Willys only ever has one,
/// so this is a no-op there.
fn find_total(lines: &[&str]) -> Option<Money> {
    lines.iter().find_map(|l| {
        let l = l.trim();
        let rest = l.strip_prefix("Totalt")?.trim();
        let amount_str = rest.strip_suffix("SEK")?.trim();
        // Willys: amount is the whole remainder ("431,00"). Hemköp's first
        // Totalt line has an item count in between ("3 varor   116,63") —
        // the amount is still just the last token either way.
        let amount_str =
            amount_str.rsplit_once(char::is_whitespace).map_or(amount_str, |(_, a)| a);
        parse_money(amount_str)
    })
}

/// Willys: `"2026-08-30T15 26:22.552Z"` — the PDF's text layout drops the
/// colon between hour and minute (a font-spacing artifact, not a typo);
/// patch it back in and parse as RFC 3339.
///
/// Hemköp's receipt carries no ISO timestamp at all — only the payment
/// terminal's bare `"2026-08-30 13:43:54"` line (excluding the `Kassa:`
/// line, whose date/time are separate whitespace-split tokens rather than
/// one). Treated as `Europe/Stockholm` local time and converted to UTC,
/// since the printed timestamp is store-local, not UTC.
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

    for line in lines {
        let line = line.trim();
        if line.starts_with("Kassa") {
            continue; // e.g. "Kassa: 3/23   2026-08-30   13:43" — date/time
            // as separate trailing tokens, not the leading pair below, but
            // excluded explicitly since "3/23" makes the parse attempt
            // pointless anyway.
        }
        let mut parts = line.split_whitespace();
        let (Some(date_str), Some(time_str)) = (parts.next(), parts.next()) else { continue };
        let Ok(naive) = chrono::NaiveDateTime::parse_from_str(
            &format!("{date_str} {time_str}"),
            "%Y-%m-%d %H:%M:%S",
        ) else {
            continue;
        };
        if let chrono::LocalResult::Single(local) =
            naive.and_local_timezone(chrono_tz::Europe::Stockholm)
        {
            return Some(local.with_timezone(&chrono::Utc));
        }
    }
    None
}

/// One `Payment` per `"Mottaget ..."` line — a receipt can settle in more
/// than one way (e.g. Hemköp: a `Bonuscheck` coupon for part of the total,
/// card for the rest). Two shapes seen:
///   - same line: `"Mottaget Kontokort   431,00"` → method + amount inline.
///   - split across two: `"Mottaget Kupong"` then, on the next non-blank
///     line, `"  Bonuscheck   15,00"` — the amount lives on the follower.
///
/// Whichever payment is the *last* found gets refined with card details, on
/// the assumption (true for both known fixtures) that the card payment is
/// always the final one printed: `card_last4` from whichever line ends in a
/// run of `*` immediately followed by digits — `"Kort ************1025"`
/// (Willys) or `"Debit Mastercard   ************1025"` (Hemköp), the text
/// before the stars becoming the method — and `"Betalmedel MasterCard"`
/// (Willys only), when present, overriding that with the nicer brand name.
fn find_payments(lines: &[&str]) -> Vec<Payment> {
    let mut out: Vec<Payment> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i].trim();
        let Some(rest) = l.strip_prefix("Mottaget") else {
            i += 1;
            continue;
        };
        let rest = rest.trim();

        if let Some((method, amount_str)) = rest.rsplit_once(char::is_whitespace) {
            if let Some(amount) = parse_money(amount_str) {
                out.push(Payment { method: method.to_string(), amount, card_last4: None });
                i += 1;
                continue;
            }
        }

        // No amount on this line (e.g. bare "Mottaget Kupong") — the
        // sub-line right after it carries the method + amount instead.
        let mut j = i + 1;
        while j < lines.len() && lines[j].trim().is_empty() {
            j += 1;
        }
        if let Some(next) = lines.get(j).map(|l| l.trim()) {
            if !next.starts_with("Mottaget") {
                if let Some((method, amount)) = split_trailing_amount(next) {
                    out.push(Payment { method: method.to_string(), amount, card_last4: None });
                    i = j + 1;
                    continue;
                }
            }
        }
        i += 1;
    }

    if let Some(last) = out.last_mut() {
        if let Some((prefix, last4)) = find_card_line(lines) {
            last.card_last4 = Some(last4);
            if !prefix.is_empty() {
                last.method = prefix;
            }
        }
        if let Some(betalmedel) =
            lines.iter().find_map(|l| l.trim().strip_prefix("Betalmedel").map(|m| m.trim().to_string()))
        {
            last.method = betalmedel;
        }
    }

    out
}

/// A line ending in a run of `*` immediately followed by exactly 4+ digits
/// (e.g. `"...  ************1025"`) — the masked-card-number shape every
/// chain prints, regardless of what precedes it. Returns the trimmed text
/// before the stars and the last four digits.
fn find_card_line(lines: &[&str]) -> Option<(String, String)> {
    lines.iter().find_map(|l| {
        let l = l.trim();
        let digit_start = l.len() - l.chars().rev().take_while(|c| c.is_ascii_digit()).count();
        if l.len() - digit_start < 4 {
            return None;
        }
        let before_digits = &l[..digit_start];
        let star_start =
            before_digits.len() - before_digits.chars().rev().take_while(|c| *c == '*').count();
        if star_start == before_digits.len() {
            return None; // no stars immediately before the digits
        }
        let prefix = l[..star_start].trim().to_string();
        let last4 = l[l.len() - 4..].to_string();
        Some((prefix, last4))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kvitto_core::{Media, RawReceipt, ReceiptId, HEMKOP, WILLYS};

    #[test]
    fn parses_real_willys_fixture() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/willys-receipt-1.pdf");
        let bytes = std::fs::read(path).expect("fixture missing — see WILLYS_BRIEF.md");
        let raw = RawReceipt::new(ReceiptId::new(WILLYS, "test-1"), Media::Pdf, bytes);
        let profile = ProfileId("test".into());

        let receipt =
            parse(&raw, &profile, Chain::Willys).expect("parse should succeed on a known-good fixture");

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

    #[test]
    fn parses_real_hemkop_fixture() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/hemkop-receipt-1.pdf");
        let bytes = std::fs::read(path).expect("fixture missing");
        let raw = RawReceipt::new(ReceiptId::new(HEMKOP, "test-1"), Media::Pdf, bytes);
        let profile = ProfileId("test".into());

        let receipt =
            parse(&raw, &profile, Chain::Hemkop).expect("parse should succeed on a known-good fixture");

        // Item-line total (116,63 SEK), not the post-coupon running balance —
        // the Bonuscheck coupon is a Payment, not a line deduction.
        assert_eq!(receipt.total, Money(11663), "printed pre-coupon total is 116,63 SEK");
        assert!(
            receipt.balances(),
            "line_sum={:?} total={:?} lines={:#?}",
            receipt.line_sum(),
            receipt.total,
            receipt.lines
        );
        assert_eq!(receipt.store.name, "MALMABERG");
        assert_eq!(receipt.purchased_at.to_rfc3339(), "2026-08-30T11:43:54+00:00");

        assert_eq!(receipt.payments.len(), 2, "coupon + card");
        let total_paid: Money = receipt.payments.iter().map(|p| p.amount).sum();
        assert_eq!(total_paid, receipt.total, "payments should cover the full total");

        let card_payment = receipt.payments.last().expect("card payment last");
        assert_eq!(card_payment.amount, Money(10163));
        assert_eq!(card_payment.card_last4.as_deref(), Some("1025"));
        assert_eq!(card_payment.method, "Debit Mastercard");

        let coupon_payment = &receipt.payments[0];
        assert_eq!(coupon_payment.amount, Money(1500));
        assert_eq!(coupon_payment.method, "Bonuscheck");

        let pant_lines: Vec<_> =
            receipt.lines.iter().filter(|l| l.description.starts_with("+PANT")).collect();
        assert_eq!(pant_lines.len(), 2, "two deposit rows");
        for p in &pant_lines {
            assert_eq!(p.kind, LineKind::Item, "a positive-amount deposit charge, not a discount");
        }
    }
}
