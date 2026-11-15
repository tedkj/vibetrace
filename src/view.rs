//! What the window and the reports show, computed from a `Trace` and the names known so far:
//! the hop rows, the path's verdicts and the plain sentences. Pure code (tested here); the
//! controller turns it into Slint models, `report` into text.

use crate::resolve::Known;
use crate::stats::{self, LossClass, Responder};
use crate::trace::{EventKind, Trace};
use std::net::IpAddr;

/// The destination counts as "not answering" after this many rounds without an echo.
pub const DEST_PATIENCE: u32 = 5;

#[derive(Clone, Debug, PartialEq)]
pub struct HopView {
    pub ttl: u8,
    pub addr: Option<IpAddr>,
    /// Reverse DNS of the address (empty with names off, none found, pending or failed).
    pub host: String,
    /// Names on, and the address's reverse lookup could not be answered (unknown, not none).
    pub host_failed: bool,
    /// Other addresses this hop answered from.
    pub others: usize,
    pub as_num: String,
    pub as_name: String,
    pub sent: u32,
    pub received: u32,
    pub loss: f64,
    pub last: Option<f64>,
    pub avg: Option<f64>,
    pub best: Option<f64>,
    pub worst: Option<f64>,
    pub stdev: Option<f64>,
    pub jitter: Option<f64>,
    pub class: LossClass,
    pub slow: bool,
    pub later_avg: Option<f64>,
    /// The hop ends the path with this unreachable status.
    pub unreachable: Option<u32>,
    pub is_dest: bool,
    pub responders: Vec<Responder>,
    /// Replies from addresses past the hop's first `stats::MAX_RESPONDERS` (counted together).
    pub other_replies: u32,
}

impl HopView {
    pub fn silent(&self) -> bool {
        self.received == 0
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct PathView {
    pub hops: Vec<HopView>,
    /// Index of the destination's hop (the target answers there).
    pub dest: Option<usize>,
    /// The hop the others are judged against (destination, unreachable end or last answering).
    pub reference: Option<usize>,
    pub loss_start: Option<usize>,
    /// Hops after the last row were probed and never answered ("no reply beyond hop N").
    pub silent_tail: bool,
    /// The destination has not answered in `DEST_PATIENCE` rounds.
    pub dest_silent: bool,
    pub round: u32,
    pub ipv6: bool,
}

/// The rows: every hop up to the end (or up to the last one that answers).
pub fn path(t: &Trace, known: &Known, names: bool) -> PathView {
    let shown = t.shown();
    let facts = t.facts();
    let reference = t.reference();
    let mut verdicts = stats::verdicts(&facts[..shown], reference);
    let mut loss_start = stats::loss_start(&facts[..shown], reference);
    let dest = t.dest_hop();
    let end = t.end_hop();
    // A reference that is not the destination (the last hop that answers, an unreachable end)
    // is a router: loss that starts there has nothing after it to tell its rate limiting from
    // loss on the path, so it is not called real. Smaller real loss carried into it from
    // earlier hops still starts where the first of them is.
    if let Some(r) = reference
        && dest != Some(r)
        && loss_start == Some(r)
    {
        verdicts[r].loss = LossClass::Limited;
        loss_start = verdicts[..r].iter().position(|v| v.loss == LossClass::Real);
    }
    let hops = (0..shown)
        .map(|i| {
            let h = &t.hops[i];
            let s = &h.stats;
            let addr = h.responders.primary();
            let ms = |us: Option<u32>| us.map(|u| u as f64 / 1000.0);
            let (as_num, as_name) = addr.map(|a| known.as_text(a)).unwrap_or_default();
            HopView {
                ttl: i as u8 + 1,
                addr,
                host: if names { addr.and_then(|a| known.host(a)).unwrap_or("").to_string() } else { String::new() },
                host_failed: names && addr.is_some_and(|a| known.host_failed(a)),
                others: h.responders.list.len().saturating_sub(1),
                as_num,
                as_name,
                sent: s.sent,
                received: s.received,
                loss: s.loss(),
                last: ms(s.last_us),
                avg: s.avg_ms(),
                best: ms(s.best_us),
                worst: ms(s.worst_us),
                stdev: s.stdev_ms(),
                jitter: s.jitter_ms(),
                class: verdicts[i].loss,
                slow: verdicts[i].slow,
                later_avg: verdicts[i].later_avg_ms,
                unreachable: if Some(i) == end && dest.is_none() { h.unreachable_status() } else { None },
                is_dest: Some(i) == dest,
                responders: h.responders.ranked(),
                other_replies: h.responders.other,
            }
        })
        .collect();
    PathView {
        hops,
        dest,
        reference,
        loss_start,
        silent_tail: t.silent_tail(),
        dest_silent: end.is_none() && t.round() >= DEST_PATIENCE,
        round: t.round(),
        ipv6: t.target.is_ipv6(),
    }
}

// ---------- numbers ----------

/// Milliseconds as the table shows them: one decimal under 10 ms, whole ms above.
pub fn ms(v: Option<f64>) -> String {
    match v {
        None => String::new(),
        Some(v) if v < 9.95 => format!("{v:.1}"),
        Some(v) => format!("{v:.0}"),
    }
}

/// To one decimal, halves away from zero (`{:.1}` alone rounds the binary value: 12.25 reads
/// "12.2").
fn tenths(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// Milliseconds in a sentence: one decimal under 100 ms.
pub fn ms_text(v: f64) -> String {
    if v < 99.95 { format!("{:.1} ms", tenths(v)) } else { format!("{:.0} ms", v.round()) }
}

/// Loss in a column: "0.0%", "12.5%", "100%".
pub fn loss_cell(p: f64) -> String {
    if p >= 1.0 { "100%".into() } else { format!("{:.1}%", p * 100.0) }
}

/// Loss in a sentence: "3 %", "0.5 %", "12 %" (one decimal under 10 %, none when whole).
pub fn loss_text(p: f64) -> String {
    let v = p * 100.0;
    let t = tenths(v);
    if v >= 9.95 || t.fract() == 0.0 { format!("{:.0} %", v.round()) } else { format!("{t:.1} %") }
}

/// "0:42", "4:12", "1:02:03".
pub fn elapsed(ms: u64) -> String {
    let s = ms / 1000;
    if s >= 3600 { format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60) } else { format!("{}:{:02}", s / 60, s % 60) }
}

/// "1 s", "0.5 s".
pub fn interval(ms: u32) -> String {
    if ms.is_multiple_of(1000) { format!("{} s", ms / 1000) } else { format!("{} s", ms as f64 / 1000.0) }
}

// ---------- sentences ----------

/// The one plain sentence (or two) the detail panel says about hop `i`.
pub fn verdict(p: &PathView, i: usize) -> String {
    let Some(h) = p.hops.get(i) else { return String::new() };
    if h.sent == 0 {
        return "Waiting for the first probe.".into();
    }
    if h.silent() {
        return if p.reference.is_some_and(|r| r > i) {
            "No reply from this hop: the router does not answer pings. Later hops answer, so the path through it is fine.".into()
        } else {
            "No reply from this hop yet.".into()
        };
    }
    let mut out = String::new();
    if p.dest_silent && Some(i) == p.reference && !h.is_dest {
        out.push_str("The destination does not answer pings; it may filter ICMP. This is the last hop that answers. ");
    }
    if let Some(u) = h.unreachable {
        out.push_str(&format!(
            "{} says the destination cannot be reached ({}). ",
            h.addr.map(|a| a.to_string()).unwrap_or_default(),
            crate::icmp::words(u, p.ipv6)
        ));
    }
    let r = p.reference;
    let ref_loss = r.and_then(|r| p.hops.get(r)).map_or(0.0, |x| x.loss);
    let ref_word = if p.dest.is_some() { "the destination's" } else { "the last hop's" };
    let ref_noun = if p.dest.is_some() { "the destination" } else { "the last hop that answers" };
    match h.class {
        LossClass::None | LossClass::Silent => out.push_str("No loss. "),
        LossClass::Real => {
            let start = p.loss_start.unwrap_or(i);
            let pct = loss_text(h.loss);
            if start == i && Some(i) == r {
                out.push_str(&format!("{pct} loss here and not at the hops before it: the problem is at this hop or on the link to it. "));
            } else if start == i {
                out.push_str(&format!("{pct} loss starting here and carried to {ref_noun}: a real problem from this hop on. "));
            } else if start < i {
                out.push_str(&format!("{pct} loss, carried on from hop {}: a real problem from that hop on. ", start + 1));
            } else {
                out.push_str(&format!("{pct} loss, carried on to {ref_noun}. "));
            }
        }
        LossClass::Limited => {
            if Some(i) == r {
                out.push_str(&format!(
                    "Loses {}; nothing after this hop answers, so its rate limiting cannot be told from loss on the path. ",
                    loss_text(h.loss)
                ));
            } else if ref_loss == 0.0 {
                // Said against what it was compared with: other later hops may lose a little.
                out.push_str(&format!(
                    "Loses {}, but {ref_noun} loses nothing: this router answers pings slowly or rarely, the path is fine. ",
                    loss_text(h.loss)
                ));
            } else {
                out.push_str(&format!(
                    "Loses {}, more than {ref_word} {}: the difference is this router rate-limiting its answers. ",
                    loss_text(h.loss),
                    loss_text(ref_loss)
                ));
            }
        }
    }
    if let Some(avg) = h.avg {
        let sd = h.stdev.unwrap_or(0.0);
        if h.slow {
            let later = h.later_avg.unwrap_or(0.0);
            out.push_str(&format!(
                "Answers slower than later hops ({} against {}): it is slow to reply to pings, traffic through it is not delayed.",
                ms_text(avg),
                ms_text(later)
            ));
        } else if sd <= (0.5f64).max(avg * 0.2) {
            out.push_str(&format!("Latency steady around {}.", ms_text(avg)));
        } else {
            out.push_str(&format!("Latency {} on average, varying ({} stdev).", ms_text(avg), ms_text(sd)));
        }
    }
    out.trim_end().to_string()
}

/// The tooltip of hop `i`'s loss cell when the loss is not real (empty when it is, or none).
pub fn loss_tip(p: &PathView, i: usize) -> &'static str {
    let Some(h) = p.hops.get(i) else { return "" };
    let ref_loss = p.reference.and_then(|r| p.hops.get(r)).map_or(0.0, |x| x.loss);
    match h.class {
        LossClass::Limited if p.reference == Some(i) => "Nothing after this hop answers, so its rate limiting cannot be told from loss on the path.",
        LossClass::Limited if ref_loss == 0.0 && p.dest.is_some() => {
            "This router answers pings slowly or rarely. The destination loses nothing, so the path is fine."
        }
        LossClass::Limited if ref_loss == 0.0 => "This router answers pings slowly or rarely. The last hop that answers loses nothing, so the path is fine.",
        LossClass::Limited => "This router answers pings slowly or rarely. Later hops lose less, so most of this is not loss on the path.",
        LossClass::Silent if p.reference.is_some_and(|r| r > i) => "This router does not answer pings. Later hops answer, so the path through it is fine.",
        _ => "",
    }
}

pub const SLOW_TIP: &str = "This router is slow to answer pings. Later hops answer faster, so traffic through it is not delayed.";

/// One event in words, for the events list ("Route changed: 10.0.0.1 → 10.0.0.9").
pub fn event_text(k: &EventKind, ipv6: bool) -> String {
    match k {
        EventKind::RouteChange { from, to } => format!("Route changed: {from} → {to}"),
        EventKind::LossBurst { count, ended } => {
            if *ended { format!("{count} probes lost in a row") } else { format!("{count} probes lost in a row, still losing") }
        }
        EventKind::Unreachable { from, status } => format!("{from}: {}", crate::icmp::words(*status, ipv6)),
    }
}
