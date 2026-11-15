//! Reports: plain text with aligned columns (like `mtr --report`), and CSV with every
//! statistic. Both are built from the same `PathView` the window shows.

use crate::csvformat::CsvFormat;
use crate::resolve::{self, Known};
use crate::stats::LossClass;
use crate::trace::{EventKind, Trace};
use crate::view::{self, HopView, PathView};

/// Events the text report lists at most (the newest).
const REPORT_EVENTS: usize = 100;

/// What a report needs beside the trace.
pub struct Context<'a> {
    pub trace: &'a Trace,
    pub path: &'a PathView,
    pub known: &'a Known,
    pub names: bool,
    /// AS lookups switched on.
    pub asn: bool,
    /// Milliseconds the trace ran (since its start or last reset).
    pub ran_ms: u64,
    /// The path MTU probe of this trace, when one ran (SPEC §10).
    pub mtu: Option<&'a crate::mtu::Mtu>,
}

/// Hop `i`'s MTU cell text ("" past the probe's reference).
fn mtu_cell(m: &crate::mtu::Mtu, i: usize) -> String {
    m.cell(i).0
}

fn host_text(h: &HopView, names: bool) -> String {
    match h.addr {
        None => "no reply".into(),
        Some(a) if names && !h.host.is_empty() => format!("{} ({a})", h.host),
        Some(a) if names && h.host_failed => format!("{a} ({})", resolve::NAME_FAILED),
        Some(a) => a.to_string(),
    }
}

/// A responder's name and address as the report lists it.
fn responder_text(c: &Context, a: std::net::IpAddr) -> String {
    match c.known.host(a) {
        Some(n) if c.names => format!("{n} ({a})"),
        _ if c.names && c.known.host_failed(a) => format!("{a} ({})", resolve::NAME_FAILED),
        _ => a.to_string(),
    }
}

fn as_text(h: &HopView) -> String {
    if h.as_name.is_empty() { h.as_num.clone() } else { format!("{} {}", h.as_num, h.as_name) }
}

fn note(h: &HopView) -> &'static str {
    match (h.unreachable.is_some(), h.class, h.slow) {
        (true, _, _) => "unreachable",
        (_, LossClass::Limited, true) => "rate-limited, slow to answer",
        (_, LossClass::Limited, false) => "rate-limited",
        (_, LossClass::Real, _) => "real loss",
        (_, _, true) => "slow to answer",
        _ => "",
    }
}

/// The header lines both formats describe the trace with.
fn header(c: &Context) -> Vec<(&'static str, String)> {
    let t = c.trace;
    let target = if t.name == t.target.to_string() { t.name.clone() } else { format!("{} ({})", t.name, t.target) };
    let o = t.opts;
    let result = match c.path.dest.or(c.path.reference) {
        Some(i) if c.path.dest.is_some() || c.path.dest_silent || c.path.hops[i].unreachable.is_some() => view::verdict(c.path, i),
        _ => "No answer yet.".into(),
    };
    vec![
        ("Target", target),
        // After a Reset the statistics cover only the time since it.
        ("Started", if t.origin_ms > 0 {
            format!("{}, statistics since {}, ran {}", t.started.stamp(), t.started.time_after(t.origin_ms), view::elapsed(c.ran_ms))
        } else {
            format!("{}, ran {}", t.started.stamp(), view::elapsed(c.ran_ms))
        }),
        ("Probes", format!("ICMP echo, {} bytes every {}, timeout {}, max {} hops", o.size, view::interval(o.interval_ms), view::interval(o.timeout_ms), o.max_hops)),
        ("Result", result),
    ]
    .into_iter()
    .chain(c.mtu.map(|m| ("Path MTU", m.summary(&t.name).trim_start_matches(&format!("Path MTU to {}: ", t.name)).to_string())))
    .chain(lookups(c).map(|l| ("Lookups", l)))
    .collect()
}

/// Lookups that have not answered: the report says it is missing names, never leaves them
/// out silently ("2 not answered yet, 1 failed").
fn lookups(c: &Context) -> Option<String> {
    let ips = c.path.hops.iter().flat_map(|h| h.responders.iter().map(|r| r.addr));
    let (pending, failed, not_asked) = c.known.open(ips, c.names, c.asn);
    let mut parts = Vec::new();
    if pending > 0 {
        parts.push(format!("{pending} not answered yet"));
    }
    if failed > 0 {
        parts.push(format!("{failed} failed (asked again every 30 s while tracing)"));
    }
    if not_asked > 0 {
        parts.push(format!("{not_asked} not looked up (past the lookup limits)"));
    }
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// Plain text, aligned columns, a footer with the version.
pub fn text(c: &Context) -> String {
    let p = c.path;
    let mut out = String::from("VibeTrace report\n");
    for (k, v) in header(c) {
        out.push_str(&format!("{k:<9} {v}\n"));
    }
    out.push('\n');
    let hosts: Vec<String> = p.hops.iter().map(|h| host_text(h, c.names)).collect();
    let ases: Vec<String> = p.hops.iter().map(as_text).collect();
    let hw = hosts.iter().map(|h| h.chars().count()).max().unwrap_or(0).clamp(4, 60);
    let aw = ases.iter().map(|a| a.chars().count()).max().unwrap_or(0).clamp(2, 28);
    let cut = |s: &str, w: usize| -> String {
        if s.chars().count() <= w { s.to_string() } else { s.chars().take(w - 1).collect::<String>() + "…" }
    };
    let mtu_head = if c.mtu.is_some() { format!(" {:>5}", "MTU") } else { String::new() };
    out.push_str(&format!(
        "{:>3}  {:<hw$}  {:<aw$}  {:>6} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}{mtu_head}\n",
        "#", "Host", "AS", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "StDev", "Javg"
    ));
    for (i, h) in p.hops.iter().enumerate() {
        let loss = if h.sent == 0 { String::new() } else { view::loss_cell(h.loss) };
        let mtu = c.mtu.map(|m| format!(" {:>5}", mtu_cell(m, i))).unwrap_or_default();
        let line = format!(
            "{:>3}  {:<hw$}  {:<aw$}  {:>6} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}{mtu}  {}",
            h.ttl,
            cut(&hosts[i], hw),
            cut(&ases[i], aw),
            loss,
            h.sent,
            view::ms(h.last),
            view::ms(h.avg),
            view::ms(h.best),
            view::ms(h.worst),
            view::ms(h.stdev),
            view::ms(h.jitter),
            note(h)
        );
        out.push_str(line.trim_end());
        out.push('\n');
        // The other addresses of a load-balanced hop, with their share of its replies.
        let total: u32 = h.responders.iter().map(|r| r.replies).sum::<u32>() + h.other_replies;
        for r in h.responders.iter().filter(|r| Some(r.addr) != h.addr) {
            let share = r.replies as f64 / total.max(1) as f64;
            out.push_str(&format!("{:>3}  + {}  {}\n", "", responder_text(c, r.addr), view::loss_text(share).replace(" %", " % of replies")));
        }
        if h.other_replies > 0 {
            let share = h.other_replies as f64 / total.max(1) as f64;
            out.push_str(&format!("{:>3}  + other addresses  {}\n", "", view::loss_text(share).replace(" %", " % of replies")));
        }
    }
    if p.silent_tail {
        out.push_str(&format!("{:>3}  no reply beyond hop {}\n", "", p.hops.len()));
    }
    // The window's rule for the path's events: loss bursts at a rate-limiting router are the
    // router's business. The newest REPORT_EVENTS of them.
    let events: Vec<_> = c
        .trace
        .events
        .iter()
        .filter(|e| e.hop < p.hops.len())
        .filter(|e| !matches!(e.kind, EventKind::LossBurst { .. }) || Some(e.hop) == p.reference || p.hops[e.hop].class == LossClass::Real)
        .collect();
    if !events.is_empty() {
        out.push_str("\nEvents\n");
        let earlier = events.len().saturating_sub(REPORT_EVENTS);
        let older = if c.trace.events_dropped { " (the oldest are no longer kept)" } else { "" };
        if earlier > 0 {
            out.push_str(&format!("… {earlier} earlier events{older}\n"));
        } else if c.trace.events_dropped {
            out.push_str("… older events are no longer kept\n");
        }
        for e in &events[earlier..] {
            out.push_str(&format!(
                "{}  hop {:<3} {}\n",
                c.trace.started.time_after(e.at_ms + c.trace.origin_ms),
                e.hop + 1,
                view::event_text(&e.kind, c.trace.target.is_ipv6())
            ));
        }
    }
    if p.hops.iter().any(|h| h.class == LossClass::Limited || h.slow) {
        out.push_str("\nrate-limited: loss that later hops do not show; the router answers pings slowly or rarely, the path is fine.\n");
        out.push_str("slow to answer: slower than a later hop; the router is slow to reply to pings, traffic is not delayed.\n");
    }
    if c.mtu.is_some() {
        let blank = if p.hops.iter().any(|h| h.class == LossClass::Limited || h.slow) { "" } else { "\n" };
        out.push_str(&format!("{blank}MTU: the largest packet (IP bytes, don't-fragment set) that got to the hop, one way; the destination's needs its echo back too.\n"));
        out.push_str("The probe teaches Windows' path cache only what a router said (\"fragmentation needed\"), as any full-size packet to that destination would; nothing else changes.\n");
    }
    // How the times are taken (it was in About; it matters where the numbers are read).
    out.push_str(&format!("\n{TIMING}\n"));
    out.push_str(&format!("\nVibeTrace {}\n", crate::VERSION));
    out
}

/// How the round trips are timed, said under the trace report's hops.
pub const TIMING: &str = "Round trips are timed around each echo with the performance counter (microseconds, a little of it the API's own time), not the API's whole milliseconds.";

/// A CSV field whose lookup could not be answered.
const FAILED: &str = "(lookup failed)";

pub const CSV_HEADER: [&str; 16] =
    ["hop", "address", "name", "asn", "as_name", "loss_pct", "sent", "received", "last_ms", "avg_ms", "best_ms", "worst_ms", "stdev_ms", "jitter_ms", "verdict", "responders"];

/// One row per hop, every statistic; the responders joined with ";" ("address=replies"). UTF-8
/// with a BOM and CRLF rows, in the user's list separator and decimal symbol (`f`).
pub fn csv(c: &Context, f: &CsvFormat) -> String {
    let ms = |v: Option<f64>| v.map(|v| f.num(v, 3)).unwrap_or_default();
    let mut out = String::from("\u{FEFF}");
    out.push_str(&CSV_HEADER.join(&f.sep));
    if c.mtu.is_some() {
        out.push_str(&f.sep);
        out.push_str("mtu");
    }
    out.push_str("\r\n");
    for (i, h) in c.path.hops.iter().enumerate() {
        let verdict = match (h.unreachable.is_some(), h.class) {
            (true, _) => "unreachable",
            (_, LossClass::Silent) => "no reply",
            (_, LossClass::Real) => "real loss",
            (_, LossClass::Limited) => "rate-limited",
            (_, LossClass::None) => "ok",
        };
        let verdict = if h.slow { format!("{verdict}; slow to answer") } else { verdict.to_string() };
        let mut responders: Vec<String> = h
            .responders
            .iter()
            .map(|r| match c.known.host(r.addr).filter(|_| c.names) {
                Some(n) => format!("{} {n}={}", r.addr, r.replies),
                None if c.names && c.known.host_failed(r.addr) => format!("{} {FAILED}={}", r.addr, r.replies),
                None => format!("{}={}", r.addr, r.replies),
            })
            .collect();
        if h.other_replies > 0 {
            responders.push(format!("other={}", h.other_replies));
        }
        // A lookup that could not be answered is not "no name": it says so, in a form no DNS
        // or AS name can take.
        let failed = |s: &str| if s == resolve::NAME_FAILED || s == resolve::AS_FAILED || s == resolve::AS_NAME_FAILED { FAILED.to_string() } else { s.to_string() };
        // (value, text from outside: names from DNS and the AS registry)
        let row: [(String, bool); 16] = [
            (h.ttl.to_string(), false),
            (h.addr.map(|a| a.to_string()).unwrap_or_default(), false),
            (if h.host_failed { FAILED.into() } else { h.host.clone() }, true),
            (if h.as_num == "private" { String::new() } else { h.as_num.trim_start_matches("AS").to_string() }, false),
            (if h.as_num == "private" { "private".into() } else { failed(&h.as_name) }, true),
            (f.num(h.loss * 100.0, 2), false),
            (h.sent.to_string(), false),
            (h.received.to_string(), false),
            (ms(h.last), false),
            (ms(h.avg), false),
            (ms(h.best), false),
            (ms(h.worst), false),
            (ms(h.stdev), false),
            (ms(h.jitter), false),
            (verdict, false),
            (responders.join(";"), true),
        ];
        out.push_str(&row.iter().map(|(v, t)| f.field(v, *t)).collect::<Vec<_>>().join(&f.sep));
        if let Some(m) = c.mtu {
            out.push_str(&f.sep);
            out.push_str(&f.field(&mtu_cell(m, i), false));
        }
        out.push_str("\r\n");
    }
    out
}
