//! The ISP log report (SPEC §9.6), written for an ISP's support desk: what was measured, how,
//! the outages and where each broke, every hop with latency percentiles, the destination hour
//! by hour, the DNS checks. Built from the log's lines (the file and what waits to be written),
//! on the log's own thread. Pure: no I/O here.

use crate::csvformat::CsvFormat;
use crate::isplog::{self, BUCKETS, DnsVal, HopLook, HopRec, OutageRec, Record, RunRec, ViaKind};
use crate::resolve::{self, Known};
use crate::stats::{self, HopFacts, LossClass};
use crate::trace::WallClock;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

/// Gaps and DNS failures the text lists at most (the newest), outages likewise.
const LIST_MAX: usize = 50;
const OUTAGES_LISTED: usize = 200;

/// One hop over the whole log (or the destination in one hour).
#[derive(Clone, Debug, Default)]
pub struct HopAgg {
    pub sent: u64,
    pub recv: u64,
    pub local: u64,
    pub min: Option<u32>,
    pub max: u32,
    pub sum: u64,
    pub hist: Vec<u32>,
    pub addrs: HashMap<IpAddr, u64>,
}

impl HopAgg {
    /// One minute's record, read as hostile: counts kept consistent, buckets in range.
    pub fn add(&mut self, h: &HopRec) {
        let recv = h.recv.min(h.sent);
        self.sent += h.sent as u64;
        self.recv += recv as u64;
        self.local += h.local.min(h.sent - recv) as u64;
        if recv > 0 {
            let lo = h.min.min(h.max);
            self.min = Some(self.min.map_or(lo, |m| m.min(lo)));
            self.max = self.max.max(h.max);
            self.sum = self.sum.saturating_add(h.sum.min(h.max as u64 * recv as u64));
        }
        if self.hist.is_empty() {
            self.hist = vec![0; BUCKETS];
        }
        let mut left = recv;
        for &(b, n) in &h.h {
            let n = n.min(left);
            left -= n;
            let c = &mut self.hist[(b as usize).min(BUCKETS - 1)];
            *c = c.saturating_add(n);
        }
        if let Some(a) = h.addr {
            *self.addrs.entry(a).or_default() += recv.max(1) as u64;
        }
    }

    pub fn loss(&self) -> f64 {
        if self.sent == 0 { 0.0 } else { (self.sent - self.recv) as f64 / self.sent as f64 }
    }

    pub fn avg_ms(&self) -> Option<f64> {
        (self.recv > 0).then(|| self.sum as f64 / self.recv as f64 / 1000.0)
    }

    /// The `q` percentile in ms (nearest rank over the histogram, the bucket's middle, kept
    /// within the measured min and max).
    pub fn pct(&self, q: f64) -> Option<f64> {
        let n: u64 = self.hist.iter().map(|c| *c as u64).sum();
        if n == 0 {
            return None;
        }
        let rank = ((q * n as f64).ceil() as u64).clamp(1, n);
        let mut acc = 0u64;
        for (b, c) in self.hist.iter().enumerate() {
            acc += *c as u64;
            if acc >= rank {
                let mid = isplog::bucket_mid_us(b as u16);
                let lo = self.min.unwrap_or(0) as f64;
                return Some(mid.clamp(lo, (self.max as f64).max(lo)) / 1000.0);
            }
        }
        None
    }

    /// The address it answered from most.
    pub fn addr(&self) -> Option<IpAddr> {
        let mut v: Vec<(&IpAddr, &u64)> = self.addrs.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        v.first().map(|x| *x.0)
    }
}

/// A DNS resolver over the log: its checks (about when, from the minute) and its failures.
#[derive(Clone, Debug, Default)]
pub struct DnsAgg {
    pub checks: Vec<(u64, DnsVal)>,
}

/// A spell of failed DNS checks: from the first failed to the next good one (None: still).
#[derive(Clone, Debug, PartialEq)]
pub struct Spell {
    pub start: u64,
    pub end: Option<u64>,
    pub checks: u32,
    pub why: String,
}

impl DnsAgg {
    pub fn failed(&self) -> usize {
        self.checks.iter().filter(|c| matches!(c.1, DnsVal::Fail(_))).count()
    }

    pub fn times(&self) -> HopAgg {
        let mut h = HopAgg { hist: vec![0; BUCKETS], ..HopAgg::default() };
        for (_, c) in &self.checks {
            if let DnsVal::Us(us) = c {
                h.add(&HopRec { ttl: 1, sent: 1, recv: 1, min: *us, max: *us, sum: *us as u64, h: vec![(isplog::bucket(*us), 1)], ..HopRec::default() });
            }
        }
        h.sent = self.checks.len() as u64;
        h
    }

    pub fn spells(&self) -> Vec<Spell> {
        let mut c = self.checks.clone();
        c.sort_by_key(|x| x.0);
        let mut out: Vec<Spell> = Vec::new();
        let mut open: Option<Spell> = None;
        for (at, v) in c {
            match (v, open.as_mut()) {
                (DnsVal::Fail(why), Some(s)) => {
                    s.checks += 1;
                    s.why = why;
                }
                (DnsVal::Fail(why), None) => open = Some(Spell { start: at, end: None, checks: 1, why }),
                (DnsVal::Us(_), Some(_)) => {
                    let mut s = open.take().expect("open");
                    s.end = Some(at);
                    out.push(s);
                }
                (DnsVal::Us(_), None) => {}
            }
        }
        out.extend(open);
        out
    }
}

/// Everything the log says, added up.
#[derive(Clone, Debug, Default)]
pub struct Data {
    pub runs: Vec<RunRec>,
    /// The UTC minutes that have records.
    pub minutes: BTreeSet<u64>,
    /// The minutes written right after the log followed the clock forward (R-6).
    pub stepped: BTreeSet<u64>,
    pub hops: BTreeMap<u8, HopAgg>,
    /// The destination's TTL: how many minutes said each.
    pub dest_ttls: HashMap<u8, u32>,
    /// The destination over the whole log, and hour by hour (local hour -> its start's UTC ms).
    pub dest: HopAgg,
    pub hours: BTreeMap<u64, (u64, HopAgg)>,
    pub sys: DnsAgg,
    pub public: DnsAgg,
    /// The last record of each outage.
    pub outages: BTreeMap<u64, OutageRec>,
    /// Lines that were not records.
    pub skipped: u32,
}

impl Data {
    /// The destination's TTL most minutes agree on.
    pub fn dest_ttl(&self) -> Option<u8> {
        let mut v: Vec<(&u8, &u32)> = self.dest_ttls.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        v.first().map(|x| *x.0)
    }

    pub fn first(&self) -> Option<u64> {
        self.minutes.first().copied()
    }

    pub fn last(&self) -> Option<u64> {
        self.minutes.last().map(|m| m + 60_000)
    }

    /// Stretches of a minute or more without records, inside the log's span.
    pub fn gaps(&self) -> Vec<(u64, u64)> {
        let m: Vec<u64> = self.minutes.iter().copied().collect();
        m.windows(2).filter(|w| w[1] > w[0] + 60_000).map(|w| (w[0] + 60_000, w[1])).collect()
    }
}

/// A local hour's key and its start: the local time of `at`, its minutes and seconds dropped.
fn hour_of(at: u64, local: &dyn Fn(u64) -> WallClock) -> (u64, u64) {
    let w = local(at);
    let key = w.year as u64 * 1_000_000 + w.month as u64 * 10_000 + w.day as u64 * 100 + w.hour as u64;
    let start = at - (w.minute as u64 * 60_000 + w.second as u64 * 1000 + at % 1000);
    (key, start)
}

/// Add up the log's lines. Lines that are not records (or not believable at `now`) are
/// counted and skipped; a minute written in two parts (a report mid-minute) adds up.
pub fn aggregate<'a>(lines: impl IntoIterator<Item = &'a str>, now: u64, local: &dyn Fn(u64) -> WallClock) -> Data {
    let mut d = Data { dest: HopAgg { hist: vec![0; BUCKETS], ..HopAgg::default() }, ..Data::default() };
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Some(r) = crate::logfile::parse_line(line, now) else {
            d.skipped += 1;
            continue;
        };
        match r {
            Record::Run(r) => d.runs.push(r),
            Record::Outage(mut o) => {
                // Text from the file is shown and reported: cleaned like any text from outside.
                o.words = resolve::clean_name(&o.words);
                o.zone = crate::isplog::Zone::known_code(&resolve::clean_name(&o.zone)).to_string();
                o.note = o.note.map(|n| resolve::clean_name(&n));
                d.outages.insert(o.id, o);
            }
            Record::Min(m) => {
                let at = m.at - m.at % 60_000;
                d.minutes.insert(at);
                if m.stepped {
                    d.stepped.insert(at);
                }
                for h in &m.hops {
                    if h.ttl == 0 {
                        continue;
                    }
                    d.hops.entry(h.ttl).or_default().add(h);
                }
                if let Some(t) = m.dest.filter(|t| *t > 0) {
                    *d.dest_ttls.entry(t).or_default() += 1;
                    if let Some(h) = m.hops.iter().find(|h| h.ttl == t) {
                        d.dest.add(h);
                        let (key, start) = hour_of(at, local);
                        d.hours.entry(key).or_insert_with(|| (start, HopAgg::default())).1.add(h);
                    }
                }
                let clean = |v: &DnsVal| match v {
                    DnsVal::Fail(w) => DnsVal::Fail(resolve::clean_name(w)),
                    ok => ok.clone(),
                };
                for (i, v) in m.ds.iter().enumerate() {
                    d.sys.checks.push((at + i as u64 * isplog::DNS_EVERY_MS, clean(v)));
                }
                for (i, v) in m.dp.iter().enumerate() {
                    d.public.checks.push((at + i as u64 * isplog::DNS_EVERY_MS, clean(v)));
                }
            }
        }
    }
    d
}

/// What the report needs beside the log.
pub struct Ctx<'a> {
    /// The host as traced, its family.
    pub target: &'a str,
    pub ipv6: bool,
    /// Names and AS numbers this window knows.
    pub known: &'a Known,
    pub names: bool,
    /// UTC ms -> local time.
    pub local: &'a dyn Fn(u64) -> WallClock,
    pub now: u64,
    /// Why the file was left out (it could not be read): only what waits is in the report.
    pub left_out: Option<String>,
    /// Minutes that could not be written and went.
    pub dropped: u32,
}

// ---------- words and numbers ----------

pub fn stamp(w: &WallClock) -> String {
    w.stamp()
}

/// "45 s", "2 min 28 s", "1 h 4 min", "3 d 2 h".
pub fn dur(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..60 => format!("{s} s"),
        60..3600 => {
            if s.is_multiple_of(60) { format!("{} min", s / 60) } else { format!("{} min {} s", s / 60, s % 60) }
        }
        3600..86_400 => {
            if (s / 60).is_multiple_of(60) { format!("{} h", s / 3600) } else { format!("{} h {} min", s / 3600, s / 60 % 60) }
        }
        _ => {
            if (s / 3600).is_multiple_of(24) { format!("{} d", s / 86_400) } else { format!("{} d {} h", s / 86_400, s / 3600 % 24) }
        }
    }
}

fn ms(v: Option<f64>) -> String {
    crate::view::ms(v)
}

/// The end of a span, short when it is the same day as its start.
fn until(start: u64, end: u64, local: &dyn Fn(u64) -> WallClock) -> String {
    let (a, b) = (local(start), local(end));
    if (a.year, a.month, a.day) == (b.year, b.month, b.day) { b.time_after(0) } else { b.stamp() }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// The hops of the report: TTL 1 to the destination's (all of them when it never answered).
fn rows(d: &Data) -> Vec<(u8, &HopAgg)> {
    let last = d.dest_ttl().unwrap_or(u8::MAX);
    d.hops.iter().filter(|(t, _)| **t <= last).map(|(t, h)| (*t, h)).collect()
}

/// What the zone words and AS columns need of each hop.
fn looks(d: &Data, c: &Ctx) -> Vec<HopLook> {
    let rows = rows(d);
    let n = rows.last().map_or(0, |r| r.0 as usize);
    (1..=n)
        .map(|t| match rows.iter().find(|r| r.0 as usize == t) {
            Some((_, h)) => {
                let addr = h.addr();
                let asn = addr.and_then(|a| c.known.names.get(&a)).and_then(|n| n.asn);
                HopLook { addr, answers: h.recv > 0, loss: h.loss(), asn, as_name: asn.and_then(|a| c.known.as_names.get(&a).cloned()).unwrap_or_default() }
            }
            None => HopLook::default(),
        })
        .collect()
}

fn name_of(c: &Ctx, a: IpAddr) -> String {
    if !c.names {
        return String::new();
    }
    match c.known.host(a) {
        Some(n) => n.to_string(),
        None if c.known.host_failed(a) => resolve::NAME_FAILED.into(),
        None => String::new(),
    }
}

fn as_of(c: &Ctx, a: Option<IpAddr>) -> (String, String) {
    a.map(|a| c.known.as_text(a)).unwrap_or_default()
}

/// A hop's note, as the trace report writes them: rate-limited, slow to answer, real loss.
fn notes(d: &Data) -> HashMap<u8, &'static str> {
    let rows = rows(d);
    let facts: Vec<HopFacts> = rows
        .iter()
        .map(|(_, h)| HopFacts { sent: h.sent.min(u32::MAX as u64) as u32, received: h.recv.min(u32::MAX as u64) as u32, avg_ms: h.avg_ms() })
        .collect();
    let reference = d.dest_ttl().and_then(|t| rows.iter().position(|r| r.0 == t)).or_else(|| rows.iter().rposition(|r| r.1.recv > 0));
    let v = stats::verdicts(&facts, reference);
    rows.iter()
        .zip(v)
        .map(|((t, h), v)| {
            let note = match (v.loss, v.slow) {
                _ if h.recv == 0 => "no reply",
                (LossClass::Limited, true) => "rate-limited, slow to answer",
                (LossClass::Limited, false) => "rate-limited",
                (LossClass::Real, _) => "real loss",
                (_, true) => "slow to answer",
                _ => "",
            };
            (*t, note)
        })
        .collect()
}

/// When an outage ended, as far as the log can say: its end, or (still out when the log
/// stopped, or now) the end of the log's last minute, never before its start. The bool: it is
/// that lower bound.
fn ended(d: &Data, o: &OutageRec) -> (u64, bool) {
    match o.end {
        Some(e) => (e.max(o.start), false),
        None => (d.last().unwrap_or(o.start).max(o.start), true),
    }
}

/// The outages in time order, and how long the destination was out in all (an outage with no
/// end seen counts to the end of the log).
fn outages(d: &Data) -> (Vec<&OutageRec>, u64) {
    let mut v: Vec<&OutageRec> = d.outages.values().collect();
    v.sort_by_key(|o| o.start);
    let total = v.iter().map(|o| ended(d, o).0 - o.start).sum();
    (v, total)
}

// ---------- the text ----------

/// The report as plain text (LF; saved with CRLF).
pub fn text(d: &Data, c: &Ctx) -> String {
    let local = c.local;
    let mut out = String::from("VibeTrace ISP log report\n\n");
    let family = if c.ipv6 { "IPv6" } else { "IPv4" };
    let addr = d.runs.last().map(|r| r.addr);
    let kv = |out: &mut String, k: &str, v: &str| out.push_str(&format!("{k:<11} {v}\n"));
    kv(&mut out, "Target", &match addr {
        Some(a) if a.to_string() != c.target => format!("{} ({a}), {family}", c.target),
        _ => format!("{}, {family}", c.target),
    });
    // The interfaces the runs left through (R-4), and what a tunnel means for the zones.
    let mut vias: Vec<(String, ViaKind)> = Vec::new();
    for v in d.runs.iter().filter_map(|r| r.via.as_ref()) {
        let name: String = resolve::clean_name(&v.name).chars().take(64).collect();
        if !name.is_empty() && !vias.iter().any(|x| x.0 == name) {
            vias.push((name, v.kind));
        }
    }
    if !vias.is_empty() {
        let names: Vec<&str> = vias.iter().map(|v| v.0.as_str()).collect();
        kv(&mut out, "Via", &if names.len() == 1 { names[0].to_string() } else { format!("{} (the log holds runs through each)", names.join(", ")) });
        for (name, kind) in &vias {
            match kind {
                ViaKind::Tunnel => kv(&mut out, "", &format!("{name} is a tunnel or virtual adapter: the zones below describe the tunnel, not the ISP")),
                ViaKind::Ppp => kv(&mut out, "", &format!("{name} is a PPP link (a VPN, or PPPoE dialled on this computer): if it is a VPN, the zones below describe the tunnel, not the ISP")),
                ViaKind::Adapter => {}
            }
        }
    }
    let (Some(first), Some(last)) = (d.first(), d.last()) else {
        out.push_str("\nThe log holds no minutes yet.\n");
        if let Some(w) = &c.left_out {
            out.push_str(&format!("Not included: {w}.\n"));
        }
        out.push_str(&format!("\nVibeTrace {}\n", crate::VERSION));
        return out;
    };
    let span = last - first;
    let covered = d.minutes.len() as u64 * 60_000;
    kv(&mut out, "Logged", &format!("{} to {} ({}); logging covered {} ({:.0} %)", stamp(&local(first)), until(first, last, local), dur(span), dur(covered), covered as f64 * 100.0 / span.max(1) as f64));
    let gaps = d.gaps();
    let from = gaps.len().saturating_sub(LIST_MAX);
    if from > 0 {
        kv(&mut out, "Not logging", &format!("… {} earlier gaps", from));
    }
    for (j, (a, b)) in gaps[from..].iter().enumerate() {
        let k = if j == 0 && from == 0 { "Not logging" } else { "" };
        // A gap that ends where the log followed the clock forward is the PC asleep or the
        // clock changed (R-6); any other is the log not running.
        let why = if d.stepped.contains(b) { "; PC asleep or clock changed" } else { "" };
        kv(&mut out, k, &format!("{} to {} ({}{why})", stamp(&local(*a)), until(*a, *b, local), dur(b - a)));
    }
    if let Some(r) = d.runs.last() {
        kv(&mut out, "Probes", &format!("ICMP echo to every hop, {} bytes every {}, timeout {} (no admin, Windows' ICMP API)", r.size, crate::view::interval(r.interval_ms), crate::view::interval(r.timeout_ms)));
        let other: BTreeSet<(u16, u32)> = d.runs.iter().map(|r| (r.size, r.interval_ms)).collect();
        if other.len() > 1 {
            kv(&mut out, "", &format!("(the log holds {} runs with other sizes or intervals)", d.runs.len()));
        }
    }
    kv(&mut out, "DNS checks", &format!("every {} s: the system resolver and {}, name {} ({})", isplog::DNS_EVERY_MS / 1000, crate::dnscheck::public_name(c.ipv6), crate::dnscheck::NAME, if c.ipv6 { "AAAA" } else { "A" }));
    let lk = looks(d, c);
    if let Some(r) = lk.first().and_then(|h| h.addr).filter(|_| isplog::own_router(&lk)) {
        kv(&mut out, "Your router", &format!("{r} (hop 1)"));
    }
    if let Some(e) = isplog::edge(&lk) {
        let a = lk[e].addr.map(|a| a.to_string()).unwrap_or_default();
        let isp = isplog::isp_as(&lk).map(|n| {
            let name = c.known.as_names.get(&n).cloned().unwrap_or_default();
            format!(", ISP AS{n}{}", if name.is_empty() { String::new() } else { format!(" {name}") })
        });
        kv(&mut out, "ISP edge", &format!("{a} (hop {}){}", e + 1, isp.unwrap_or_default()));
    }
    if let Some(w) = &c.left_out {
        kv(&mut out, "Not included", &format!("{w}: only the minutes not written yet are in this report"));
    }
    if c.dropped > 0 || d.skipped > 0 {
        let mut parts = Vec::new();
        if c.dropped > 0 {
            parts.push(format!("{} could not be written and went", plural(c.dropped as usize, "minute", "minutes")));
        }
        if d.skipped > 0 {
            parts.push(if d.skipped == 1 { "1 line in the file could not be read and was skipped".to_string() } else { format!("{} lines in the file could not be read and were skipped", d.skipped) });
        }
        kv(&mut out, "Missing", &parts.join("; "));
    }

    // ---- the summary ----
    out.push_str("\nSummary\n");
    let (os, total) = outages(d);
    if os.is_empty() {
        out.push_str("  No outages: the destination answered throughout.\n");
    } else {
        // When the destination does not answer pings, the last hop that does stood in for it.
        let who = if os.iter().all(|o| o.dest) {
            "The destination was"
        } else if os.iter().all(|o| !o.dest) {
            "The last hop that answers pings (the destination does not) was"
        } else {
            "The destination (or, while it did not answer pings, the last hop that does) was"
        };
        let open = if os.iter().any(|o| o.end.is_none()) { " (one with no end seen counted to the end of the log)" } else { "" };
        out.push_str(&format!(
            "  {who} unreachable {}, {} in all ({:.1} % of the logged time){open}.\n",
            plural(os.len(), "time", "times"),
            dur(total),
            (total as f64 * 100.0 / covered.max(1) as f64).min(100.0)
        ));
        // Where they broke, the most common place first.
        let mut places: Vec<(&str, &str, usize)> = Vec::new();
        for o in &os {
            match places.iter_mut().find(|p| p.1 == o.words) {
                Some(p) => p.2 += 1,
                None => places.push((o.zone.as_str(), o.words.as_str(), 1)),
            }
        }
        places.sort_by_key(|a| std::cmp::Reverse(a.2));
        for (zone, words, n) in places {
            let lead = match (zone, n == os.len(), n) {
                ("computer", true, 1) => "It was".to_string(),
                ("computer", _, n) => format!("{n} {}", if n == 1 { "was" } else { "were" }),
                (_, true, 1) => "It broke at".to_string(),
                (_, true, n) => format!("All {n} broke at"),
                (_, false, n) => format!("{n} broke at"),
            };
            let tail = match zone {
                "computer" | "router" => ": not the ISP",
                _ => "",
            };
            out.push_str(&format!("  {lead} {words}{tail}.\n"));
        }
    }
    if d.dest.sent > 0 {
        out.push_str(&format!("  Loss at the destination: {} of {} probes lost (outages included).\n", crate::view::loss_text(d.dest.loss()), d.dest.sent));
    }
    let (sf, pf) = (d.sys.failed(), d.public.failed());
    if !d.sys.checks.is_empty() || !d.public.checks.is_empty() {
        let pub_name = crate::dnscheck::public_name(c.ipv6);
        if sf == 0 && pf == 0 {
            out.push_str(&format!("  DNS: every check answered ({} through the system resolver, {} through {pub_name}).\n", d.sys.checks.len(), d.public.checks.len()));
        } else {
            let mut s = format!("  DNS: the system resolver failed {sf} of {} checks; {pub_name} failed {pf} of {}.", d.sys.checks.len(), d.public.checks.len());
            // Failures of the system resolver while the public one answered (same minute).
            let pub_ok: BTreeSet<u64> = d.public.checks.iter().filter(|x| matches!(x.1, DnsVal::Us(_))).map(|x| x.0 - x.0 % 60_000).collect();
            let alone = d.sys.checks.iter().filter(|x| matches!(x.1, DnsVal::Fail(_)) && pub_ok.contains(&(x.0 - x.0 % 60_000))).count();
            if alone > 0 {
                s.push_str(&format!(" {} while {pub_name} answered: the DNS server this computer uses, not the line.", plural(alone, "of the failures came", "of the failures came")));
            }
            out.push_str(&s);
            out.push('\n');
        }
    }

    // ---- the outages ----
    if !os.is_empty() {
        out.push_str("\nOutages (the destination lost probes in a row; when it broke, where)\n");
        let shown = &os[os.len().saturating_sub(OUTAGES_LISTED)..];
        if os.len() > OUTAGES_LISTED {
            out.push_str(&format!("  … {} earlier outages\n", os.len() - OUTAGES_LISTED));
        }
        out.push_str(&format!("  {:<19}  {:<19}  {:<12}  {}\n", "Start", "End", "Length", "Where it broke"));
        for o in shown {
            let (end, len) = match ended(d, o) {
                (e, false) => (until(o.start, e, local), dur(e - o.start)),
                (e, true) => ("(no end seen)".into(), format!("≥{}", dur(e - o.start))),
            };
            let note = o.note.as_deref().map(|n| format!(" ({n})")).unwrap_or_default();
            out.push_str(&format!("  {:<19}  {:<19}  {:<12}  {}{note}\n", stamp(&local(o.start)), end, len, o.words));
        }
    }

    // ---- the hops ----
    out.push_str("\nHops (the whole log; ms)\n");
    let notes = notes(d);
    let rows = rows(d);
    let hosts: Vec<String> = rows
        .iter()
        .map(|(_, h)| match h.addr() {
            None => "no reply".into(),
            Some(a) => {
                let n = name_of(c, a);
                if n.is_empty() { a.to_string() } else { format!("{n} ({a})") }
            }
        })
        .collect();
    let ases: Vec<String> = rows
        .iter()
        .map(|(_, h)| {
            let (num, name) = as_of(c, h.addr());
            if name.is_empty() { num } else { format!("{num} {name}") }
        })
        .collect();
    let hw = hosts.iter().map(|s| s.chars().count()).max().unwrap_or(4).clamp(4, 60);
    let aw = ases.iter().map(|s| s.chars().count()).max().unwrap_or(2).clamp(2, 28);
    let cut = |s: &str, w: usize| if s.chars().count() <= w { s.to_string() } else { s.chars().take(w - 1).collect::<String>() + "…" };
    out.push_str(&format!("  {:>3}  {:<hw$}  {:<aw$}  {:>8} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}\n", "#", "Host", "AS", "Sent", "Loss%", "Avg", "p50", "p95", "p99", "Worst"));
    for (i, (t, h)) in rows.iter().enumerate() {
        let line = format!(
            "  {:>3}  {:<hw$}  {:<aw$}  {:>8} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}  {}",
            t,
            cut(&hosts[i], hw),
            cut(&ases[i], aw),
            h.sent,
            crate::view::loss_cell(h.loss()),
            ms(h.avg_ms()),
            ms(h.pct(0.50)),
            ms(h.pct(0.95)),
            ms(h.pct(0.99)),
            ms((h.recv > 0).then(|| h.max as f64 / 1000.0)),
            notes.get(t).copied().unwrap_or("")
        );
        out.push_str(line.trim_end());
        out.push('\n');
    }

    // ---- the destination, hour by hour ----
    if !d.hours.is_empty() {
        out.push_str("\nThe destination hour by hour (ms)\n");
        out.push_str(&format!("  {:<16}  {:>6} {:>6} {:>6} {:>6}  {}\n", "Hour", "Sent", "Loss%", "Avg", "p95", "Outages"));
        for (start, h) in d.hours.values() {
            let w = local(*start);
            let n = os.iter().filter(|o| o.start >= *start && o.start < start + 3_600_000).count();
            let line = format!(
                "  {:04}-{:02}-{:02} {:02}:00  {:>6} {:>6} {:>6} {:>6}  {}",
                w.year,
                w.month,
                w.day,
                w.hour,
                h.sent,
                crate::view::loss_cell(h.loss()),
                ms(h.avg_ms()),
                ms(h.pct(0.95)),
                if n == 0 { String::new() } else { n.to_string() }
            );
            out.push_str(line.trim_end());
            out.push('\n');
        }
    }

    // ---- DNS ----
    if !d.sys.checks.is_empty() || !d.public.checks.is_empty() {
        out.push_str("\nDNS checks (ms)\n");
        out.push_str(&format!("  {:<28}  {:>6} {:>6} {:>6} {:>6}\n", "Resolver", "Checks", "Failed", "Avg", "p95"));
        for (name, a) in [("System resolver".to_string(), &d.sys), (crate::dnscheck::public_name(c.ipv6).to_string(), &d.public)] {
            let t = a.times();
            out.push_str(format!("  {:<28}  {:>6} {:>6} {:>6} {:>6}\n", name, a.checks.len(), a.failed(), ms(t.avg_ms()), ms(t.pct(0.95))).trim_end());
            out.push('\n');
        }
        let mut spells: Vec<(String, Spell)> = d.sys.spells().into_iter().map(|s| ("system resolver".to_string(), s)).collect();
        spells.extend(d.public.spells().into_iter().map(|s| (crate::dnscheck::public_name(c.ipv6).to_string(), s)));
        spells.sort_by_key(|s| s.1.start);
        if !spells.is_empty() {
            out.push_str("  Failures (to the minute)\n");
            if spells.len() > LIST_MAX {
                out.push_str(&format!("  … {} earlier\n", spells.len() - LIST_MAX));
            }
            for (who, s) in spells.iter().skip(spells.len().saturating_sub(LIST_MAX)) {
                let end = s.end.map_or("still failing".to_string(), |e| until(s.start, e, local));
                out.push_str(&format!("  {} to {}  {who}: {} ({})\n", stamp(&local(s.start)), end, s.why, plural(s.checks as usize, "check", "checks")));
            }
        }
    }

    // ---- how to read it ----
    out.push_str("\nHow to read this\n");
    out.push_str("  Outage: the destination lost probes in a row, more than its own normal loss explains\n");
    out.push_str("  (3 in a row when it loses nothing, up to 30 when it loses a lot; until its normal loss is known, 12).\n");
    out.push_str("  Where it broke: the first hop that stopped answering while every hop after it did too.\n");
    out.push_str("  rate-limited: loss that later hops do not show; the router answers pings slowly or rarely,\n");
    out.push_str("  the path is fine. slow to answer: slower than a later hop; traffic is not delayed.\n");
    out.push_str("  Percentiles come from 1/16-octave buckets: each is within 2.2 % of the measured value.\n");
    out.push_str("  They are per TTL over the whole log, replies only; a hop whose router changed mid-log blends both.\n");
    out.push_str("  A DNS check that fails can itself take up to about 12 s (Windows' resolver retries a dead server).\n");
    out.push_str(&format!("\nVibeTrace {}\n", crate::VERSION));
    out
}

// ---------- the CSV ----------

/// The report as CSV in the user's separators: blocks with their own header rows, an empty row
/// between them. UTF-8 with a BOM, CRLF.
pub fn csv(d: &Data, c: &Ctx, f: &CsvFormat) -> String {
    let local = c.local;
    let mut out = String::from("\u{FEFF}");
    let row = |out: &mut String, cells: &[(String, bool)]| {
        out.push_str(&cells.iter().map(|(v, t)| f.field(v, *t)).collect::<Vec<_>>().join(&f.sep));
        out.push_str("\r\n");
    };
    let s = |v: &str| (v.to_string(), false);
    let txt = |v: &str| (v.to_string(), true);
    let num = |v: Option<f64>, p: usize| (v.map(|v| f.num(v, p)).unwrap_or_default(), false);
    let at = |ms: u64| (stamp(&local(ms)), false);
    row(&mut out, &[s("item"), s("value")]);
    row(&mut out, &[s("report"), s("VibeTrace ISP log")]);
    row(&mut out, &[s("target"), txt(c.target)]);
    if let Some(r) = d.runs.last() {
        row(&mut out, &[s("address"), s(&r.addr.to_string())]);
        row(&mut out, &[s("probe_bytes"), s(&r.size.to_string())]);
        row(&mut out, &[s("interval_s"), num(Some(r.interval_ms as f64 / 1000.0), 1)]);
    }
    row(&mut out, &[s("family"), s(if c.ipv6 { "IPv6" } else { "IPv4" })]);
    if let (Some(a), Some(b)) = (d.first(), d.last()) {
        row(&mut out, &[s("from"), at(a)]);
        row(&mut out, &[s("to"), at(b)]);
        row(&mut out, &[s("logged_minutes"), s(&d.minutes.len().to_string())]);
    }
    let (os, total) = outages(d);
    row(&mut out, &[s("outages"), s(&os.len().to_string())]);
    row(&mut out, &[s("outage_s"), s(&(total / 1000).to_string())]);
    if let Some(w) = &c.left_out {
        row(&mut out, &[s("not_included"), txt(w)]);
    }
    row(&mut out, &[s("version"), s(crate::VERSION)]);
    out.push_str("\r\n");
    row(&mut out, &[s("hop"), s("address"), s("name"), s("asn"), s("as_name"), s("sent"), s("received"), s("loss_pct"), s("avg_ms"), s("p50_ms"), s("p95_ms"), s("p99_ms"), s("worst_ms"), s("note")]);
    let notes = notes(d);
    for (t, h) in rows(d) {
        let a = h.addr();
        let (asn, as_name) = as_of(c, a);
        let failed = |v: &str| if v == resolve::NAME_FAILED || v == resolve::AS_FAILED || v == resolve::AS_NAME_FAILED { "(lookup failed)".to_string() } else { v.to_string() };
        row(
            &mut out,
            &[
                s(&t.to_string()),
                s(&a.map(|a| a.to_string()).unwrap_or_default()),
                txt(&a.map(|a| failed(&name_of(c, a))).unwrap_or_default()),
                s(if asn == "private" { "" } else { asn.trim_start_matches("AS") }),
                txt(&if asn == "private" { "private".into() } else { failed(&as_name) }),
                s(&h.sent.to_string()),
                s(&h.recv.to_string()),
                num(Some(h.loss() * 100.0), 2),
                num(h.avg_ms(), 3),
                num(h.pct(0.50), 3),
                num(h.pct(0.95), 3),
                num(h.pct(0.99), 3),
                num((h.recv > 0).then(|| h.max as f64 / 1000.0), 3),
                s(notes.get(&t).copied().unwrap_or("")),
            ],
        );
    }
    out.push_str("\r\n");
    row(&mut out, &[s("outage_start"), s("outage_end"), s("length_s"), s("broke_at_hop"), s("address"), s("zone"), s("where")]);
    for o in &os {
        row(
            &mut out,
            &[
                at(o.start),
                o.end.map(at).unwrap_or_default(),
                s(&o.end.map(|e| (e.saturating_sub(o.start) / 1000).to_string()).unwrap_or_default()),
                s(&o.hop.map(|h| h.to_string()).unwrap_or_default()),
                s(&o.addr.map(|a| a.to_string()).unwrap_or_default()),
                s(&o.zone),
                txt(&format!("{}{}", o.words, o.note.as_deref().map(|n| format!(" ({n})")).unwrap_or_default())),
            ],
        );
    }
    out.push_str("\r\n");
    row(&mut out, &[s("hour"), s("sent"), s("loss_pct"), s("avg_ms"), s("p95_ms"), s("outages")]);
    for (start, h) in d.hours.values() {
        let n = os.iter().filter(|o| o.start >= *start && o.start < start + 3_600_000).count();
        row(&mut out, &[at(*start), s(&h.sent.to_string()), num(Some(h.loss() * 100.0), 2), num(h.avg_ms(), 3), num(h.pct(0.95), 3), s(&n.to_string())]);
    }
    out.push_str("\r\n");
    row(&mut out, &[s("dns_resolver"), s("checks"), s("failed"), s("avg_ms"), s("p95_ms")]);
    for (name, a) in [("system resolver", &d.sys), (crate::dnscheck::public_name(c.ipv6), &d.public)] {
        let t = a.times();
        row(&mut out, &[s(name), s(&a.checks.len().to_string()), s(&a.failed().to_string()), num(t.avg_ms(), 3), num(t.pct(0.95), 3)]);
    }
    out.push_str("\r\n");
    row(&mut out, &[s("dns_failure_start"), s("dns_failure_end"), s("resolver"), s("checks"), s("why")]);
    let mut spells: Vec<(&str, Spell)> = d.sys.spells().into_iter().map(|x| ("system resolver", x)).collect();
    spells.extend(d.public.spells().into_iter().map(|x| (crate::dnscheck::public_name(c.ipv6), x)));
    spells.sort_by_key(|x| x.1.start);
    for (who, sp) in spells {
        row(&mut out, &[at(sp.start), sp.end.map(at).unwrap_or_default(), s(who), s(&sp.checks.to_string()), txt(&sp.why)]);
    }
    out
}
