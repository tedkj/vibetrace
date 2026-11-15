//! The ISP log's pure core (SPEC §9): what goes into a minute record, the records on disk, the
//! latency histogram the percentiles come from, the outage rule, and where an outage broke.
//! No threads, no clocks, no I/O: the trace feeds it, `logfile` stores it, `ispreport` reads it.

use crate::dnscheck::{Check, Which};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;

/// The log file's format.
pub const LOG_VERSION: u32 = 1;
/// Fewest and most losses in a row that make an outage (`needed`).
pub const OUTAGE_MIN: u32 = 3;
pub const OUTAGE_MAX: u32 = 30;
/// The chance per probe of the reference's normal loss making the run: at most this.
pub const OUTAGE_CHANCE: f64 = 1e-6;
/// Outages and DNS failure spells kept per run (the newest).
pub const OUTAGES_MAX: usize = 1000;
pub const DNS_SPELLS_MAX: usize = 1000;
/// How often the DNS checks run while logging.
pub const DNS_EVERY_MS: u64 = 30_000;
/// A break hop that normally loses more than this is a rate limiter: said with a caveat.
pub const RATE_LIMITER: f64 = 0.05;
/// A router as the reference (the destination does not answer pings) answers in bursts: an
/// outage needs this many in a row from it at least.
pub const ROUTER_OUTAGE_MIN: u32 = 5;
/// Each hop's newest outcomes the trace keeps for the log (10 minutes at one probe a second),
/// logging or not: the outage rule's normal loss (from before the log too), and the hops'
/// answers since an outage began.
pub const SEEN: usize = 600;
/// Histogram buckets: 16 per octave of microseconds (u32 spans 32 octaves).
pub const BUCKETS: usize = 512;

/// The bucket of a round trip: 16 per doubling, so a bucket is 4.4 % wide and its middle is
/// within ±2.2 % of anything in it.
pub fn bucket(us: u32) -> u16 {
    if us <= 1 { 0 } else { (((us as f64).log2() * 16.0).floor() as usize).min(BUCKETS - 1) as u16 }
}

/// The middle of a bucket, in µs (geometric).
pub fn bucket_mid_us(b: u16) -> f64 {
    2f64.powf((b as f64 + 0.5) / 16.0)
}

/// Losses in a row the reference needs for an outage, given its normal loss `p`: the fewest
/// `k` with `p^k <= 10^-6`, from 3 to 30.
pub fn needed(p: f64) -> u32 {
    if p.is_nan() || p <= 0.0 {
        return OUTAGE_MIN;
    }
    if p >= 1.0 {
        return OUTAGE_MAX;
    }
    let k = (OUTAGE_CHANCE.ln() / p.ln() - 1e-9).ceil();
    (k.max(0.0) as u32).clamp(OUTAGE_MIN, OUTAGE_MAX)
}

/// A hop's normal outcomes in its ring (the first `before`, (session ms, answered)): sent and
/// lost, leaving out what was an outage, wherever it came from (an outage's misses are the
/// outage, not the line's usual loss): every run of `OUTAGE_MAX` or more losses in a row (an
/// outage under the rule at any `p`: one before the log, or a previous log's), and the
/// outcomes inside this log's outages (from their first loss, before the log too).
pub fn normal_counts(ring: &VecDeque<(u64, bool)>, before: usize, outages: &VecDeque<Outage>) -> (u32, u32) {
    let first = ring.front().map_or(0, |x| x.0);
    // Outages are in time order: only the newest can reach back into the ring.
    let spans: Vec<(u64, u64)> = outages.iter().rev().map(|o| (o.from_ms.min(o.start_ms), o.end_ms.unwrap_or(u64::MAX))).take_while(|s| s.1 > first).collect();
    let (mut sent, mut lost, mut run) = (0u32, 0u32, 0u32);
    let close = |run: &mut u32, sent: &mut u32, lost: &mut u32| {
        // A run that was an outage counts for nothing; a shorter one is loss.
        if *run < OUTAGE_MAX {
            *sent += *run;
            *lost += *run;
        }
        *run = 0;
    };
    for &(t, answered) in ring.iter().take(before) {
        if spans.iter().any(|s| t >= s.0 && t < s.1) {
            continue;
        }
        if answered {
            close(&mut run, &mut sent, &mut lost);
            sent += 1;
        } else {
            run += 1;
        }
    }
    close(&mut run, &mut sent, &mut lost);
    (sent, lost)
}

/// The outage rule's `p`: the reference's normal loss before the run (`normal_counts`), with
/// the prior of `stats::normal_loss` (little history is never "loses nothing").
pub fn rule_loss(ring: &VecDeque<(u64, bool)>, before: usize, outages: &VecDeque<Outage>) -> f64 {
    let (sent, lost) = normal_counts(ring, before, outages);
    crate::stats::normal_loss(sent, lost)
}

/// Addresses of this side of the router: RFC 1918, link-local, loopback, IPv6 ULA and
/// link-local. CGNAT (100.64/10) is not among them: it is the ISP's.
pub fn is_local_net(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_link_local() || a.is_loopback(),
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_local_net(IpAddr::V4(v4));
            }
            let s = a.segments();
            a.is_loopback() || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xfe00) == 0xfc00
        }
    }
}

// ---------- the records on disk ----------

/// One line of the log file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Record {
    Run(RunRec),
    Min(MinRec),
    Outage(OutageRec),
}

impl Record {
    /// The record's time (UTC ms).
    pub fn at(&self) -> u64 {
        match self {
            Record::Run(r) => r.at,
            Record::Min(m) => m.at,
            Record::Outage(o) => o.start,
        }
    }

    pub fn line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// The time the ring keeps a record by: an outage by its end (or start while open), so
    /// the end of an old outage written now is not taken for an old line.
    pub fn age_at(&self) -> u64 {
        match self {
            Record::Outage(o) => o.end.unwrap_or(o.start).max(o.start),
            r => r.at(),
        }
    }
}

/// A log started (or restarted with new options).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RunRec {
    pub v: u32,
    pub at: u64,
    pub target: String,
    pub addr: IpAddr,
    pub interval_ms: u32,
    pub size: u16,
    pub timeout_ms: u32,
    pub max_hops: u8,
    pub version: String,
    /// The interface the trace left through when the log began (R-4; none in older logs, or
    /// when Windows could not say).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<Via>,
}

/// An interface the trace leaves through: its name as Windows' network settings show it
/// ("Wi-Fi", "Ethernet 2", "Tailscale") and what it is.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Via {
    pub name: String,
    #[serde(default)]
    pub kind: ViaKind,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViaKind {
    /// A tunnel or virtual adapter (WireGuard, Tailscale, an IP-in-IP tunnel): the hops past
    /// this computer are the tunnel's, not the ISP's.
    Tunnel,
    /// PPP: a VPN of Windows' own, or PPPoE dialled on this computer (the interface does not
    /// say which).
    Ppp,
    /// A network adapter (Ethernet, Wi-Fi, mobile broadband); anything else in a file too.
    #[default]
    #[serde(other)]
    Adapter,
}

impl ViaKind {
    /// What an interface is, from its IANA type and tunnel type (`MIB_IF_ROW2`): a tunnel
    /// (IF_TYPE_TUNNEL, any tunnel type) or a virtual adapter of a VPN (IF_TYPE_PROP_VIRTUAL:
    /// Wintun, WireGuard), PPP, or an adapter.
    pub fn of(if_type: u32, tunnel_type: i32) -> ViaKind {
        use windows_sys::Win32::NetworkManagement::IpHelper::{IF_TYPE_PPP, IF_TYPE_PROP_VIRTUAL, IF_TYPE_TUNNEL};
        use windows_sys::Win32::NetworkManagement::Ndis::TUNNEL_TYPE_NONE;
        match if_type {
            IF_TYPE_TUNNEL | IF_TYPE_PROP_VIRTUAL => ViaKind::Tunnel,
            _ if tunnel_type != TUNNEL_TYPE_NONE => ViaKind::Tunnel,
            IF_TYPE_PPP => ViaKind::Ppp,
            _ => ViaKind::Adapter,
        }
    }
}

/// One minute (UTC, `at` its start).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MinRec {
    pub at: u64,
    /// The destination's TTL in that minute (none: it did not answer and was never found).
    #[serde(default)]
    pub dest: Option<u8>,
    #[serde(default)]
    pub hops: Vec<HopRec>,
    /// The DNS checks of that minute: system resolver, public resolver.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ds: Vec<DnsVal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dp: Vec<DnsVal>,
    /// The clock jumped forward before this minute while logging (the PC slept, or the clock
    /// was set forward: the log followed the wall clock, R-6): a gap before it is that.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stepped: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One hop in one minute.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HopRec {
    pub ttl: u8,
    /// The address that answered most in that minute.
    #[serde(default)]
    pub addr: Option<IpAddr>,
    pub sent: u32,
    pub recv: u32,
    /// Probes that could not leave this computer (no route).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub local: u32,
    #[serde(default)]
    pub min: u32,
    #[serde(default)]
    pub max: u32,
    #[serde(default)]
    pub sum: u64,
    /// (bucket, count), buckets ascending.
    #[serde(default)]
    pub h: Vec<(u16, u32)>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// A DNS check in a minute record: the round trip in µs, or why it failed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DnsVal {
    Us(u32),
    Fail(String),
}

impl From<&Check> for DnsVal {
    fn from(c: &Check) -> Self {
        match c {
            Ok(us) => DnsVal::Us(*us),
            Err(e) => DnsVal::Fail(e.clone()),
        }
    }
}

/// An outage as recorded: written when it is found (`end` none) and again when it ends; the
/// last record of an `id` is the one that counts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OutageRec {
    pub id: u64,
    pub start: u64,
    #[serde(default)]
    pub end: Option<u64>,
    /// The reference's TTL, and whether it is the destination.
    pub ttl: u8,
    pub dest: bool,
    /// The break hop's TTL and address.
    #[serde(default)]
    pub hop: Option<u8>,
    #[serde(default)]
    pub addr: Option<IpAddr>,
    pub zone: String,
    pub words: String,
    /// "still out when the log stopped" and the like.
    #[serde(default)]
    pub note: Option<String>,
}

// ---------- a minute being filled ----------

/// One hop's probes in the minute being filled.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HopAcc {
    pub sent: u32,
    pub recv: u32,
    pub local: u32,
    pub min: u32,
    pub max: u32,
    pub sum: u64,
    /// (bucket, count), ascending.
    pub hist: Vec<(u16, u32)>,
    pub addrs: Vec<(IpAddr, u32)>,
}

impl HopAcc {
    pub fn reply(&mut self, from: IpAddr, us: u32) {
        self.sent += 1;
        self.recv += 1;
        self.min = if self.recv == 1 { us } else { self.min.min(us) };
        self.max = self.max.max(us);
        self.sum += us as u64;
        let b = bucket(us);
        match self.hist.binary_search_by_key(&b, |x| x.0) {
            Ok(i) => self.hist[i].1 += 1,
            Err(i) => self.hist.insert(i, (b, 1)),
        }
        match self.addrs.iter_mut().find(|a| a.0 == from) {
            Some(a) => a.1 += 1,
            None => self.addrs.push((from, 1)),
        }
    }

    pub fn lost(&mut self, local: bool) {
        self.sent += 1;
        if local {
            self.local += 1;
        }
    }

    fn rec(&self, ttl: u8) -> HopRec {
        let mut best: Option<(IpAddr, u32)> = None;
        for a in &self.addrs {
            if best.is_none_or(|b| a.1 > b.1) {
                best = Some(*a);
            }
        }
        HopRec { ttl, addr: best.map(|b| b.0), sent: self.sent, recv: self.recv, local: self.local, min: self.min, max: self.max, sum: self.sum, h: self.hist.clone() }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MinuteAcc {
    pub hops: BTreeMap<u8, HopAcc>,
    /// The lowest TTL an echo came from in this minute.
    pub dest: Option<u8>,
    pub ds: Vec<DnsVal>,
    pub dp: Vec<DnsVal>,
}

impl MinuteAcc {
    pub fn rec(&self, minute: u64, dest_now: Option<u8>) -> MinRec {
        MinRec {
            at: minute * 60_000,
            dest: self.dest.or(dest_now),
            hops: self.hops.iter().map(|(t, h)| h.rec(*t)).collect(),
            ds: self.ds.clone(),
            dp: self.dp.clone(),
            stepped: false,
        }
    }
}

// ---------- outages and DNS spells, while the log runs ----------

/// An outage seen by this run (session milliseconds, as the trace counts).
#[derive(Clone, Debug, PartialEq)]
pub struct Outage {
    /// Unique in the run: its start's UTC ms.
    pub id: u64,
    pub start_ms: u64,
    pub end_ms: Option<u64>,
    /// The reference's TTL when it was found.
    pub ttl: u8,
    pub dest: bool,
    /// Per hop index (0..ttl): probes sent in the outage and replies they got.
    pub probes: Vec<u32>,
    pub replies: Vec<u32>,
    /// A probe could not leave this computer meanwhile (its ICMP status).
    pub local: Option<u32>,
    /// The log ended while it lasted.
    pub stopped: bool,
    /// It was already under way when the log began (its start is the log's).
    pub before_log: bool,
    /// Its first loss (session ms), before the log too: what the rule leaves out of the line's
    /// normal loss.
    pub from_ms: u64,
}

/// One DNS resolver's failures: from the first failed check to the next good one.
#[derive(Clone, Debug, PartialEq)]
pub struct DnsSpell {
    pub start_ms: u64,
    pub end_ms: Option<u64>,
    pub checks: u32,
    pub why: String,
}

#[derive(Clone, Debug, Default)]
pub struct DnsTrack {
    /// The newest check: when (session ms) and what it gave.
    pub last: Option<(u64, Check)>,
    pub spells: VecDeque<DnsSpell>,
    pub checks: u32,
    pub failed: u32,
}

impl DnsTrack {
    pub fn failing(&self) -> bool {
        self.last.as_ref().is_some_and(|l| l.1.is_err())
    }

    fn add(&mut self, at_ms: u64, c: &Check) {
        self.checks += 1;
        match c {
            Ok(_) => {
                if let Some(s) = self.spells.back_mut().filter(|s| s.end_ms.is_none()) {
                    s.end_ms = Some(at_ms);
                }
            }
            Err(why) => {
                self.failed += 1;
                match self.spells.back_mut().filter(|s| s.end_ms.is_none()) {
                    Some(s) => {
                        s.checks += 1;
                        s.why = why.clone();
                    }
                    None => {
                        self.spells.push_back(DnsSpell { start_ms: at_ms, end_ms: None, checks: 1, why: why.clone() });
                        while self.spells.len() > DNS_SPELLS_MAX {
                            self.spells.pop_front();
                        }
                    }
                }
            }
        }
        self.last = Some((at_ms, c.clone()));
    }
}

/// A run of the ISP log: the minutes being filled, the outages, the DNS checks. Lives in the
/// `Trace` (the probers feed it under the trace's lock).
#[derive(Clone, Debug, Default)]
pub struct LogState {
    /// The controller's number for this run (its answers carry it).
    pub run: u64,
    /// Session ms when the log began.
    pub since_ms: u64,
    /// UTC minute -> what it holds so far.
    pub minutes: BTreeMap<u64, MinuteAcc>,
    pub outages: VecDeque<Outage>,
    pub outages_dropped: u32,
    /// The open outage's id.
    pub open: Option<u64>,
    /// Outages found or ended since the controller last looked (ids): records to write.
    pub changed: Vec<u64>,
    pub dns: [DnsTrack; 2],
    /// The wall clock was followed forward at these UTC ms (`Trace::reanchor`: a sleep, a
    /// clock set forward): the first minute written that ends after one says so (`stepped`).
    pub steps: Vec<u64>,
}

impl LogState {
    pub fn new(run: u64, since_ms: u64) -> LogState {
        LogState { run, since_ms, ..LogState::default() }
    }

    pub fn minute(&mut self, unix_ms: u64) -> &mut MinuteAcc {
        self.minutes.entry(unix_ms / 60_000).or_default()
    }

    pub fn outage(&self, id: u64) -> Option<&Outage> {
        self.outages.iter().find(|o| o.id == id)
    }

    pub fn outage_mut(&mut self, id: u64) -> Option<&mut Outage> {
        self.outages.iter_mut().find(|o| o.id == id)
    }

    /// A new outage; past `OUTAGES_MAX` the oldest ended ones go (counted).
    pub fn push_outage(&mut self, o: Outage) {
        self.changed.push(o.id);
        self.open = Some(o.id);
        self.outages.push_back(o);
        while self.outages.len() > OUTAGES_MAX {
            match self.outages.iter().position(|x| Some(x.id) != self.open) {
                Some(i) => {
                    let gone = self.outages.remove(i).map(|x| x.id);
                    self.changed.retain(|c| Some(*c) != gone);
                    self.outages_dropped += 1;
                }
                None => break,
            }
        }
    }

    /// A DNS check's result (`at_ms`: when it started, session ms; `unix_ms` the same in UTC).
    pub fn dns_check(&mut self, which: Which, at_ms: u64, unix_ms: u64, c: &Check) {
        let m = self.minute(unix_ms);
        match which {
            Which::System => m.ds.push(c.into()),
            Which::Public => m.dp.push(c.into()),
        }
        self.dns[which as usize].add(at_ms, c);
    }

    /// The log ends: an open outage is recorded as still out.
    pub fn end(&mut self) {
        if let Some(id) = self.open.take()
            && let Some(o) = self.outage_mut(id)
        {
            o.stopped = true;
            self.changed.push(id);
        }
    }
}

// ---------- where an outage broke ----------

/// What `locate` needs of each hop up to the reference.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HopLook {
    pub addr: Option<IpAddr>,
    /// It answers pings at all (hops that never do are skipped).
    pub answers: bool,
    /// Its loss over the trace (a rate limiter loses a lot without a break).
    pub loss: f64,
    pub asn: Option<u32>,
    pub as_name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Zone {
    ThisComputer,
    Router,
    OwnNetwork,
    IspEdge,
    InsideIsp,
    BeyondIsp,
    PastEdge,
    Destination,
}

impl Zone {
    pub fn code(self) -> &'static str {
        match self {
            Zone::ThisComputer => "computer",
            Zone::Router => "router",
            Zone::OwnNetwork => "network",
            Zone::IspEdge => "isp-edge",
            Zone::InsideIsp => "isp",
            Zone::BeyondIsp => "beyond",
            Zone::PastEdge => "past-edge",
            Zone::Destination => "destination",
        }
    }

    /// A zone code read back from a log file, as one of the codes VibeTrace writes; anything
    /// else (a hand-edited or hostile file) is "" (somewhere not known), so it never reaches a
    /// report or the CSV as it was (IN-VibeTrace-2).
    pub fn known_code(code: &str) -> &'static str {
        [Zone::ThisComputer, Zone::Router, Zone::OwnNetwork, Zone::IspEdge, Zone::InsideIsp, Zone::BeyondIsp, Zone::PastEdge, Zone::Destination].into_iter().map(Zone::code).find(|c| *c == code).unwrap_or("")
    }

    /// The zone in a few words, for the report's summary ("at the ISP's edge").
    pub fn phrase(code: &str) -> &'static str {
        match code {
            "computer" => "on this computer (no network)",
            "router" => "at your router",
            "network" => "at a private address past your router",
            "isp-edge" => "at the ISP's edge",
            "isp" => "inside the ISP",
            "beyond" => "beyond the ISP",
            "past-edge" => "past the ISP's edge",
            "destination" => "at the destination",
            _ => "somewhere not known",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Located {
    /// The break hop's index.
    pub hop: Option<usize>,
    pub addr: Option<IpAddr>,
    pub zone: Zone,
    pub words: String,
}

/// Whether hop 1 is this side's router: a private or link-local address (IPv4), or any IPv6
/// address (an IPv6 router answers from its global one). A public IPv4 hop 1 is the ISP's own
/// gateway (a bridged modem).
pub fn own_router(hops: &[HopLook]) -> bool {
    hops.first().and_then(|h| h.addr).is_none_or(|a| a.is_ipv6() || is_local_net(a))
}

/// The first hop past this side's own network (the ISP's edge), if any.
pub fn edge(hops: &[HopLook]) -> Option<usize> {
    let from = if own_router(hops) { 1 } else { 0 };
    hops.iter().enumerate().skip(from).position(|(_, h)| h.answers && h.addr.is_some_and(|a| !is_local_net(a))).map(|p| p + from)
}

/// The ISP's AS: the first known AS at or after the edge.
pub fn isp_as(hops: &[HopLook]) -> Option<u32> {
    let e = edge(hops)?;
    hops[e..].iter().find_map(|h| h.asn)
}

/// The zone of hop `k` on this path.
pub fn zone_of(hops: &[HopLook], k: usize) -> Zone {
    let e = edge(hops);
    if k == 0 && own_router(hops) {
        return Zone::Router;
    }
    match e {
        None => return Zone::OwnNetwork,
        Some(e) if k < e => return Zone::OwnNetwork,
        Some(e) if k == e => return Zone::IspEdge,
        _ => {}
    }
    let isp = isp_as(hops);
    let h = &hops[k];
    match (h.asn, isp) {
        (Some(a), Some(i)) if a == i => Zone::InsideIsp,
        (Some(_), Some(_)) => Zone::BeyondIsp,
        _ if h.addr.is_some_and(crate::resolve::is_private) => Zone::InsideIsp,
        _ => Zone::PastEdge,
    }
}

/// Where an outage broke (SPEC §9.3): `hops` up to and including the reference, the outage's
/// per-hop probes and replies, the reference's index and whether it is the destination, and
/// the ICMP words when probes could not leave this computer.
pub fn locate(hops: &[HopLook], o: &Outage, local: Option<&str>) -> Located {
    if hops.is_empty() {
        return Located { hop: None, addr: None, zone: if local.is_some() { Zone::ThisComputer } else { Zone::Destination }, words: "no hop answered before it".into() };
    }
    let r = (o.ttl as usize).saturating_sub(1).min(hops.len().saturating_sub(1));
    let replies = |i: usize| o.replies.get(i).copied().unwrap_or(0);
    let addr_of = |i: usize| hops.get(i).and_then(|h| h.addr);
    if let Some(w) = local
        && replies(0) == 0
    {
        return Located { hop: None, addr: None, zone: Zone::ThisComputer, words: format!("this computer: its probes could not leave ({w})") };
    }
    // Walking back from the reference over the hops that answer pings: the lowest of those
    // with no reply, every later one silent too.
    let mut k = r;
    for i in (0..r).rev() {
        if !hops.get(i).is_some_and(|h| h.answers) {
            continue;
        }
        if replies(i) == 0 {
            k = i;
        } else {
            break;
        }
    }
    let a = addr_of(k);
    let at = a.map(|a| a.to_string()).unwrap_or_else(|| "no address".into());
    let n = k + 1;
    // Hops just before it that never answer pings: the break may be at one of them (R-9).
    let quiet = (0..k).rev().take_while(|i| !hops.get(*i).is_some_and(|h| h.answers)).count();
    let maybe = match quiet {
        0 => String::new(),
        1 => format!(" (hop {} does not answer pings: it may be there)", k),
        q => format!(" (hops {} to {} do not answer pings: it may be there)", k + 1 - q, k),
    };
    if k == r && o.dest {
        let words = if k == 0 { format!("the destination itself (hop 1, {at})") } else { format!("the destination itself (hop {n}, {at}): every hop before it answered{maybe}") };
        return Located { hop: Some(k), addr: a, zone: Zone::Destination, words };
    }
    let zone = zone_of(hops, k);
    let h = &hops[k];
    let as_text = match (h.asn, h.as_name.is_empty()) {
        (Some(x), true) => format!(", AS{x}"),
        (Some(x), false) => format!(", AS{x} {}", h.as_name),
        _ => String::new(),
    };
    let mut words = match zone {
        Zone::Router => format!("hop 1, your router or the link to it ({at})"),
        Zone::OwnNetwork => format!("hop {n}, a private address past your router: your network, or the ISP's private addressing ({at})"),
        Zone::IspEdge => format!("hop {n}, the ISP's edge ({at})"),
        Zone::InsideIsp => format!("hop {n}, inside the ISP ({at}{as_text})"),
        Zone::BeyondIsp => format!("hop {n}, beyond the ISP ({at}{as_text})"),
        Zone::PastEdge => format!("hop {n}, past the ISP's edge ({at}; AS not known)"),
        Zone::ThisComputer | Zone::Destination => format!("hop {n} ({at})"),
    };
    words.push_str(&maybe);
    if h.loss > RATE_LIMITER {
        words.push_str(" (it rate-limits its answers: the break may be just after it)");
    }
    Located { hop: Some(k), addr: a, zone, words }
}
