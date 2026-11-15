//! Path MTU per hop (SPEC §10): the largest packet (total IP size) that gets to each hop of the
//! path, and where the size drops, with DF-set ICMP echoes (IPv4) through the same ICMP API as
//! the trace. No admin rights.
//!
//! `Mtu` is a step machine: `next` says which probe to send, `answer` takes what came back. It
//! never sleeps and never touches the network, so it is tested probe by probe against the fake
//! network; `MtuRun::spawn` runs it on a thread at a low rate (one probe at a time, at least 1 s
//! apart to the same hop and 250 ms apart in all).
//!
//! The scan goes forward, hop by hop, with the largest size still possible (this computer's
//! link MTU at first). Sizes only shrink along the path, so a size that got to hop k-1 and not
//! to hop k drops on the link into hop k, and nothing bigger ever needs sending again: which
//! matters, because after a "too big" Windows remembers the path MTU per destination and will
//! not send (IPv4) or would split (IPv6) anything bigger to it. A "fragmentation needed" /
//! "packet too big" names the router before the narrow link, and Windows' path cache then
//! holds the MTU it reported: the scan goes on with that. A size that simply gets no answer is
//! checked against small probes (rate limiting is not size), and then a binary search finds the
//! largest size that does get there: a black hole.

use crate::trace::{Kind, Network, Opts, Outcome, Prober};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows_sys::Win32::NetworkManagement::IpHelper::IP_PACKET_TOO_BIG;

/// The largest link MTU searched (jumbo frames); a link that says more is taken as this.
pub const MAX_MTU: u32 = 9000;
/// When this computer's link MTU cannot be read.
pub const DEFAULT_LINK: u32 = 1500;
pub const MIN_V4: u32 = 68;
/// Every IPv6 link carries at least this (RFC 8200).
pub const MIN_V6: u32 = 1280;
/// The small probe that tells rate limiting from size: the trace's own 56-byte payload.
pub const SMALL_PAYLOAD: u16 = 56;
/// The chance per probe of a hop's own loss making a size look too big: at most this.
pub const SIZE_CHANCE: f64 = 1e-3;
/// Big probes lost in a row before a size counts as not getting there: at least, at most.
pub const STRIKES_MIN: u32 = 3;
pub const STRIKES_MAX: u32 = 12;
/// Small probes lost in a row before a hop counts as not answering now.
pub const QUIET: u32 = 3;
/// A run stops after this many probes (and says so).
pub const MAX_PROBES: u32 = 200;
/// The pace: to the same hop, and between any two probes.
pub const SAME_HOP_MS: u64 = 1000;
pub const ANY_MS: u64 = 250;
pub const TIMEOUT_MS: u32 = 2000;

/// IP and ICMP headers on top of the payload.
pub fn header(ipv6: bool) -> u32 {
    if ipv6 { 48 } else { 28 }
}

/// Big probes lost in a row a hop needs before their size counts as not getting there, given
/// the share `p` of its small probes that went unanswered: the fewest `k` with `p^k <= 10^-3`,
/// from 3 to 12. A clean router: 3. One answering half its probes: 10.
pub fn strikes(p: f64) -> u32 {
    if p.is_nan() || p <= 0.0 {
        return STRIKES_MIN;
    }
    if p >= 1.0 {
        return STRIKES_MAX;
    }
    let k = (SIZE_CHANCE.ln() / p.ln() - 1e-9).ceil();
    (k.max(0.0) as u32).clamp(STRIKES_MIN, STRIKES_MAX)
}

/// Why packets over a drop's size do not get to its hop.
#[derive(Clone, Debug, PartialEq)]
pub enum Why {
    /// A router said "fragmentation needed" / "packet too big"; Windows' cache then held `mtu`.
    FragNeeded { from: IpAddr, mtu: Option<u32> },
    /// No answer to big probes while small ones were answered: a black hole (or a filter).
    Silent,
    /// A router answered big probes with an unreachable ("prohibited by a filter", "host
    /// unreachable": its ICMP status) while small ones got through: it refuses packets over
    /// the size (a filter on size, R-14), and the scan goes on past it.
    Refused { from: IpAddr, status: u32 },
    /// Windows' path cache held a smaller path MTU (learned before the run, or from other
    /// traffic meanwhile; the cause is not known): where it drops is not known.
    /// is not known.
    Cache,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HopState {
    Waiting,
    Probing,
    Done,
    /// No answer even to small probes (rate limiting, a busy router).
    NotMeasured,
    /// It loses so many of its pings, outages left out, that big probes going unanswered
    /// cannot be told from its usual loss: not measured (no verdict, no cause claimed).
    Lossy,
    /// It never answers pings: not probed.
    Silent,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HopMtu {
    /// The largest size that gets here.
    pub value: Option<u32>,
    /// `value` is only a lower bound: Windows would not send anything bigger to the
    /// destination any more (its path cache), so more could not be tried.
    pub at_least: bool,
    /// Not measured but known: the measured hops on both sides carry the same.
    pub inferred: bool,
    pub state: HopState,
}

/// What the run is told about the path when it starts.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Plan {
    pub ipv6: bool,
    /// The hop judged: the destination, or the last that answers.
    pub reference: usize,
    pub dest: bool,
    /// Per hop index up to the reference: it answers pings.
    pub answers: Vec<bool>,
    /// Per hop: the addresses it answered from (to place a "too big" sender on the path).
    pub addrs: Vec<Vec<IpAddr>>,
    /// This computer's link MTU (None: not readable).
    pub link: Option<u32>,
    /// Windows' path MTU for the destination when the run starts.
    pub cached: Option<u32>,
    /// Per hop index: the trace's probes sent and answered there (its normal loss, which a
    /// lost big probe is judged against; the scan's own small probes add to it).
    pub loss: Vec<(u32, u32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    pub hop: usize,
    pub ttl: u8,
    /// Total IP size.
    pub size: u32,
    pub payload: u16,
    pub df: bool,
    pub small: bool,
}

/// Where the size drops: the first hop packets over `size` do not get to.
#[derive(Clone, Debug, PartialEq)]
pub struct Drop {
    /// That hop (None: not known, Windows learned it earlier).
    pub hop: Option<usize>,
    /// The measured hop before it (None: this computer).
    pub after: Option<usize>,
    /// The largest size that gets to `hop` (when known), and the one that got to `after`.
    pub size: Option<u32>,
    pub above: u32,
    pub why: Why,
    /// Hops between `after` and `hop` do not answer pings: it drops somewhere among them.
    pub silent_between: bool,
}

/// Checking whether a big size that went unanswered really does not get there.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Check {
    /// Bigs lost in a row at this size.
    lost: u32,
    /// The round (1, 2, 3...): round r sends r bigs back to back, then one small, so a router
    /// that answers every n-th probe cannot hide a size in its rhythm.
    round: u32,
    bigs_left: u32,
    small_due: bool,
    /// Smalls lost in a row.
    quiet: u32,
    /// The size tried was answered with an unreachable (who, its status): the small probe due
    /// now tells a filter on size (answered) from the path failing there (refused too).
    refused: Option<(IpAddr, u32)>,
}

#[derive(Clone, Debug)]
pub struct Mtu {
    pub plan: Plan,
    pub hops: Vec<HopMtu>,
    /// This computer's own link MTU.
    pub link: u32,
    /// The size being tried along the path (only shrinks).
    pub size: u32,
    /// The size is a lower bound from here on (Windows' cache).
    capped: bool,
    pub min: u32,
    pub drops: Vec<Drop>,
    pub probes: u32,
    pub done: bool,
    /// Why the run stopped early (an unreachable, no route), in words.
    pub error: Option<String>,
    /// Things worth saying (the link MTU unknown, the cache, the probe cap).
    pub notes: Vec<String>,
    /// The hop being scanned.
    k: usize,
    check: Check,
    /// A binary search for the largest size that gets to hop `k` (lo gets there, hi might).
    search: Option<(u32, u32)>,
    /// Per hop: small probes sent and answered (its own loss, for `strikes`, with the trace's).
    smalls: Vec<(u32, u32)>,
}

impl Mtu {
    pub fn new(plan: Plan) -> Mtu {
        let min = if plan.ipv6 { MIN_V6 } else { MIN_V4 };
        let mut notes = Vec::new();
        let link = match plan.link {
            Some(l) => l.clamp(min, MAX_MTU),
            None => {
                notes.push(format!("This computer's link MTU could not be read: searched up to {DEFAULT_LINK} bytes."));
                DEFAULT_LINK
            }
        };
        let n = plan.reference + 1;
        let hops = (0..n)
            .map(|i| {
                let answers = i == plan.reference || plan.answers.get(i).copied().unwrap_or(false);
                HopMtu { value: None, at_least: false, inferred: false, state: if answers { HopState::Waiting } else { HopState::Silent } }
            })
            .collect();
        let mut m = Mtu {
            hops,
            link,
            size: link,
            capped: false,
            min,
            drops: Vec::new(),
            probes: 0,
            done: false,
            error: None,
            notes,
            k: 0,
            check: Check::default(),
            search: None,
            smalls: vec![(0, 0); n],
            plan,
        };
        let cached = m.plan.cached;
        m.cache(cached, true);
        m
    }

    /// The hop being probed now.
    pub fn probing(&self) -> Option<usize> {
        (!self.done && self.k < self.hops.len()).then_some(self.k)
    }

    /// The hop being probed and the size tried there (the status line).
    pub fn current(&self) -> Option<(usize, u32)> {
        self.probing().map(|k| (k, self.trying()))
    }

    /// The path MTU to the reference, once known.
    pub fn path_mtu(&self) -> Option<u32> {
        self.hops.last().and_then(|h| h.value)
    }

    /// Windows' path cache says nothing bigger than `c` goes out unsplit to the destination
    /// (at the start: learned earlier; later: learned from other traffic meanwhile). From here
    /// on the size is at most `c`, and a hop passing `c` may carry more.
    fn cache(&mut self, c: Option<u32>, start: bool) {
        let Some(c) = c.filter(|c| *c >= self.min && *c < self.size) else { return };
        self.size = c;
        self.capped = true;
        self.notes.push(if start {
            format!("Windows' path cache already held {c} bytes for this destination (learned before this scan): nothing bigger was sent.")
        } else {
            format!("Windows' path cache dropped to {c} bytes for this destination during the scan: nothing bigger was sent after.")
        });
        if !self.drops.iter().any(|d| d.why == Why::Cache) {
            self.drops.push(Drop { hop: None, after: None, size: Some(c), above: self.link, why: Why::Cache, silent_between: false });
        }
    }

    fn probe(&self, k: usize, size: u32, small: bool) -> Probe {
        let ttl = if k == self.plan.reference && self.plan.dest { 64 } else { (k + 1).min(255) as u8 };
        let size = if small { SMALL_PAYLOAD as u32 + header(self.plan.ipv6) } else { size };
        Probe { hop: k, ttl, size, payload: (size - header(self.plan.ipv6)) as u16, df: !self.plan.ipv6, small }
    }

    /// The size tried at hop `k` now: the scan's, or the binary search's middle.
    fn trying(&self) -> u32 {
        match self.search {
            Some((lo, hi)) => lo + (hi - lo).div_ceil(2),
            None => self.size,
        }
    }

    /// The next probe to send, or None when the run is over. `cached`: Windows' path MTU for
    /// the destination now (read right before).
    pub fn next(&mut self, cached: Option<u32>) -> Option<Probe> {
        if self.done {
            return None;
        }
        if self.probes >= MAX_PROBES {
            self.notes.push(format!("Stopped after {MAX_PROBES} probes: hops without a number were not finished."));
            self.finish();
            return None;
        }
        // Windows' path cache before every probe: learned meanwhile (another program's traffic,
        // a "too big" that came back late), nothing bigger may be sent (IPv6 would split it
        // and the probe pass, wrongly).
        let before = self.trying();
        self.cache(cached, false);
        if let (Some((lo, hi)), Some(c)) = (self.search, cached.filter(|c| *c >= self.min))
            && c < hi
        {
            self.search = Some((lo.min(c), c));
        }
        if self.trying() != before {
            self.check = Check::default();
        }
        loop {
            if self.k >= self.hops.len() {
                self.finish();
                return None;
            }
            let k = self.k;
            if self.hops[k].state == HopState::Silent {
                self.k += 1;
                continue;
            }
            if let Some((lo, hi)) = self.search
                && lo >= hi
            {
                // Found: the largest size that gets here (none, when even the floor did not).
                if lo < self.floor() {
                    self.not_measured(k);
                } else {
                    self.settle(k, lo);
                }
                continue;
            }
            self.hops[k].state = HopState::Probing;
            if self.check.small_due {
                return Some(self.probe(k, 0, true));
            }
            let s = self.trying();
            return Some(self.probe(k, s, false));
        }
    }

    /// Hop `k` carries `v`: on to the next hop, with `v` as the size from here.
    fn settle(&mut self, k: usize, v: u32) {
        self.hops[k].value = Some(v);
        // Capped by Windows' cache, a hop may carry more than it was tried with; the reference
        // carries what the cache says (a router reported it, minutes ago at most).
        self.hops[k].at_least = self.capped && v >= self.size && k != self.plan.reference;
        self.hops[k].state = HopState::Done;
        if let Some(d) = self.drops.iter_mut().rev().find(|d| d.hop == Some(k) && d.size.is_none()) {
            d.size = Some(v);
        }
        self.size = self.size.min(v);
        self.search = None;
        self.check = Check::default();
        self.k = k + 1;
    }

    /// The measured hop before `k` (None: this computer), and whether hops between did not
    /// answer (the drop is somewhere among them).
    fn before(&self, k: usize) -> (Option<usize>, bool) {
        let after = (0..k).rev().find(|j| self.hops[*j].value.is_some());
        let from = after.map_or(0, |a| a + 1);
        (after, (from..k).any(|j| self.hops[j].value.is_none()))
    }

    fn add_drop(&mut self, k: usize, why: Why, size: Option<u32>) {
        if self.drops.iter().any(|d| d.hop == Some(k)) {
            return;
        }
        let (after, silent_between) = self.before(k);
        let above = after.and_then(|a| self.hops[a].value).unwrap_or(self.link);
        self.drops.push(Drop { hop: Some(k), after, size, above, why, silent_between });
    }

    fn finish(&mut self) {
        self.done = true;
        for h in &mut self.hops {
            if h.state == HopState::Probing || h.state == HopState::Waiting {
                h.state = if h.value.is_some() { HopState::Done } else { HopState::Waiting };
            }
        }
        // A hop not measured between two that carry the same carries it too.
        for k in 0..self.hops.len() {
            if self.hops[k].value.is_some() {
                continue;
            }
            let before = (0..k).rev().find_map(|j| self.hops[j].value).unwrap_or(self.link);
            let after = (k + 1..self.hops.len()).find_map(|j| self.hops[j].value);
            // Equal on both sides: no drop between them, so this one carries it too.
            if after == Some(before) {
                self.hops[k].value = Some(before);
                self.hops[k].inferred = true;
            }
        }
    }

    /// Hop `k`'s normal loss: the trace's probes there and the scan's small ones, with the
    /// prior of `stats::normal_loss` (little history is never "loses nothing").
    fn normal_loss(&self, k: usize) -> f64 {
        let (ts, tr) = self.plan.loss.get(k).copied().unwrap_or((0, 0));
        let (ss, sr) = self.smalls[k];
        crate::stats::normal_loss(ts + ss, ts.saturating_sub(tr) + ss.saturating_sub(sr))
    }

    /// The hop that answered from `a`, before hop `k`.
    fn place(&self, a: IpAddr, k: usize) -> Option<usize> {
        (0..k).find(|j| self.plan.addrs.get(*j).is_some_and(|x| x.contains(&a)))
    }

    /// The size a search starts from, as one that gets there: IPv4 the small probe's 84
    /// bytes (it was answered; every IPv4 link carries it), IPv6 1280 (every IPv6 link must).
    /// Never the trace's own probe size: sent without DF, routers may have split it.
    fn floor(&self) -> u32 {
        if self.plan.ipv6 { MIN_V6 } else { SMALL_PAYLOAD as u32 + header(false) }
    }

    /// Search hop `k` for the largest size up to `hi`. Its low end is a size seen to get there,
    /// or one under the floor (nothing seen yet: the floor itself gets tried too). Nothing below
    /// the floor can be told (IPv6 under 1280): the hop is not measured then.
    fn search_up_to(&mut self, k: usize, hi: u32) {
        let floor = self.floor();
        if hi < floor {
            self.not_measured(k);
            return;
        }
        let lo = self.search.map_or(floor - 1, |x| x.0).min(hi);
        self.search = Some((lo, hi));
    }

    /// Hop `k` cannot be measured: the scan goes on past it with the same size.
    fn not_measured(&mut self, k: usize) {
        self.hops[k].state = HopState::NotMeasured;
        if let Some(d) = self.drops.iter().position(|d| d.hop == Some(k) && d.size.is_none()) {
            self.drops.remove(d);
        }
        self.search = None;
        self.check = Check::default();
        self.k = k + 1;
    }

    /// What came back for `p`; `cached`: Windows' path MTU for the destination right after.
    pub fn answer(&mut self, p: &Probe, o: Outcome, cached: Option<u32>) {
        if self.done || p.hop != self.k {
            return;
        }
        // IPv6: a big probe that "got there" though Windows now knows a smaller path MTU was
        // split by this computer: it says nothing, but that the size does not fit unsplit.
        let o = match o {
            Outcome::Reply { kind: Kind::Echo | Kind::TtlExpired, .. } if self.plan.ipv6 && !p.small && cached.is_some_and(|c| c < p.size) => Outcome::Failed(IP_PACKET_TOO_BIG),
            o => o,
        };
        self.probes += 1;
        let k = p.hop;
        if p.small {
            self.smalls[k].0 += 1;
        }
        match o {
            // Got there.
            Outcome::Reply { kind: Kind::Echo | Kind::TtlExpired, .. } if p.small => {
                self.smalls[k].1 += 1;
                self.check.small_due = false;
                self.check.quiet = 0;
                let p = self.normal_loss(k);
                let need = strikes(p);
                if let Some((from, status)) = self.check.refused {
                    // Small ones get through where the size was refused: a filter on size at
                    // this hop (R-14). Not an error: the largest size it lets through is
                    // searched, and the scan goes on from there.
                    let s = self.trying();
                    self.check = Check::default();
                    self.add_drop(k, Why::Refused { from, status }, None);
                    match self.search {
                        Some((lo, _)) => self.search = Some((lo, s - 1)),
                        None => self.search_up_to(k, s - 1),
                    }
                // (Three or more lost bigs take two rounds at least: 1, then 2 back to back.)
                } else if self.check.lost >= need && p.powi(need as i32) > SIZE_CHANCE * 1.000001 {
                    // Even the most lost bigs in a row are this hop's usual: it cannot be told.
                    self.not_measured(k);
                    self.hops[k].state = HopState::Lossy;
                } else if self.check.lost >= need {
                    // The size does not get here (small ones do): a black hole.
                    let s = self.trying();
                    self.check = Check::default();
                    match self.search {
                        Some((lo, _)) => self.search = Some((lo, s - 1)),
                        None => {
                            self.add_drop(k, Why::Silent, None);
                            self.search_up_to(k, s - 1);
                        }
                    }
                } else {
                    // Another round, one big more back to back.
                    self.check.round += 1;
                    self.check.bigs_left = self.check.round;
                }
            }
            Outcome::Reply { kind: Kind::Echo | Kind::TtlExpired, .. } => {
                let s = p.size;
                self.check = Check::default();
                match self.search {
                    Some((_, hi)) => self.search = Some((s, hi)),
                    None => self.settle(k, s),
                }
            }
            // A router said it does not fit: the drop is on the link before hop k (after the
            // router that said so, when it sits on the path), and Windows learned its MTU.
            Outcome::Reply { kind: Kind::Other(IP_PACKET_TOO_BIG), from, .. } if !p.small => {
                let s = p.size;
                let m = cached.filter(|m| *m < s && *m >= self.min);
                let at = self.place(from, k).map_or(k, |j| (j + 1).min(k));
                self.add_drop(at, Why::FragNeeded { from, mtu: m }, if at < k { m } else { None });
                self.check = Check::default();
                match m {
                    Some(m) => {
                        // Try what the router reported (it may still not fit further on).
                        self.size = self.size.min(m);
                        if let Some((lo, _)) = self.search {
                            self.search = Some((lo.min(m), m));
                        }
                    }
                    // No MTU to go by: search for it.
                    None => self.search_up_to(k, s - 1),
                }
            }
            // This computer would not send it: Windows' path cache knows a smaller MTU.
            Outcome::Failed(IP_PACKET_TOO_BIG) if !p.small => {
                self.check = Check::default();
                match cached.filter(|c| *c < p.size && *c >= self.min) {
                    Some(c) => {
                        self.cache(Some(c), false);
                        if let Some((lo, _)) = self.search {
                            self.search = Some((lo.min(c), c));
                        }
                    }
                    None => {
                        // The cache cannot be read: search for the largest size Windows still
                        // sends (a refusal counts as "does not fit").
                        self.capped = true;
                        let s = p.size - 1;
                        self.size = self.size.min(s.max(self.min));
                        self.search_up_to(k, s);
                    }
                }
            }
            // A big probe refused ("prohibited", "host unreachable"): a small one tells whether
            // that is the size or the path (R-14).
            Outcome::Reply { kind: Kind::Unreachable(s), from, .. } if !p.small => {
                self.check = Check { refused: Some((from, s)), small_due: true, ..Check::default() };
            }
            // Small ones refused too: the path fails there, whatever the size.
            Outcome::Reply { kind: Kind::Unreachable(s), from, .. } => {
                self.error = Some(format!("{from}: {}", crate::icmp::words(s, self.plan.ipv6)));
                self.finish();
            }
            Outcome::Failed(s) => {
                self.error = Some(crate::icmp::words(s, self.plan.ipv6).to_string());
                self.finish();
            }
            // No answer (or an answer that says nothing about size).
            _ if p.small => {
                self.check.small_due = true;
                self.check.quiet += 1;
                if self.check.quiet >= QUIET {
                    // Not answering now, not even small.
                    self.not_measured(k);
                }
            }
            _ => {
                self.check.lost += 1;
                if self.check.round == 0 {
                    self.check.round = 1;
                    self.check.bigs_left = 1;
                }
                self.check.bigs_left = self.check.bigs_left.saturating_sub(1);
                if self.check.bigs_left == 0 {
                    self.check.small_due = true;
                }
            }
        }
    }

    // ---------- in words ----------

    /// Why packets over the drop's size do not get to its hop, in a sentence.
    pub fn drop_words(&self, d: &Drop) -> String {
        let size = d.size.map_or_else(|| "some sizes".to_string(), |s| format!("{s} bytes"));
        // The hops between were not measured: "do not answer" only when none of them answers
        // pings (NET2-4); a lossy or busy one does answer.
        let from = d.after.map_or(0, |a| a + 1);
        let quiet = d.hop.is_some_and(|h| (from..h).all(|j| self.hops[j].state == HopState::Silent));
        let why = if quiet { "do not answer pings" } else { "could not be measured" };
        let place = match (d.silent_between, d.after) {
            (true, Some(a)) => format!(" (the hops after hop {} {why}: it is somewhere among them)", a + 1),
            (true, None) => format!(" (the hops before it {why}: it is somewhere among them)"),
            _ => String::new(),
        };
        match &d.why {
            Why::FragNeeded { from, mtu } => {
                let who = match self.place(*from, self.hops.len()) {
                    Some(j) => format!("{from} (hop {})", j + 1),
                    None => from.to_string(),
                };
                let said = if self.plan.ipv6 { "packet too big" } else { "fragmentation needed" };
                let m = mtu.map(|m| format!(", next-hop MTU {m}")).unwrap_or_default();
                format!("Packets over {size} do not get here: {who} said \"{said}\"{m}.{place}")
            }
            Why::Silent => format!(
                "Packets over {size} get no answer from here on, and no \"fragmentation needed\" comes back: a PMTUD black hole (or a filter that drops big pings).{place}"
            ),
            Why::Refused { from, status } => {
                let who = match self.place(*from, self.hops.len()) {
                    Some(j) => format!("{from} (hop {})", j + 1),
                    None => from.to_string(),
                };
                format!("Packets over {size} are refused by {who}, which answers \"{}\"; smaller ones get through.{place}", crate::icmp::words(*status, self.plan.ipv6))
            }
            Why::Cache => format!(
                "Windows' path cache holds {size} for this destination (learned before or beside this scan): where it drops is not known."
            ),
        }
    }

    /// The table's MTU cell for hop `k`: text, kind (0 plain, 1 a drop a router said:
    /// "fragmentation needed", or refused over a size, 2 a black hole, 3 not measured, 4
    /// probing now) and tooltip.
    pub fn cell(&self, k: usize) -> (String, i32, String) {
        let Some(h) = self.hops.get(k) else { return (String::new(), 0, String::new()) };
        if self.probing() == Some(k) {
            return ("…".into(), 4, "Being measured now.".into());
        }
        if let Some(v) = h.value {
            if let Some(d) = self.drops.iter().find(|d| d.hop == Some(k)) {
                let kind = if d.why == Why::Silent { 2 } else { 1 };
                return (v.to_string(), kind, self.drop_words(d));
            }
            if h.at_least {
                return (
                    format!("≥{v}"),
                    0,
                    format!("At least {v} bytes get here; Windows would not send bigger ones to this destination any more (its path MTU cache), so more could not be tried."),
                );
            }
            if h.inferred {
                let why = if h.state == HopState::Lossy { "it loses too many of its pings to tell" } else { "no answer to pings" };
                return (v.to_string(), 0, format!("Not measured ({why}), but the hops on both sides carry {v} bytes, so this one does."));
            }
            return (v.to_string(), 0, format!("Packets of up to {v} bytes get here."));
        }
        match h.state {
            HopState::NotMeasured => ("?".into(), 3, "Not measured: no answer, even to small probes (rate limiting, a busy router, or the path down now).".into()),
            HopState::Lossy => (
                "?".into(),
                3,
                format!("Not measured: it loses about {:.0} % of its pings, so big probes going unanswered cannot be told from that.", self.normal_loss(k) * 100.0),
            ),
            HopState::Silent if self.done => ("?".into(), 3, "Not measured: this hop does not answer pings.".into()),
            _ if self.done => ("?".into(), 3, "Not measured.".into()),
            _ => (String::new(), 0, String::new()),
        }
    }

    /// The answer in a sentence (the toast, the report's header line).
    pub fn summary(&self, target: &str) -> String {
        if let Some(e) = &self.error {
            return format!("Path MTU to {target}: stopped ({e}).");
        }
        let Some(v) = self.path_mtu() else {
            return if let Some(k) = self.hops.len().checked_sub(1).filter(|k| self.hops[*k].state == HopState::Lossy) {
                format!("Path MTU to {target}: not measured (the last hop loses about {:.0} % of its pings: lost big probes cannot be told from that).", self.normal_loss(k) * 100.0)
            } else if self.hops.last().is_some_and(|h| h.state == HopState::NotMeasured) {
                format!("Path MTU to {target}: not measured (no answer, even to small probes).")
            } else {
                format!("Path MTU to {target}: not finished.")
            };
        };
        let real: Vec<&Drop> = self.drops.iter().filter(|d| d.why != Why::Cache).collect();
        let said = if self.plan.ipv6 { "packet too big" } else { "fragmentation needed" };
        let cache = self.drops.iter().any(|d| d.why == Why::Cache);
        let more = if real.len() > 1 { format!(" ({} drops in all)", real.len()) } else { String::new() };
        let first = real.first().map(|d| {
            let at = d.hop.map_or("somewhere".to_string(), |h| format!("hop {}", h + 1));
            match &d.why {
                Why::FragNeeded { from, mtu } => format!("it drops at {at} ({from} said \"{said}\"{})", mtu.map(|m| format!(", MTU {m}")).unwrap_or_default()),
                Why::Refused { from, status } => format!(
                    "it drops at {at}: packets over {} are refused by {from} (\"{}\")",
                    d.size.map_or_else(|| "some sizes".to_string(), |s| format!("{s} bytes")),
                    crate::icmp::words(*status, self.plan.ipv6)
                ),
                _ => format!("it drops at {at}, where bigger packets get no answer and no \"fragmentation needed\" comes back: a PMTUD black hole"),
            }
        });
        let at_least = if self.hops.last().is_some_and(|h| h.at_least) { "at least " } else { "" };
        match (first, cache) {
            (None, false) => format!("Path MTU to {target}: {v} bytes, the whole way."),
            (None, true) => format!("Path MTU to {target}: {at_least}{v} bytes; Windows already knew it, where it drops is not known."),
            (Some(f), _) => format!("Path MTU to {target}: {at_least}{v} bytes; {f}.{more}"),
        }
    }
}

/// One probe of the machine on `prober`, no pacing (tests, and the runner below). False when
/// the run is over.
pub fn step(net: &dyn Network, prober: &mut dyn Prober, dest: IpAddr, mtu: &Mutex<Mtu>) -> bool {
    let cached = net.cached_mtu(dest);
    let Some(p) = mtu.lock().unwrap().next(cached) else { return false };
    let o = prober.probe_size(p.ttl, p.payload, p.df);
    let after = net.cached_mtu(dest);
    mtu.lock().unwrap().answer(&p, o, after);
    true
}

/// A manual run's prober and network (tests).
type Manual = Mutex<(Box<dyn Prober>, Arc<dyn Network>)>;

/// A run in the background. Dropping it (or `stop`) ends it after the probe in flight.
pub struct MtuRun {
    pub state: Arc<Mutex<Mtu>>,
    stop: Arc<AtomicBool>,
    /// Tests: no thread; `steps` sends probes when told.
    manual: Option<Manual>,
    pub dest: IpAddr,
}

impl MtuRun {
    /// A handle of its own, big enough for the largest probe.
    fn prober(net: &dyn Network, dest: IpAddr) -> Result<Box<dyn Prober>, String> {
        let opts = Opts { interval_ms: 1000, timeout_ms: TIMEOUT_MS, size: (MAX_MTU - header(dest.is_ipv6())) as u16, max_hops: 1 };
        net.open(dest, &opts)
    }

    /// Start probing `plan`'s path on a thread of its own. This computer's link MTU and Windows'
    /// path cache are read there (IP helper calls: never on the window's thread).
    pub fn spawn(net: Arc<dyn Network>, dest: IpAddr, plan: Plan) -> Result<MtuRun, String> {
        let mut prober = Self::prober(&*net, dest)?;
        let state = Arc::new(Mutex::new(Mtu::new(Plan { link: Some(DEFAULT_LINK), ..plan.clone() })));
        let stop = Arc::new(AtomicBool::new(false));
        let (s, halt) = (state.clone(), stop.clone());
        std::thread::Builder::new()
            .name("mtu".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                let mut plan = plan;
                plan.link = net.link_mtu(dest);
                plan.cached = net.cached_mtu(dest);
                *s.lock().unwrap() = Mtu::new(plan);
                let mut last_any: Option<Instant> = None;
                let mut last_hop: std::collections::HashMap<u8, Instant> = std::collections::HashMap::new();
                loop {
                    if halt.load(Ordering::Relaxed) {
                        return;
                    }
                    let cached = net.cached_mtu(dest);
                    let Some(p) = s.lock().unwrap().next(cached) else { return };
                    // The pace: 1 s to the same hop, 250 ms between any two.
                    let due = [last_any.map(|t| t + Duration::from_millis(ANY_MS)), last_hop.get(&p.ttl).map(|t| *t + Duration::from_millis(SAME_HOP_MS))]
                        .into_iter()
                        .flatten()
                        .max();
                    if let Some(due) = due {
                        while Instant::now() < due {
                            if halt.load(Ordering::Relaxed) {
                                return;
                            }
                            std::thread::sleep((due - Instant::now()).min(Duration::from_millis(50)));
                        }
                    }
                    let o = prober.probe_size(p.ttl, p.payload, p.df);
                    let now = Instant::now();
                    last_any = Some(now);
                    last_hop.insert(p.ttl, now);
                    if halt.load(Ordering::Relaxed) {
                        return;
                    }
                    let after = net.cached_mtu(dest);
                    s.lock().unwrap().answer(&p, o, after);
                }
            })
            .map_err(|e| format!("Could not start the path MTU probe: {e}"))?;
        Ok(MtuRun { state, stop, manual: None, dest })
    }

    /// Tests: the same run with no thread; `steps` sends the probes.
    pub fn manual(net: Arc<dyn Network>, dest: IpAddr, mut plan: Plan) -> Result<MtuRun, String> {
        let prober = Self::prober(&*net, dest)?;
        plan.link = net.link_mtu(dest);
        plan.cached = net.cached_mtu(dest);
        Ok(MtuRun { state: Arc::new(Mutex::new(Mtu::new(plan))), stop: Arc::new(AtomicBool::new(false)), manual: Some(Mutex::new((prober, net))), dest })
    }

    /// Manual runs: send up to `n` probes now.
    pub fn steps(&self, n: u32) {
        let Some(m) = &self.manual else { return };
        let mut g = m.lock().unwrap();
        let (prober, net) = &mut *g;
        for _ in 0..n {
            if self.stop.load(Ordering::Relaxed) || !step(&**net, &mut **prober, self.dest, &self.state) {
                return;
            }
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.state.lock().unwrap().done = true;
    }

    pub fn running(&self) -> bool {
        !self.stop.load(Ordering::Relaxed) && !self.state.lock().unwrap().done
    }
}

impl std::ops::Drop for MtuRun {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
