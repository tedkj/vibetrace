//! The trace: one prober thread per TTL, all writing into one shared `Trace`; the window reads
//! a snapshot of it on a timer (results are shared state, not messages: no event per probe).
//!
//! The probing itself is behind `Network` / `Prober`, so the engine and the window run the same
//! code against Windows' ICMP API (`icmp`) and against a scripted fake network (`fake`).

use crate::dnscheck::{Check, Which};
use crate::isplog::{self, LogState, MinRec, Outage};
use crate::stats::{History, HopFacts, Responders, Sample, Stats, ROUTE_WINDOW};
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How a trace probes. Changing any of these starts the statistics over (mixing packet sizes or
/// intervals in one average would be dishonest).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opts {
    pub interval_ms: u32,
    pub timeout_ms: u32,
    /// ICMP payload in bytes (56: a 64-byte ICMP packet, as ping on Unix).
    pub size: u16,
    pub max_hops: u8,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { interval_ms: 1000, timeout_ms: 2000, size: 56, max_hops: 30 }
    }
}

/// What answered a probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An echo reply: the destination itself.
    Echo,
    /// Time exceeded in transit: a router on the way.
    TtlExpired,
    /// Destination unreachable (the ICMP API's status code), from a router or the target.
    Unreachable(u32),
    /// Any other ICMP error that names a sender (packet too big, parameter problem...).
    Other(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Reply { from: IpAddr, kind: Kind, rtt_us: u32 },
    /// No answer within the timeout.
    Lost,
    /// The probe could not be sent from this computer (the ICMP API's status code): no route,
    /// no IPv6, a bad address. Not a network loss: the trace stops and says why.
    Failed(u32),
}

/// One open ICMP handle: sends one probe and waits for its answer (up to the timeout).
pub trait Prober: Send {
    /// A probe of the trace's own size.
    fn probe(&mut self, ttl: u8) -> Outcome;
    /// A probe of `payload` bytes (at most the size the handle was opened for), with the
    /// don't-fragment flag when `df` (IPv4; IPv6 routers never fragment). The path MTU probe.
    fn probe_size(&mut self, ttl: u8, payload: u16, df: bool) -> Outcome;
}

pub trait Network: Send + Sync {
    fn open(&self, dest: IpAddr, opts: &Opts) -> Result<Box<dyn Prober>, String>;
    /// The MTU of the link this computer reaches `dest` through (None: it could not be read).
    fn link_mtu(&self, _dest: IpAddr) -> Option<u32> {
        None
    }
    /// The path MTU Windows has learned for `dest` (its path cache), if any.
    fn cached_mtu(&self, _dest: IpAddr) -> Option<u32> {
        None
    }
    /// The interface this computer reaches `dest` through, if Windows says (R-4).
    fn via(&self, _dest: IpAddr) -> Option<crate::isplog::Via> {
        None
    }
}

/// The local wall-clock time a trace began (for the report and the events' times).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WallClock {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl WallClock {
    pub fn now() -> WallClock {
        use windows_sys::Win32::System::SystemInformation::GetLocalTime;
        let mut t = unsafe { std::mem::zeroed() };
        unsafe { GetLocalTime(&mut t) };
        WallClock { year: t.wYear, month: t.wMonth as u8, day: t.wDay as u8, hour: t.wHour as u8, minute: t.wMinute as u8, second: t.wSecond as u8 }
    }

    /// "14:03:11", `ms` after this moment (the day wraps; events show the time of day only).
    pub fn time_after(&self, ms: u64) -> String {
        let s = (self.hour as u64 * 3600 + self.minute as u64 * 60 + self.second as u64 + ms / 1000) % 86_400;
        format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
    }

    /// "2026-10-19 14:03:11".
    pub fn stamp(&self) -> String {
        format!("{:04}-{:02}-{:02} {}", self.year, self.month, self.day, self.time_after(0))
    }

    /// The wall clock `offset_min` minutes from UTC at UTC millisecond `unix_ms` (a fixed
    /// offset: the tests' local time; the app asks Windows, `host::local_time`).
    pub fn at(unix_ms: u64, offset_min: i64) -> WallClock {
        let s = (unix_ms / 1000) as i64 + offset_min * 60;
        let (days, secs) = (s.div_euclid(86_400), s.rem_euclid(86_400));
        // Civil from days (Howard Hinnant's algorithm).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
        WallClock { year: y as u16, month: m as u8, day: d as u8, hour: (secs / 3600) as u8, minute: (secs / 60 % 60) as u8, second: (secs % 60) as u8 }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// The hop's address changed for good (the new one answered the last ten replies).
    RouteChange { from: IpAddr, to: IpAddr },
    /// Three or more probes lost in a row (`count` grows while it lasts; `ended` once a reply came).
    LossBurst { count: u32, ended: bool },
    /// The hop says the destination cannot be reached (the ICMP API's status code).
    Unreachable { from: IpAddr, status: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// Index of the hop (TTL - 1).
    pub hop: usize,
    /// Milliseconds since the trace (or its last reset) began.
    pub at_ms: u64,
    pub kind: EventKind,
}

/// Addresses one hop hands to the name and AS lookups at most: its listed responders and as many
/// route changes again (RIN4-5). A forger rotating sources gets a new address listed every
/// ROUTE_WINDOW replies; past this, no new lookup is queued for that hop.
pub const LOOKUPS_PER_HOP: usize = 2 * crate::stats::MAX_RESPONDERS;
/// Addresses one trace hands to the lookups at most, all hops together (RIN4-5). A real path is
/// well under 100.
pub const MAX_LOOKED_UP: usize = 512;

/// A loss burst becomes an event at this many losses in a row.
pub const BURST: u32 = 3;
/// Events kept: past this many the oldest `EVENTS_MAX / 2` go (a lossy destination makes a
/// burst every few seconds, for as long as it runs).
pub const EVENTS_MAX: usize = 2000;

#[derive(Clone, Debug, Default)]
pub struct Hop {
    pub stats: Stats,
    pub history: History,
    pub responders: Responders,
    /// The kinds of the newest replies (losses not counted): whether this hop is where the path
    /// ends (an echo or an unreachable among them).
    kinds: VecDeque<Kind>,
    /// The loss burst running now (its index in `Trace::events`).
    burst: Option<usize>,
    /// Probes lost in a row at the newest end (not bounded by the history ring).
    run: u32,
    /// The unreachable status this hop reported last (one event per change, not per probe).
    unreachable: Option<u32>,
}

impl Hop {
    pub fn answers(&self) -> bool {
        self.stats.received > 0
    }
    fn says(&self, f: impl Fn(&Kind) -> bool) -> bool {
        self.kinds.iter().any(f)
    }
    /// The unreachable status among its newest replies, if it ends the path that way.
    pub fn unreachable_status(&self) -> Option<u32> {
        self.kinds.iter().rev().find_map(|k| if let Kind::Unreachable(s) = k { Some(*s) } else { None })
    }
    pub fn facts(&self) -> HopFacts {
        HopFacts { sent: self.stats.sent, received: self.stats.received, avg_ms: self.stats.avg_ms() }
    }
}

/// Everything measured so far, shared by the prober threads and the window.
#[derive(Debug)]
pub struct Trace {
    pub target: IpAddr,
    /// What the user typed (a name, or the address again).
    pub name: String,
    pub opts: Opts,
    pub started: WallClock,
    /// `at_ms` of the last reset: elapsed time and the events count from here.
    pub origin_ms: u64,
    pub hops: Vec<Hop>,
    pub events: Vec<Event>,
    /// Why probing stopped, in plain words (nothing can be sent from this computer).
    pub fatal: Option<String>,
    /// The oldest events were dropped (`EVENTS_MAX`).
    pub events_dropped: bool,
    /// Responders never seen before, for the name and AS lookups (taken by the window).
    pub new_addrs: Vec<IpAddr>,
    /// Every address handed to the lookups this trace (at most MAX_LOOKED_UP).
    seen: HashSet<IpAddr>,
    /// Per hop index, how many of `seen` it handed in (at most LOOKUPS_PER_HOP; a reset keeps it).
    looked_up: Vec<u32>,
    /// UTC milliseconds at session time 0 (the ISP log's clock; 0 when not known), as it stands
    /// since the last time the wall clock was followed (`reanchor`).
    pub started_unix: u64,
    /// The anchors before that: (until session ms, UTC ms at session time 0), oldest first.
    /// Every session time is dated by the anchor in force when it was: a loss sent before a
    /// sleep stays before it, whenever the rule or the window gets to it (NET2-3).
    pub earlier: Vec<(u64, u64)>,
    /// Some hop has answered (since the start, resets aside).
    pub answered: bool,
    /// The ISP log, while it runs (SPEC §9).
    pub log: Option<LogState>,
    /// Per hop index, its newest outcomes as the log counts them: (session ms, answered; an
    /// "unreachable" is no answer), at most `isplog::SEEN`. Kept logging or not, so a log
    /// switched on mid-trace knows the line's normal loss at once; a reset leaves it.
    pub recent: Vec<VecDeque<(u64, bool)>>,
}

impl Trace {
    pub fn new(target: IpAddr, name: &str, opts: Opts, started: WallClock) -> Trace {
        Trace {
            target,
            name: name.to_string(),
            opts,
            started,
            origin_ms: 0,
            hops: vec![Hop::default(); opts.max_hops as usize],
            events: Vec::new(),
            fatal: None,
            events_dropped: false,
            new_addrs: Vec::new(),
            seen: HashSet::new(),
            looked_up: vec![0; opts.max_hops as usize],
            started_unix: 0,
            earlier: Vec::new(),
            answered: false,
            log: None,
            recent: Vec::new(),
        }
    }

    /// One probe's outcome for `ttl` (1-based), sent on `tick` at `at_ms` since the start.
    pub fn record(&mut self, ttl: u8, tick: u32, at_ms: u64, outcome: Outcome) {
        if self.fatal.is_some() || ttl == 0 || ttl as usize > self.hops.len() {
            return;
        }
        let i = ttl as usize - 1;
        let at = at_ms.saturating_sub(self.origin_ms);
        // While logging, a probe that cannot leave this computer after the path has answered
        // is the network gone (the adapter down, no route): a loss at every hop, and an outage
        // of "this computer", never a stop (SPEC §9.3).
        let (outcome, local) = match outcome {
            Outcome::Failed(s) if self.log.is_some() && self.answered => (Outcome::Lost, Some(s)),
            o => (o, None),
        };
        let reply = match outcome {
            Outcome::Reply { from, rtt_us, kind } => Some((from, rtt_us, kind)),
            _ => None,
        };
        match outcome {
            Outcome::Failed(status) => {
                self.fatal = Some(crate::icmp::words(status, self.target.is_ipv6()).to_string());
            }
            Outcome::Lost => {
                let hop = &mut self.hops[i];
                hop.stats.lost();
                hop.history.push(Sample { tick, at_ms: at, rtt_us: None });
                hop.run = hop.run.saturating_add(1);
                let run = hop.run;
                // A hop that has never answered loses everything: that is not a burst.
                if hop.answers() && run >= BURST {
                    match hop.burst {
                        Some(e) => {
                            if let EventKind::LossBurst { count, .. } = &mut self.events[e].kind {
                                *count = run;
                            }
                        }
                        None => {
                            // Created at the third loss: its first loss is still in the ring.
                            let first = hop.history.iter().rev().nth(run as usize - 1).map_or(at, |s| s.at_ms);
                            hop.burst = Some(self.events.len());
                            self.push_event(Event { hop: i, at_ms: first, kind: EventKind::LossBurst { count: run, ended: false } });
                        }
                    }
                }
            }
            Outcome::Reply { from, kind, rtt_us } => {
                let hop = &mut self.hops[i];
                hop.stats.reply(rtt_us);
                hop.run = 0;
                hop.history.push(Sample { tick, at_ms: at, rtt_us: Some(rtt_us) });
                if let Some(e) = hop.burst.take()
                    && let EventKind::LossBurst { ended, .. } = &mut self.events[e].kind
                {
                    *ended = true;
                }
                if hop.kinds.len() == ROUTE_WINDOW {
                    hop.kinds.pop_front();
                }
                hop.kinds.push_back(kind);
                let change = hop.responders.reply(from);
                let unreachable = if let Kind::Unreachable(s) = kind { Some(s) } else { None };
                let new_unreachable = unreachable.is_some() && unreachable != hop.unreachable;
                if unreachable.is_some() {
                    hop.unreachable = unreachable;
                }
                if let Some((from, to)) = change {
                    self.push_event(Event { hop: i, at_ms: at, kind: EventKind::RouteChange { from, to } });
                }
                if let (true, Some(status)) = (new_unreachable, unreachable) {
                    self.push_event(Event { hop: i, at_ms: at, kind: EventKind::Unreachable { from, status } });
                }
                // Only a listed responder is looked up (IN-VibeTrace-1: the rest are "other"),
                // and at most LOOKUPS_PER_HOP per hop and MAX_LOOKED_UP in all (RIN4-5): an
                // address that rotates in by holding the hop for a window is still listed and
                // its route change shown, but past either cap it is not looked up.
                if self.hops[i].responders.has(from)
                    && self.looked_up.get(i).is_some_and(|&n| (n as usize) < LOOKUPS_PER_HOP)
                    && self.seen.len() < MAX_LOOKED_UP
                    && self.seen.insert(from)
                {
                    self.looked_up[i] += 1;
                    self.new_addrs.push(from);
                }
                self.answered = true;
            }
        }
        if self.fatal.is_some() {
            return;
        }
        let answered = matches!(reply, Some((_, _, k)) if !matches!(k, Kind::Unreachable(_)));
        if self.recent.len() <= i {
            self.recent.resize_with(i + 1, VecDeque::new);
        }
        if self.recent[i].len() == isplog::SEEN {
            self.recent[i].pop_front();
        }
        self.recent[i].push_back((at_ms, answered));
        if self.log.is_some() {
            self.log_probe(i, at_ms, reply, local);
        }
    }

    // ---------- the ISP log ----------

    /// UTC ms of session time `at_ms`, by the anchor in force then.
    pub fn unix(&self, at_ms: u64) -> u64 {
        unix_at(&self.earlier, self.started_unix, at_ms)
    }

    /// The wall clock says it is `wall` at session time `now_ms` (a sleep the monotonic clock did
    /// not count, a clock set forward): from `now_ms` on, times are dated by it; what came
    /// before keeps its anchor.
    pub fn reanchor(&mut self, now_ms: u64, wall: u64) {
        self.earlier.push((now_ms, self.started_unix));
        self.started_unix = wall.saturating_sub(now_ms);
        // While logging, the minute after the jump says so: the gap before it is the PC asleep
        // or the clock changed, not the log stopped (R-6).
        if let Some(log) = &mut self.log {
            log.steps.push(wall);
        }
    }

    /// Start logging (a new run, `run` the controller's number for it) at session time `now_ms`.
    pub fn start_log(&mut self, run: u64, now_ms: u64) {
        self.log = Some(LogState::new(run, now_ms));
    }

    /// One probe into the log: its minute, its hop's recent outcomes, the open outage, or the
    /// outage rule. An "unreachable" is the path failing, not the hop answering: for the log it
    /// is a loss (a router saying "network unreachable" for every probe past it during an
    /// outage must not make it look answered).
    fn log_probe(&mut self, i: usize, at_ms: u64, reply: Option<(IpAddr, u32, Kind)>, local: Option<u32>) {
        let unix = self.unix(at_ms);
        let reference = self.reference();
        let dest_hop = self.dest_hop();
        let interval = self.opts.interval_ms as u64;
        let answered = matches!(reply, Some((_, _, k)) if !matches!(k, Kind::Unreachable(_)));
        let recent = &self.recent;
        let log = self.log.as_mut().expect("logging");
        let m = log.minute(unix);
        let acc = m.hops.entry(i as u8 + 1).or_default();
        match reply {
            Some((from, us, kind)) if answered => {
                acc.reply(from, us);
                if kind == Kind::Echo {
                    m.dest = Some(m.dest.map_or(i as u8 + 1, |d| d.min(i as u8 + 1)));
                }
            }
            _ => acc.lost(local.is_some()),
        }
        // An outage under way: count what every hop gets; it ends when the destination echoes
        // (at any TTL: the path may have changed length), or a router reference answers again.
        if let Some(id) = log.open {
            if let Some(x) = log.outages.iter().position(|o| o.id == id) {
                let o = &mut log.outages[x];
                let ends = match reply {
                    Some((_, _, Kind::Echo)) => o.dest || i + 1 == o.ttl as usize,
                    Some((_, _, Kind::TtlExpired)) => !o.dest && i + 1 == o.ttl as usize,
                    _ => false,
                };
                // (The answer that ends it is not part of it.)
                if at_ms >= o.start_ms && i < o.probes.len() && !ends {
                    o.probes[i] += 1;
                    o.replies[i] += answered as u32;
                }
                if local.is_some() {
                    o.local = local;
                }
                if ends {
                    o.end_ms = Some(at_ms);
                    // The hops' probes of the last interval went out as the path came back:
                    // they do not say where it broke (each hop's newest, when it answered).
                    let from = at_ms.saturating_sub(interval);
                    for j in (0..o.probes.len()).filter(|j| *j != i) {
                        if recent.get(j).and_then(|s| s.back()).is_some_and(|&(t, a)| a && t > from && t >= o.start_ms) {
                            o.probes[j] = o.probes[j].saturating_sub(1);
                            o.replies[j] = o.replies[j].saturating_sub(1);
                        }
                    }
                    log.open = None;
                    log.changed.push(id);
                }
            }
            return;
        }
        // The rule: the reference went unanswered `needed(p)` times in a row, `p` its normal
        // loss before the run (the trace's, from before the log too; earlier outages left out;
        // a prior while there is little: `isplog::rule_loss`). A router as the reference
        // answers in bursts: 5 at least.
        let Some(r) = reference else { return };
        if i != r || answered {
            return;
        }
        let Some(seen) = recent.get(r) else { return };
        let run = seen.iter().rev().take_while(|x| !x.1).count();
        if run < isplog::OUTAGE_MIN as usize {
            return;
        }
        let before = seen.len() - run;
        let p = isplog::rule_loss(seen, before, &log.outages);
        let mut need = isplog::needed(p);
        if dest_hop != Some(r) {
            need = need.max(isplog::ROUTER_OUTAGE_MIN);
        }
        if (run as u32) < need {
            return;
        }
        // It began at the run's first loss, never before the log: one that began before it
        // starts with the log and says so.
        let since = log.since_ms;
        let before_log = seen[before].0 < since;
        let start = seen[before].0.max(since);
        let n = r + 1;
        let (mut probes, mut replies) = (vec![0u32; n], vec![0u32; n]);
        for (j, s) in recent.iter().enumerate().take(n) {
            for &(_, a) in s.iter().filter(|x| x.0 >= start) {
                probes[j] += 1;
                replies[j] += a as u32;
            }
        }
        let id = unix_at(&self.earlier, self.started_unix, start);
        let o = Outage { id, start_ms: start, end_ms: None, ttl: n as u8, dest: dest_hop == Some(r), probes, replies, local, stopped: false, before_log, from_ms: seen[before].0 };
        log.push_outage(o);
    }

    /// A DNS check's result, `at_ms` when it started (session time).
    pub fn record_dns(&mut self, which: Which, at_ms: u64, c: &Check) {
        let unix = self.unix(at_ms);
        if let Some(log) = &mut self.log {
            log.dns_check(which, at_ms, unix, c);
        }
    }

    /// The minutes that are complete at `now_ms` (all of them with `all`: the log ends, or a
    /// report wants everything so far), oldest first. A minute is complete once no probe sent
    /// in it can still come back.
    pub fn take_minutes(&mut self, now_ms: u64, all: bool) -> Vec<MinRec> {
        let unix_now = self.unix(now_ms);
        let dest_now = self.dest_hop().map(|d| d as u8 + 1);
        let grace = self.opts.timeout_ms as u64 + 1000;
        let Some(log) = &mut self.log else { return Vec::new() };
        let mut out = Vec::new();
        while let Some((&m, _)) = log.minutes.first_key_value() {
            if !all && (m + 1) * 60_000 + grace > unix_now {
                break;
            }
            let acc = log.minutes.remove(&m).expect("first key");
            let mut rec = acc.rec(m, dest_now);
            // The first minute that ends after a jump of the clock carries it (R-6).
            let end = (m + 1) * 60_000;
            if log.steps.iter().any(|w| *w < end) {
                rec.stepped = true;
                log.steps.retain(|w| *w >= end);
            }
            out.push(rec);
        }
        out
    }

    /// The log ends (stop, a new target, switched off): an open outage is recorded as still out.
    pub fn end_log(&mut self) {
        if let Some(log) = &mut self.log {
            log.end();
        }
    }

    /// One more event; past `EVENTS_MAX` the oldest half goes, except open bursts' events (a
    /// hop dark for hours keeps its one event, with its start). The hops' open bursts point
    /// into the list, so their indexes move by the events dropped before them.
    fn push_event(&mut self, e: Event) {
        self.events.push(e);
        if self.events.len() > EVENTS_MAX {
            let open: HashSet<usize> = self.hops.iter().filter_map(|h| h.burst).collect();
            let gone = EVENTS_MAX / 2;
            let mut i = 0;
            self.events.retain(|_| {
                i += 1;
                i > gone || open.contains(&(i - 1))
            });
            self.events_dropped = true;
            for h in &mut self.hops {
                if let Some(b) = &mut h.burst {
                    *b -= (0..*b).filter(|j| *j < gone && !open.contains(j)).count();
                }
            }
        }
    }

    /// The destination's hop: the lowest TTL at which the target itself answers (an echo among
    /// its newest replies, so one flap of a load-balanced path does not move it).
    pub fn dest_hop(&self) -> Option<usize> {
        self.hops.iter().position(|h| h.says(|k| *k == Kind::Echo))
    }

    /// Where the path ends: the destination's hop, or else the lowest hop that says the
    /// destination is unreachable. Threads above it rest.
    pub fn end_hop(&self) -> Option<usize> {
        self.dest_hop().or_else(|| self.hops.iter().position(|h| h.says(|k| matches!(k, Kind::Unreachable(_)))))
    }

    pub fn should_probe(&self, ttl: u8) -> bool {
        // An outage under way keeps its reference probed (an unreachable from a router before
        // it would otherwise make the TTLs past that router rest, and the end go unseen).
        let outage_ttl = self.log.as_ref().and_then(|l| l.open.and_then(|id| l.outage(id))).map(|o| o.ttl);
        self.fatal.is_none() && (self.end_hop().is_none_or(|e| (ttl as usize) <= e + 1) || outage_ttl.is_some_and(|t| ttl <= t))
    }

    /// The last hop that answers at all (when the path has no end yet).
    pub fn last_answering(&self) -> Option<usize> {
        self.hops.iter().rposition(|h| h.answers())
    }

    /// The hop the others are judged against: the destination, the unreachable end, or the
    /// last hop that answers.
    pub fn reference(&self) -> Option<usize> {
        self.end_hop().or_else(|| self.last_answering())
    }

    /// How many hop rows the window shows: up to the end, or up to the last hop that answers
    /// (silent hops after it are summed up in one quiet row instead).
    pub fn shown(&self) -> usize {
        self.end_hop().or_else(|| self.last_answering()).map_or(0, |e| e + 1)
    }

    /// No end found and hops after the last answering one were probed without an answer.
    pub fn silent_tail(&self) -> bool {
        self.end_hop().is_none() && self.hops.iter().skip(self.shown()).any(|h| h.stats.sent > 0)
    }

    pub fn facts(&self) -> Vec<HopFacts> {
        self.hops.iter().map(Hop::facts).collect()
    }

    /// The most probes any hop has had: the trace's round.
    pub fn round(&self) -> u32 {
        self.hops.iter().map(|h| h.stats.sent).max().unwrap_or(0)
    }

    /// Statistics, history, responders and events start over; probing goes on.
    pub fn reset(&mut self, now_ms: u64) {
        self.origin_ms = now_ms;
        for h in &mut self.hops {
            *h = Hop::default();
        }
        self.events.clear();
        self.events_dropped = false;
    }
}

/// UTC ms of session time `at_ms`: the anchor in force then (`Trace::earlier`), else `now`.
fn unix_at(earlier: &[(u64, u64)], now: u64, at_ms: u64) -> u64 {
    earlier.iter().find(|e| at_ms < e.0).map_or(now, |e| e.1) + at_ms
}

// ---------- running it ----------

/// A running trace. Dropping it (or `stop`) ends the probing: each thread finishes the probe it
/// is waiting on (up to the timeout) and exits without recording it. The window never waits.
pub struct Session {
    pub trace: Arc<Mutex<Trace>>,
    stop: Arc<AtomicBool>,
    clock: Clock,
    /// The probing interval (kept here so reading the clock never takes the trace's lock).
    interval_ms: u32,
}

enum Clock {
    Real(Instant),
    /// Tests: probes run only when `step` says, in TTL order, on a clock of whole ticks.
    Manual { probers: Mutex<Vec<Box<dyn Prober>>>, tick: Mutex<u32> },
}

impl Session {
    /// One thread per TTL, each with its own ICMP handle, staggered across the interval.
    pub fn start(net: &dyn Network, trace: Trace) -> Result<Session, String> {
        let opts = trace.opts;
        let target = trace.target;
        // Open them all first: a failure is reported, not left to the threads.
        let probers = (0..opts.max_hops).map(|_| net.open(target, &opts)).collect::<Result<Vec<_>, _>>()?;
        let trace = Arc::new(Mutex::new(trace));
        let stop = Arc::new(AtomicBool::new(false));
        let start = Instant::now();
        for (i, prober) in probers.into_iter().enumerate() {
            let (shared, halt) = (trace.clone(), stop.clone());
            let ttl = i as u8 + 1;
            let spawned = std::thread::Builder::new()
                .name(format!("probe-{ttl}"))
                .stack_size(64 * 1024)
                .spawn(move || run_hop(prober, ttl, opts, start, &shared, &halt));
            if let Err(e) = spawned {
                stop.store(true, Ordering::Relaxed);
                return Err(format!("Could not start probing: {e}"));
            }
        }
        Ok(Session { trace, stop, clock: Clock::Real(start), interval_ms: opts.interval_ms })
    }

    /// For tests: the same engine with no threads; `step` runs whole rounds.
    pub fn manual(net: &dyn Network, trace: Trace) -> Result<Session, String> {
        let opts = trace.opts;
        let probers = (0..opts.max_hops).map(|_| net.open(trace.target, &opts)).collect::<Result<Vec<_>, _>>()?;
        Ok(Session {
            trace: Arc::new(Mutex::new(trace)),
            stop: Arc::new(AtomicBool::new(false)),
            clock: Clock::Manual { probers: Mutex::new(probers), tick: Mutex::new(0) },
            interval_ms: opts.interval_ms,
        })
    }

    /// Manual sessions: run `rounds` rounds (every TTL that should be probed, in order).
    pub fn step(&self, rounds: u32) {
        let Clock::Manual { probers, tick } = &self.clock else { return };
        let mut probers = probers.lock().unwrap();
        for _ in 0..rounds {
            if self.stop.load(Ordering::Relaxed) {
                return;
            }
            let t = {
                let mut t = tick.lock().unwrap();
                *t += 1;
                *t - 1
            };
            let opts = self.trace.lock().unwrap().opts;
            for (i, p) in probers.iter_mut().enumerate() {
                let ttl = i as u8 + 1;
                if !self.trace.lock().unwrap().should_probe(ttl) {
                    continue;
                }
                let outcome = p.probe(ttl);
                let at = t as u64 * opts.interval_ms as u64 + offset_ms(ttl, &opts);
                self.trace.lock().unwrap().record(ttl, t, at, outcome);
            }
        }
    }

    /// Tests: let `ticks` pass on a manual session's clock without probing (a long trace, fast).
    pub fn skip(&self, ticks: u32) {
        if let Clock::Manual { tick, .. } = &self.clock {
            *tick.lock().unwrap() += ticks;
        }
    }

    /// Milliseconds since the session began (manual: the ticks run so far). 64 bits: 32 would
    /// stop the clock after 49.7 days of one trace.
    pub fn now_ms(&self) -> u64 {
        match &self.clock {
            Clock::Real(start) => start.elapsed().as_millis() as u64,
            Clock::Manual { tick, .. } => *tick.lock().unwrap() as u64 * self.interval_ms as u64,
        }
    }

    /// The tick the newest probes belong to (the sparklines' right edge).
    pub fn tick(&self) -> u32 {
        match &self.clock {
            Clock::Real(_) => (self.now_ms() / self.interval_ms.max(1) as u64).min(u32::MAX as u64) as u32,
            Clock::Manual { tick, .. } => tick.lock().unwrap().saturating_sub(1),
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Where in the interval a TTL's probes leave: spread evenly, so they never all go at once.
fn offset_ms(ttl: u8, opts: &Opts) -> u64 {
    ((ttl as u32 - 1) * opts.interval_ms / opts.max_hops.max(1) as u32) as u64
}

/// One TTL's loop: wait for the tick, probe (blocking up to the timeout), record, and on to the
/// next tick (`next_tick`). A probe that waits out a 2 s timeout at a 1 s interval takes every
/// other tick: such a hop is probed less often, and its Sent column says so.
fn run_hop(mut prober: Box<dyn Prober>, ttl: u8, opts: Opts, start: Instant, trace: &Mutex<Trace>, stop: &AtomicBool) {
    let interval = Duration::from_millis(opts.interval_ms.max(1) as u64);
    let offset = Duration::from_millis(offset_ms(ttl, &opts));
    let mut tick: u32 = 0;
    loop {
        let due = start + offset + interval * tick;
        // Sleep in short steps so a stopped session's threads go quickly.
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let now = Instant::now();
            if now >= due {
                break;
            }
            std::thread::sleep((due - now).min(Duration::from_millis(100)));
        }
        if trace.lock().unwrap().should_probe(ttl) {
            let sent = Instant::now();
            let outcome = prober.probe(ttl);
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let at_ms = (sent - start).as_millis() as u64;
            let mut t = trace.lock().unwrap();
            t.record(ttl, tick, at_ms, outcome);
            if t.fatal.is_some() {
                return;
            }
        }
        let since = Instant::now().saturating_duration_since(start + offset);
        tick = next_tick(since.as_millis(), interval.as_millis(), tick);
    }
}

/// The tick to probe next, `since_ms` after this TTL's first due time: the first one not yet
/// due, or one that came due at most a quarter interval ago. A timeout of whole intervals ends
/// just after a tick came due; taking the first tick strictly ahead would skip that one too.
fn next_tick(since_ms: u128, interval_ms: u128, tick: u32) -> u32 {
    let next = since_ms.saturating_sub(interval_ms / 4).div_ceil(interval_ms);
    (next.min(u32::MAX as u128) as u32).max(tick + 1)
}
