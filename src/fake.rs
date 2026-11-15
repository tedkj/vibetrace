//! A scripted network for the tests (engine and window): routers, a destination, loss, load
//! balancing, rate limiting, route changes, unreachables and local failures, all keyed to the
//! round (how many times TTL 1 has been probed), so every run is the same.

use crate::trace::{Kind, Network, Opts, Outcome, Prober};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use windows_sys::Win32::NetworkManagement::IpHelper::IP_PACKET_TOO_BIG;

pub const HOST_UNREACHABLE: u32 = 11003;

#[derive(Clone, Debug)]
pub struct FakeHop {
    /// Answers from these in turn (one per round): several make a load-balanced hop.
    pub addrs: Vec<IpAddr>,
    pub rtt_ms: f64,
    /// Never answers.
    pub silent: bool,
    /// Loses the probe of every round divisible by this (a rate-limiting router: 3 is 33 %).
    pub lose_every: Option<u32>,
    /// Loses the probes of these rounds.
    pub lose: Vec<u32>,
    /// From this round on, answers from this address (a route change).
    pub change: Option<(u32, IpAddr)>,
    /// The MTU of the link into this hop (path MTU probes).
    pub mtu_in: u32,
    /// The router before that link drops packets too big for it without a word (a PMTUD black
    /// hole) instead of saying "fragmentation needed".
    pub black_hole: bool,
    /// Path MTU probes ending here are answered only every n-th time (ICMP rate limiting).
    pub mtu_every: Option<u32>,
    mtu_count: Arc<AtomicU32>,
    /// This router refuses to forward packets over this size, answering with this ICMP status
    /// ("prohibited", "host unreachable": a size-selective filter, R-14); ones it would forward
    /// smaller, or that end here, pass.
    pub refuse_over: Option<(u32, u32)>,
}

impl FakeHop {
    pub fn new(addr: &str, rtt_ms: f64) -> FakeHop {
        FakeHop {
            addrs: vec![addr.parse().unwrap()],
            rtt_ms,
            silent: false,
            lose_every: None,
            lose: vec![],
            change: None,
            mtu_in: 1500,
            black_hole: false,
            mtu_every: None,
            mtu_count: Arc::new(AtomicU32::new(0)),
            refuse_over: None,
        }
    }
}

/// Scripted DNS checks: each resolver answers its set result (9 ms and 12 ms by default).
pub struct FakeDns {
    pub results: std::sync::Mutex<std::collections::HashMap<crate::dnscheck::Which, crate::dnscheck::Check>>,
    pub asked: std::sync::Mutex<Vec<(crate::dnscheck::Which, bool)>>,
}

impl Default for FakeDns {
    fn default() -> Self {
        use crate::dnscheck::Which;
        let mut m = std::collections::HashMap::new();
        m.insert(Which::System, Ok(12_000));
        m.insert(Which::Public, Ok(9_000));
        FakeDns { results: Mutex::new(m), asked: Mutex::new(Vec::new()) }
    }
}

impl crate::dnscheck::DnsChecker for FakeDns {
    fn check(&self, which: crate::dnscheck::Which, aaaa: bool) -> crate::dnscheck::Check {
        self.asked.lock().unwrap().push((which, aaaa));
        self.results.lock().unwrap().get(&which).cloned().unwrap_or(Err("no answer in 5 s".into()))
    }
}

/// The tray's handler for its events, once the app has set it.
type OnEvent = std::rc::Rc<std::cell::RefCell<Option<std::rc::Rc<dyn Fn(crate::tray::Event)>>>>;
/// Who hears the session end, once the app has set it.
type OnEnd = std::rc::Rc<std::cell::RefCell<Option<std::rc::Rc<dyn Fn()>>>>;

/// A tray that records what it was asked (tests): "show <state> <tip>", "hide", "menu"; the
/// menu answers `pick`; with `missing` there is no notification area (no icon can show).
#[derive(Default)]
pub struct FakeTray {
    pub calls: std::rc::Rc<std::cell::RefCell<Vec<String>>>,
    pub pick: std::rc::Rc<std::cell::Cell<Option<u32>>>,
    pub on: OnEvent,
    pub missing: std::rc::Rc<std::cell::Cell<bool>>,
    /// Who hears Windows ending the session (call it to end it).
    pub session_end: OnEnd,
}

impl crate::tray::TrayHost for FakeTray {
    fn show(&self, state: crate::tray::State, tip: &str, on: std::rc::Rc<dyn Fn(crate::tray::Event)>) -> bool {
        if self.missing.get() {
            self.calls.borrow_mut().push("show failed".into());
            return false;
        }
        self.calls.borrow_mut().push(format!("show {state:?} {tip}"));
        *self.on.borrow_mut() = Some(on);
        true
    }

    fn hide(&self) {
        self.calls.borrow_mut().push("hide".into());
    }

    fn menu(&self, entries: &[(u32, String)]) -> Option<u32> {
        self.calls.borrow_mut().push(format!("menu {}", entries.iter().filter(|e| e.0 != 0).map(|e| e.1.as_str()).collect::<Vec<_>>().join(" | ")));
        self.pick.get()
    }

    fn on_session_end(&self, f: std::rc::Rc<dyn Fn()>) {
        *self.session_end.borrow_mut() = Some(f);
    }
}

/// A rate-limited router: answers only every n-th probe that ends there.
fn rate_limited(every: Option<u32>, count: &AtomicU32) -> bool {
    match every {
        Some(n) if n > 1 => count.fetch_add(1, Ordering::Relaxed) % n != n - 1,
        _ => false,
    }
}

#[derive(Clone, Debug)]
pub struct FakeNet {
    pub target: IpAddr,
    pub hops: Vec<FakeHop>,
    pub dest_rtt_ms: f64,
    pub dest_silent: bool,
    pub dest_lose: Vec<u32>,
    pub dest_lose_every: Option<u32>,
    /// Every this many rounds the destination answers this many ms later (a busy link).
    pub dest_spikes: Option<(u32, f64)>,
    /// From this hop index on, every probe gets "host unreachable" from that hop's router (in
    /// the rounds `unreachable_in` only, when it is not empty).
    pub unreachable_at: Option<usize>,
    pub unreachable_in: Vec<u32>,
    /// From this round on, the destination sits at this hop index.
    pub dest_moves: Option<(u32, usize)>,
    /// Every probe fails locally with this ICMP status.
    pub fail: Option<u32>,
    /// In these rounds every probe fails locally ("no route": the adapter is down).
    pub down: Vec<u32>,
    /// `open` refuses with this.
    pub open_error: Option<String>,
    /// Path MTU probes: this computer's link MTU (None: unreadable), the link into the
    /// destination, its black hole and rate limiting, and Windows' path cache for the target.
    pub link_mtu: Option<u32>,
    pub dest_mtu_in: u32,
    pub dest_black_hole: bool,
    pub dest_mtu_every: Option<u32>,
    dest_mtu_count: Arc<AtomicU32>,
    pub cache: Arc<Mutex<Option<u32>>>,
    /// The interface this computer reaches the target through (R-4; None: Windows did not say).
    pub via: Option<crate::isplog::Via>,
    round: Arc<AtomicU32>,
}

impl FakeNet {
    /// `routers` routers (10.0.0.1, .2, ... at 1, 2, ... ms) and then 93.184.216.34 at 20 ms.
    pub fn simple(routers: usize) -> FakeNet {
        FakeNet {
            target: "93.184.216.34".parse().unwrap(),
            hops: (0..routers).map(|i| FakeHop::new(&format!("10.0.0.{}", i + 1), (i + 1) as f64)).collect(),
            dest_rtt_ms: 20.0,
            dest_silent: false,
            dest_lose: vec![],
            dest_lose_every: None,
            dest_spikes: None,
            unreachable_at: None,
            unreachable_in: vec![],
            dest_moves: None,
            fail: None,
            down: vec![],
            open_error: None,
            link_mtu: Some(1500),
            dest_mtu_in: 1500,
            dest_black_hole: false,
            dest_mtu_every: None,
            dest_mtu_count: Arc::new(AtomicU32::new(0)),
            cache: Arc::new(Mutex::new(None)),
            via: None,
            round: Arc::new(AtomicU32::new(0)),
        }
    }

    /// A believable path for the window and its snapshots: home router, the ISP, a silent hop,
    /// a load-balanced core hop, a rate-limiting router, a slow-to-answer one, the destination.
    pub fn showcase() -> FakeNet {
        let mut n = FakeNet::simple(0);
        let mut h = vec![
            FakeHop::new("192.168.1.1", 0.4),
            FakeHop::new("100.64.0.1", 3.2),
            FakeHop::new("193.90.112.1", 4.1),
            FakeHop::new("193.90.112.9", 4.6),
            FakeHop::new("62.115.42.118", 9.8),
            FakeHop::new("62.115.122.158", 10.4),
            FakeHop::new("62.115.138.71", 18.2),
            FakeHop::new("152.195.80.141", 19.6),
            FakeHop::new("152.195.80.149", 20.1),
        ];
        h[3].silent = true;
        h[4].addrs = vec!["62.115.42.118".parse().unwrap(), "62.115.42.122".parse().unwrap()];
        h[5].lose_every = Some(4);
        h[6].rtt_ms = 44.0;
        n.hops = h;
        n.dest_rtt_ms = 20.6;
        n
    }

    pub fn rounds(&self) -> u32 {
        self.round.load(Ordering::Relaxed)
    }
}

impl Network for FakeNet {
    fn open(&self, _dest: IpAddr, _opts: &Opts) -> Result<Box<dyn Prober>, String> {
        if let Some(e) = &self.open_error {
            return Err(e.clone());
        }
        Ok(Box::new(FakeProber { net: self.clone() }))
    }

    fn link_mtu(&self, _dest: IpAddr) -> Option<u32> {
        self.link_mtu
    }

    fn cached_mtu(&self, dest: IpAddr) -> Option<u32> {
        if dest == self.target { *self.cache.lock().unwrap() } else { None }
    }

    fn via(&self, _dest: IpAddr) -> Option<crate::isplog::Via> {
        self.via.clone()
    }
}

struct FakeProber {
    net: FakeNet,
}

/// A few tenths of a millisecond of wobble, the same every run.
fn wobble(rtt_ms: f64, round: u32, i: usize) -> u32 {
    (rtt_ms * 1000.0) as u32 + ((round as usize * 7 + i * 3) % 5) as u32 * 90
}

impl Prober for FakeProber {
    fn probe(&mut self, ttl: u8) -> Outcome {
        let n = &self.net;
        let i = ttl as usize - 1;
        // Each round begins with TTL 1.
        let round = if ttl == 1 { n.round.fetch_add(1, Ordering::Relaxed) } else { n.round.load(Ordering::Relaxed).saturating_sub(1) };
        if let Some(s) = n.fail {
            return Outcome::Failed(s);
        }
        if n.down.contains(&round) {
            return Outcome::Failed(windows_sys::Win32::Foundation::ERROR_NETWORK_UNREACHABLE);
        }
        let dest = match n.dest_moves {
            Some((from, at)) if round >= from => at,
            _ => n.hops.len(),
        };
        if let Some(u) = n.unreachable_at.filter(|u| i >= *u && (n.unreachable_in.is_empty() || n.unreachable_in.contains(&round))) {
            let from = n.hops.get(u).map_or(n.target, |h| h.addrs[0]);
            let rtt = n.hops.get(u).map_or(n.dest_rtt_ms, |h| h.rtt_ms);
            return Outcome::Reply { from, kind: Kind::Unreachable(HOST_UNREACHABLE), rtt_us: wobble(rtt, round, i) };
        }
        if i >= dest {
            let lost = n.dest_silent || n.dest_lose.contains(&round) || n.dest_lose_every.is_some_and(|k| round % k == 0);
            let spike = n.dest_spikes.filter(|(k, _)| round % k == 0).map_or(0.0, |(_, ms)| ms);
            return if lost { Outcome::Lost } else { Outcome::Reply { from: n.target, kind: Kind::Echo, rtt_us: wobble(n.dest_rtt_ms + spike, round, i) } };
        }
        let hop = n.hops.get(i).cloned().unwrap_or_else(|| FakeHop::new(&format!("10.0.99.{}", i + 1), n.dest_rtt_ms - 1.0));
        if hop.silent || hop.lose.contains(&round) || hop.lose_every.is_some_and(|k| round % k == 0) {
            return Outcome::Lost;
        }
        let from = match hop.change {
            Some((r, a)) if round >= r => a,
            _ => hop.addrs[round as usize % hop.addrs.len()],
        };
        Outcome::Reply { from, kind: Kind::TtlExpired, rtt_us: wobble(hop.rtt_ms, round, i) }
    }

    /// A path MTU probe: the links into each hop up to the probed one, as Windows sends it
    /// (IPv4 with DF refused here when bigger than the link or the path cache; IPv6 split here
    /// instead, so it passes), routers saying "too big" (and Windows learning the MTU they
    /// report) or dropping it silently, rate-limited answers.
    fn probe_size(&mut self, ttl: u8, payload: u16, df: bool) -> Outcome {
        let n = &self.net;
        if let Some(s) = n.fail {
            return Outcome::Failed(s);
        }
        let v6 = n.target.is_ipv6();
        let size = payload as u32 + if v6 { 48 } else { 28 };
        let dest = n.hops.len();
        let end = (ttl as usize - 1).min(dest);
        let cached = *n.cache.lock().unwrap();
        // This computer: too big for its own link or for what Windows knows of the path.
        let mut split = !df && !v6;
        for limit in [n.link_mtu, cached].into_iter().flatten() {
            if size > limit {
                if v6 {
                    split = true;
                } else if df {
                    // Windows' own refusal: no reply, no sender, the last error says it.
                    return crate::icmp::sent_outcome(0, "0.0.0.0".parse().unwrap(), 0, IP_PACKET_TOO_BIG, n.target, 0);
                }
            }
        }
        if let Some(u) = n.unreachable_at.filter(|u| end >= *u) {
            let from = n.hops.get(u).map_or(n.target, |h| h.addrs[0]);
            return Outcome::Reply { from, kind: Kind::Unreachable(HOST_UNREACHABLE), rtt_us: 5_000 };
        }
        for j in 1..=end {
            if let Some((_, status)) = n.hops[j - 1].refuse_over.filter(|r| size > r.0) {
                return Outcome::Reply { from: n.hops[j - 1].addrs[0], kind: Kind::Unreachable(status), rtt_us: 4_000 };
            }
            let (mtu, quiet) = if j == dest { (n.dest_mtu_in, n.dest_black_hole) } else { (n.hops[j].mtu_in, n.hops[j].black_hole) };
            if size > mtu && !split {
                if quiet {
                    return Outcome::Lost;
                }
                let mut c = n.cache.lock().unwrap();
                *c = Some(c.map_or(mtu, |c| c.min(mtu)));
                // The router's "fragmentation needed" as IcmpSendEcho2 hands it over.
                return crate::icmp::sent_outcome(1, n.hops[j - 1].addrs[0], IP_PACKET_TOO_BIG, 0, n.target, 4_000);
            }
        }
        if end == dest {
            if n.dest_silent || rate_limited(n.dest_mtu_every, &n.dest_mtu_count) {
                return Outcome::Lost;
            }
            return Outcome::Reply { from: n.target, kind: Kind::Echo, rtt_us: (n.dest_rtt_ms * 1000.0) as u32 };
        }
        let hop = &n.hops[end];
        if hop.silent || rate_limited(hop.mtu_every, &hop.mtu_count) {
            return Outcome::Lost;
        }
        Outcome::Reply { from: hop.addrs[0], kind: Kind::TtlExpired, rtt_us: (hop.rtt_ms * 1000.0) as u32 }
    }
}
