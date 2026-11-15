//! Per-hop statistics and the path's verdicts. Pure code: no threads, no clocks, no I/O; every
//! number here is computed from what the probes measured, nothing is smoothed or invented.
//!
//! Round-trip times are kept in microseconds (`u32`); the views turn them into milliseconds.

use std::collections::VecDeque;
use std::net::IpAddr;

/// Probes kept per hop for the charts: 10 minutes at the fastest interval (0.5 s), so the
/// detail chart's 10 minutes are always filled.
pub const HISTORY: usize = 1200;
/// A route change: the newest this many replies all came from one new address.
pub const ROUTE_WINDOW: usize = 10;
/// The most addresses one hop keeps apart (a load-balanced hop answers from a handful): replies
/// from any further address are counted together in `Responders::other`, so forged or rotating
/// sources over a days-long ISP log cannot grow the list, the lookups or the scans of it
/// (IN-VibeTrace-1).
pub const MAX_RESPONDERS: usize = 16;
/// What a hop's normal loss is taken to be before it is known: as if `PRIOR_SENT` probes had
/// lost `PRIOR_LOST` (30 %). The outage rule and the path MTU's black-hole check judge losses
/// in a row against it, so a short history never makes a few lost probes look like more than a
/// lossy hop's usual (a fresh log needs 12 in a row; a minute of answers brings it to 5, five
/// minutes to 3).
pub const PRIOR_SENT: u32 = 10;
pub const PRIOR_LOST: u32 = 3;

/// A hop's normal loss from `lost` of `sent` probes, with the prior above: never 0 on little
/// history, the measured share once there is plenty.
pub fn normal_loss(sent: u32, lost: u32) -> f64 {
    (lost.min(sent) + PRIOR_LOST) as f64 / (sent + PRIOR_SENT) as f64
}

/// One probe in the history: the tick it was sent on, when (ms since the trace began) and its
/// round-trip time, or `None` when it was lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub tick: u32,
    pub at_ms: u64,
    pub rtt_us: Option<u32>,
}

/// Sent, received, last/best/worst, mean and stdev (Welford) and jitter (mtr's "Javg": the mean
/// absolute difference between consecutive replies; a loss in between does not break the pair).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Stats {
    pub sent: u32,
    pub received: u32,
    pub last_us: Option<u32>,
    pub best_us: Option<u32>,
    pub worst_us: Option<u32>,
    mean: f64,
    m2: f64,
    jitter_sum: f64,
    jitter_n: u32,
}

impl Stats {
    pub fn reply(&mut self, rtt_us: u32) {
        self.sent += 1;
        self.received += 1;
        if let Some(prev) = self.last_us {
            self.jitter_sum += (rtt_us as f64 - prev as f64).abs();
            self.jitter_n += 1;
        }
        self.last_us = Some(rtt_us);
        self.best_us = Some(self.best_us.map_or(rtt_us, |b| b.min(rtt_us)));
        self.worst_us = Some(self.worst_us.map_or(rtt_us, |w| w.max(rtt_us)));
        // Welford: numerically stable running mean and sum of squared deviations.
        let x = rtt_us as f64;
        let d = x - self.mean;
        self.mean += d / self.received as f64;
        self.m2 += d * (x - self.mean);
    }

    pub fn lost(&mut self) {
        self.sent += 1;
    }

    pub fn lost_count(&self) -> u32 {
        self.sent - self.received
    }

    /// Lost share of the probes sent, 0..1 (0 before the first probe).
    pub fn loss(&self) -> f64 {
        if self.sent == 0 { 0.0 } else { self.lost_count() as f64 / self.sent as f64 }
    }

    pub fn avg_ms(&self) -> Option<f64> {
        (self.received > 0).then(|| self.mean / 1000.0)
    }

    /// Sample standard deviation (n - 1), 0 for a single reply.
    pub fn stdev_ms(&self) -> Option<f64> {
        match self.received {
            0 => None,
            1 => Some(0.0),
            n => Some((self.m2 / (n - 1) as f64).max(0.0).sqrt() / 1000.0),
        }
    }

    pub fn jitter_ms(&self) -> Option<f64> {
        match self.received {
            0 => None,
            _ if self.jitter_n == 0 => Some(0.0),
            _ => Some(self.jitter_sum / self.jitter_n as f64 / 1000.0),
        }
    }
}

/// The last `HISTORY` probes of a hop, oldest first.
#[derive(Clone, Debug, Default)]
pub struct History {
    ring: VecDeque<Sample>,
}

impl History {
    pub fn push(&mut self, s: Sample) {
        if self.ring.len() == HISTORY {
            self.ring.pop_front();
        }
        self.ring.push_back(s);
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Sample> + ExactSizeIterator {
        self.ring.iter()
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }
}

/// One address a hop answered from, with how often.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Responder {
    pub addr: IpAddr,
    pub replies: u32,
    /// Replies since the hop's last route change (who the hop is now).
    pub recent: u32,
}

/// The addresses a hop answers from. Load balancers make one hop answer from several; the most
/// frequent one (since the last route change) is the hop's address, and a route change is a new
/// address answering every one of the newest `ROUTE_WINDOW` replies.
#[derive(Clone, Debug, Default)]
pub struct Responders {
    pub list: Vec<Responder>,
    /// Replies from addresses past the first MAX_RESPONDERS, counted together.
    pub other: u32,
    newest: VecDeque<IpAddr>,
    /// The address that last held the hop for a whole window (the first one to answer at the
    /// start): a route change is measured against it.
    settled: Option<IpAddr>,
}

impl Responders {
    /// Count a reply from `addr`; a route change comes back as (old, new).
    pub fn reply(&mut self, addr: IpAddr) -> Option<(IpAddr, IpAddr)> {
        let full = self.list.len() >= MAX_RESPONDERS;
        match self.list.iter_mut().find(|r| r.addr == addr) {
            Some(r) => {
                r.replies += 1;
                r.recent += 1;
            }
            None if !full => self.list.push(Responder { addr, replies: 1, recent: 1 }),
            None => self.other += 1,
        }
        if self.newest.len() == ROUTE_WINDOW {
            self.newest.pop_front();
        }
        self.newest.push_back(addr);
        let settled = *self.settled.get_or_insert(addr);
        let all_new = self.newest.len() == ROUTE_WINDOW && self.newest.iter().all(|a| *a == addr);
        if all_new && settled != addr {
            self.settled = Some(addr);
            if !self.has(addr) {
                // A new address holds the hop while the list is full: it takes the place of the
                // one with the fewest replies (those join `other`), with its last ROUTE_WINDOW.
                if let Some(k) = (0..self.list.len()).min_by_key(|&k| self.list[k].replies) {
                    let gone = self.list.remove(k);
                    self.other += gone.replies;
                }
                self.other = self.other.saturating_sub(ROUTE_WINDOW as u32);
                self.list.push(Responder { addr, replies: ROUTE_WINDOW as u32, recent: ROUTE_WINDOW as u32 });
            }
            // Who the hop is now starts over: the old address keeps its share in the list.
            for r in &mut self.list {
                r.recent = if r.addr == addr { ROUTE_WINDOW as u32 } else { 0 };
            }
            return Some((settled, addr));
        }
        None
    }

    /// The hop's address: most replies since the last route change, the earlier one on a tie.
    pub fn primary(&self) -> Option<IpAddr> {
        let mut best: Option<&Responder> = None;
        for r in &self.list {
            if best.is_none_or(|b| r.recent > b.recent) {
                best = Some(r);
            }
        }
        best.map(|r| r.addr)
    }

    /// Every responder, most replies first (the detail panel and the reports).
    pub fn ranked(&self) -> Vec<Responder> {
        let mut v = self.list.clone();
        v.sort_by_key(|r| std::cmp::Reverse(r.replies));
        v
    }

    pub fn total(&self) -> u32 {
        self.list.iter().map(|r| r.replies).sum::<u32>() + self.other
    }

    /// Is `addr` one of the hop's listed responders (not counted in `other`)?
    pub fn has(&self, addr: IpAddr) -> bool {
        self.list.iter().any(|r| r.addr == addr)
    }
}

// ---------- the path's verdicts ----------

/// What the attribution needs of one hop.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct HopFacts {
    pub sent: u32,
    pub received: u32,
    pub avg_ms: Option<f64>,
}

impl HopFacts {
    fn answers(&self) -> bool {
        self.received > 0
    }
    fn loss(&self) -> f64 {
        if self.sent == 0 { 0.0 } else { (self.sent - self.received) as f64 / self.sent as f64 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LossClass {
    /// No probe lost (or none sent yet).
    None,
    /// Carried on to every later hop and the destination: loss on the path.
    Real,
    /// Later hops lose clearly less: the router rate-limits its answers, the path is fine.
    Limited,
    /// The hop never answered: it does not answer pings at all.
    Silent,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Verdict {
    pub loss: LossClass,
    /// Answers more slowly than a later hop: slow to reply, not a slow path.
    pub slow: bool,
    /// The fastest average of the later hops (what `slow` compares with).
    pub later_avg_ms: Option<f64>,
}

/// Does `later` lose at least about as much as `own`? "About": within two standard errors of
/// the difference (the hops are sampled independently), and never closer than half a percent.
pub fn carried(own: HopFacts, later: HopFacts) -> bool {
    let (p, q) = (own.loss(), later.loss());
    if q >= p {
        return true;
    }
    if own.sent == 0 || later.sent == 0 {
        return true;
    }
    let sigma = (p * (1.0 - p) * (1.0 / own.sent as f64 + 1.0 / later.sent as f64)).sqrt();
    q >= p - (2.0 * sigma).max(0.005)
}

/// Slower than a later hop by more than 2 ms and 10 %.
fn slower(own: f64, later: f64) -> bool {
    own - later > (2.0f64).max(later * 0.1)
}

/// Verdicts for the hops `0..=reference` (the destination's hop, or the last hop that answers
/// when the destination does not). Hops past the reference are not judged (Silent / None).
///
/// A hop's loss is real only when the reference loses too and every later answering hop loses
/// at least about as much (`carried`): loss that stops at a router is that router rate-limiting
/// its ICMP answers, not loss on the path.
pub fn verdicts(hops: &[HopFacts], reference: Option<usize>) -> Vec<Verdict> {
    let mut out = vec![Verdict { loss: LossClass::None, slow: false, later_avg_ms: None }; hops.len()];
    for (i, h) in hops.iter().enumerate() {
        if !h.answers() {
            out[i].loss = if h.sent > 0 { LossClass::Silent } else { LossClass::None };
            continue;
        }
        let Some(r) = reference.filter(|r| *r < hops.len() && hops[*r].answers()) else {
            out[i].loss = if h.loss() > 0.0 { LossClass::Limited } else { LossClass::None };
            continue;
        };
        if i > r {
            continue;
        }
        let later: Vec<HopFacts> = hops[i + 1..=r].iter().copied().filter(|j| j.answers()).collect();
        out[i].loss = if h.loss() == 0.0 {
            LossClass::None
        } else if hops[r].loss() > 0.0 && later.iter().all(|j| carried(*h, *j)) {
            LossClass::Real
        } else {
            LossClass::Limited
        };
        let fastest = later.iter().filter_map(|j| j.avg_ms).fold(None, |m: Option<f64>, a| Some(m.map_or(a, |m| m.min(a))));
        out[i].later_avg_ms = fastest;
        out[i].slow = matches!((h.avg_ms, fastest), (Some(a), Some(f)) if slower(a, f));
    }
    out
}

/// Where the reference's loss starts: walk back from the reference while the answering hop
/// before loses at least about as much (it carries the same loss). None when the reference loses
/// nothing.
pub fn loss_start(hops: &[HopFacts], reference: Option<usize>) -> Option<usize> {
    let r = reference?;
    let rh = *hops.get(r)?;
    if !rh.answers() || rh.loss() == 0.0 {
        return None;
    }
    let mut start = r;
    for i in (0..r).rev() {
        let h = hops[i];
        if !h.answers() {
            continue; // a hop that never answers says nothing either way
        }
        // The hop named as the start must be one `verdicts` classes real (every later answering
        // hop loses about as much); a hop losing clearly more is a rate limiter inside the
        // stretch: step over it, the chain may go on before it.
        if h.loss() > 0.0 && carried(rh, h) && hops[i + 1..=r].iter().filter(|j| j.answers()).all(|j| carried(h, *j)) {
            start = i;
        } else if h.loss() > 0.0 && carried(rh, h) {
            continue;
        } else {
            break;
        }
    }
    Some(start)
}
