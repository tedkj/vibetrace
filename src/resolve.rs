//! Names: the target (forward lookup), every responder's reverse DNS, and AS numbers through
//! Team Cymru's DNS service. All of it off the UI thread: the target on its own short thread,
//! the responders on one resolver thread, cached for the session.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Family {
    /// The resolver's first answer.
    #[default]
    Auto,
    V4,
    V6,
}

impl Family {
    pub fn index(self) -> i32 {
        match self {
            Family::Auto => 0,
            Family::V4 => 1,
            Family::V6 => 2,
        }
    }
    pub fn from_index(i: i32) -> Family {
        match i {
            1 => Family::V4,
            2 => Family::V6,
            _ => Family::Auto,
        }
    }
}

/// What the user typed, as a host: spaces trimmed, and a pasted URL or `host:port` cut down to
/// its host ("https://example.com/x" -> "example.com", "[2001:db8::1]" -> "2001:db8::1").
pub fn clean_target(input: &str) -> Result<String, String> {
    let mut s = input.trim();
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
    }
    if let Some(i) = s.find(['/', '?', '#']) {
        s = &s[..i];
    }
    if let Some(i) = s.rfind('@') {
        s = &s[i + 1..];
    }
    let host = if let Some(rest) = s.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else if s.matches(':').count() == 1 {
        s.split(':').next().unwrap_or("") // host:port; more colons is an IPv6 literal
    } else {
        s
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return Err("Type a host name or an address to trace.".into());
    }
    if host.chars().any(|c| c.is_whitespace() || invisible(c)) {
        return Err(format!("“{}” is not a host name or an address.", clean_name(host)));
    }
    Ok(host.to_string())
}

/// The first address of the family asked for (Auto: whatever came first).
pub fn pick(addrs: &[IpAddr], family: Family) -> Option<IpAddr> {
    addrs.iter().copied().find(|a| match family {
        Family::Auto => true,
        Family::V4 => a.is_ipv4(),
        Family::V6 => a.is_ipv6(),
    })
}

/// Forward lookup with the system's resolver (a literal needs none).
pub fn resolve_system(host: &str, family: Family) -> Result<IpAddr, String> {
    let addrs: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => (host, 0u16)
            .to_socket_addrs()
            .map_err(|e| resolve_error(host, &e))?
            .map(|a| a.ip())
            .collect(),
    };
    pick(&addrs, family).ok_or_else(|| match family {
        Family::V6 => format!("“{host}” has no IPv6 address."),
        Family::V4 => format!("“{host}” has no IPv4 address."),
        Family::Auto => format!("“{host}” has no address."),
    })
}

/// Addresses that are nobody's on the internet: private, CGNAT, loopback, link-local, ULA,
/// documentation, benchmarking (198.18/15, seen on carrier cores and from fake-IP proxies),
/// reserved and multicast. They get no AS lookup ("private"): Team Cymru has none for them.
pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_documentation()
                || a.is_multicast()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_private(IpAddr::V4(v4));
            }
            let s = a.segments();
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Team Cymru's origin query: "d.c.b.a.origin.asn.cymru.com", or the address's 32 nibbles
/// reversed under "origin6.asn.cymru.com".
pub fn origin_query(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::with_capacity(96);
            for b in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s + "origin6.asn.cymru.com"
        }
    }
}

/// An origin answer: "15169 | 8.8.8.0/24 | US | arin | 2023-12-28" -> (15169, "8.8.8.0/24").
/// Several origins ("13335 209242 | ...") take the first.
pub fn parse_origin(txt: &str) -> Option<(u32, String)> {
    let mut f = txt.split('|').map(str::trim);
    let asn = f.next()?.split_whitespace().next()?.parse().ok()?;
    let prefix = f.next().unwrap_or("").to_string();
    Some((asn, prefix))
}

/// An AS answer: "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US" -> "GOOGLE, US":
/// the part before " - " (or the name without its country), and the country, short.
pub fn parse_as_name(txt: &str) -> Option<String> {
    let f: Vec<&str> = txt.split('|').map(str::trim).collect();
    let cc = f.get(1).copied().unwrap_or("");
    let full = f.get(4)?.trim();
    if full.is_empty() {
        return None;
    }
    let short = match full.find(" - ") {
        Some(i) => &full[..i],
        None => full.rsplit_once(", ").filter(|(_, c)| c.len() == 2).map_or(full, |(n, _)| n),
    };
    Some(if cc.is_empty() { short.to_string() } else { format!("{short}, {cc}") })
}

/// A name from the network as it may be shown: no control characters (a newline would split
/// a report line), no bidirectional overrides or zero-width characters (they make a name read
/// as another), at most 255 characters (a DNS name's limit; TXT strings can be longer).
pub fn clean_name(s: &str) -> String {
    s.chars().filter(|c| !invisible(*c)).take(255).collect()
}

/// Characters that change how the text around them reads without showing themselves: controls,
/// bidirectional embeddings, overrides, isolates and marks, zero-width spaces and line
/// separators, the soft hyphen and the Unicode tag characters (U+E0000..U+E007F). The joiners
/// U+200C (ZWNJ) and U+200D (ZWJ) are not among them: emoji sequences and Persian, Arabic and
/// Indic names need them (family rule, 2026-10-20). The template's set (VibeTemplate `text.rs`,
/// IN-VibeTrace-5).
pub fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{E0000}'..='\u{E007F}')
}

/// What a lookup answered: `Ok(Some)` a name, `Ok(None)` there is none, `Err` the question
/// could not be answered now (a timeout, a server failure): unknown, never "none".
pub type Answer<T> = Result<Option<T>, String>;

/// The lookups, behind a trait so the window runs against a fake.
pub trait Lookup: Send + Sync {
    fn resolve(&self, host: &str, family: Family) -> Result<IpAddr, String>;
    /// The name a reverse lookup gives (PTR).
    fn reverse(&self, ip: IpAddr) -> Answer<String>;
    /// The origin AS and prefix of a public address.
    fn origin(&self, ip: IpAddr) -> Answer<(u32, String)>;
    /// The AS's short name with its country ("GOOGLE, US").
    fn as_name(&self, asn: u32) -> Answer<String>;
}

/// Windows' resolver: the system's DNS settings, its cache, its hosts file.
pub struct System;

impl Lookup for System {
    fn resolve(&self, host: &str, family: Family) -> Result<IpAddr, String> {
        resolve_system(host, family)
    }

    fn reverse(&self, ip: IpAddr) -> Answer<String> {
        reverse_system(ip)
    }

    fn origin(&self, ip: IpAddr) -> Answer<(u32, String)> {
        Ok(txt(&origin_query(ip))?.iter().find_map(|t| parse_origin(t)))
    }

    fn as_name(&self, asn: u32) -> Answer<String> {
        Ok(txt(&format!("AS{asn}.asn.cymru.com"))?.iter().find_map(|t| parse_as_name(t)))
    }
}

/// A reverse lookup's error: "no such name" and "no record of that kind" are answers (none);
/// anything else (a timeout, a server failure, no network) leaves it unknown.
pub fn reverse_error(code: i32) -> Answer<String> {
    match code {
        11001 | 11004 => Ok(None), // WSAHOST_NOT_FOUND, WSANO_DATA
        c => Err(format!("reverse lookup failed ({})", std::io::Error::from_raw_os_error(c))),
    }
}

/// A TXT query's status: NXDOMAIN and "no records" are answers (none); anything else is
/// unknown.
pub fn txt_error(status: u32) -> Result<Vec<String>, String> {
    match status {
        9003 | 9501 => Ok(Vec::new()), // DNS_ERROR_RCODE_NAME_ERROR, DNS_INFO_NO_RECORDS
        s => Err(format!("DNS query failed ({})", std::io::Error::from_raw_os_error(s as i32))),
    }
}

/// The forward lookup's error in words: a name that does not exist is "not found"; a name
/// with no address is said so; anything else is a lookup that could not be done now.
pub fn resolve_error(host: &str, e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(11001) => format!("“{host}” was not found (no such host name)."),
        Some(11004) => format!("“{host}” has no address."),
        _ => format!("“{host}” could not be looked up right now (the DNS server did not answer: {e}). Try again."),
    }
}

fn winsock() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        use windows_sys::Win32::Networking::WinSock::{WSADATA, WSAStartup};
        let mut d: WSADATA = unsafe { std::mem::zeroed() };
        // SAFETY: version 2.2 into a zeroed WSADATA; never cleaned up (process lifetime).
        unsafe { WSAStartup(0x0202, &mut d) };
    });
}

/// GetNameInfoW with NI_NAMEREQD: a name, None when the address has none, an error when the
/// question could not be answered.
fn reverse_system(ip: IpAddr) -> Answer<String> {
    use windows_sys::Win32::Networking::WinSock::*;
    winsock();
    let mut host = vec![0u16; NI_MAXHOST as usize];
    let r = unsafe {
        match ip {
            IpAddr::V4(a) => {
                let mut sa: SOCKADDR_IN = std::mem::zeroed();
                sa.sin_family = AF_INET;
                sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(a.octets());
                // SAFETY: a filled-in sockaddr of the size given; the name lands in `host`.
                GetNameInfoW((&sa as *const SOCKADDR_IN).cast(), size_of::<SOCKADDR_IN>() as i32, host.as_mut_ptr(), host.len() as u32, std::ptr::null_mut(), 0, NI_NAMEREQD as i32)
            }
            IpAddr::V6(a) => {
                let mut sa: SOCKADDR_IN6 = std::mem::zeroed();
                sa.sin6_family = AF_INET6;
                sa.sin6_addr.u.Byte = a.octets();
                // SAFETY: as above.
                GetNameInfoW((&sa as *const SOCKADDR_IN6).cast(), size_of::<SOCKADDR_IN6>() as i32, host.as_mut_ptr(), host.len() as u32, std::ptr::null_mut(), 0, NI_NAMEREQD as i32)
            }
        }
    };
    if r != 0 {
        // SAFETY: no arguments.
        return reverse_error(unsafe { WSAGetLastError() });
    }
    let len = host.iter().position(|&c| c == 0).unwrap_or(host.len());
    let name = String::from_utf16_lossy(&host[..len]).trim_end_matches('.').to_string();
    Ok((!name.is_empty() && name.parse::<IpAddr>().is_err()).then_some(name))
}

/// The TXT records of `name` (DnsQuery_W), each one's strings joined; none for a name that
/// does not exist, an error when the query could not be answered.
fn txt(name: &str) -> Result<Vec<String>, String> {
    use windows_sys::Win32::NetworkManagement::Dns::*;
    let w = crate::host::wide(name);
    let mut list: *mut DNS_RECORDA = std::ptr::null_mut();
    // SAFETY: a NUL-terminated name; the answer list is ours to free with DnsFree.
    let r = unsafe { DnsQuery_W(w.as_ptr(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, std::ptr::null_mut(), &mut list, std::ptr::null_mut()) };
    if r != 0 {
        return txt_error(r);
    }
    if list.is_null() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut p = list as *const DNS_RECORDW; // DnsQuery_W fills in the wide form
    while !p.is_null() {
        // SAFETY: a record of the list DnsQuery_W returned; TXT data holds `dwStringCount`
        // wide strings (the array runs past its declared length of one).
        unsafe {
            let rec = &*p;
            if rec.wType == DNS_TYPE_TEXT {
                let t = &rec.Data.TXT;
                let strings = std::slice::from_raw_parts(t.pStringArray.as_ptr(), t.dwStringCount as usize);
                let mut s = String::new();
                for &sp in strings {
                    if !sp.is_null() {
                        let len = (0..).take_while(|&i| *sp.add(i) != 0).count();
                        s.push_str(&String::from_utf16_lossy(std::slice::from_raw_parts(sp, len)));
                    }
                }
                out.push(s);
            }
            p = rec.pNext;
        }
    }
    // SAFETY: the list DnsQuery_W returned, freed once.
    unsafe { DnsFree(list as *const _, DnsFreeRecordList) };
    Ok(out)
}

// ---------- the resolver thread ----------

/// Where one lookup stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ask {
    /// Not answered yet (or not asked: switched off).
    #[default]
    Pending,
    /// Answered: a name, or none.
    Answered,
    /// Could not be answered (unknown, never "none"); `Resolver::retry_failed` asks again.
    Failed,
}

/// What the window shows (in quiet ink) where a name could not be looked up.
pub const NAME_FAILED: &str = "name lookup failed";
pub const AS_FAILED: &str = "AS lookup failed";
/// The origin answered, its AS's name could not be looked up (R2-TRACE-4: not the host column's words).
pub const AS_NAME_FAILED: &str = "AS name lookup failed";

/// What is known about one responder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Name {
    /// Reverse DNS, once looked up (None while pending, failed, or when it has none).
    pub host: Option<String>,
    pub host_ask: Ask,
    pub asn: Option<u32>,
    pub prefix: String,
    /// The origin and the AS's name: a failure of either fails this.
    pub as_ask: Ask,
    pub private: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Known {
    pub names: HashMap<IpAddr, Name>,
    /// AS number -> its short name with country.
    pub as_names: HashMap<u32, String>,
}

impl Known {
    /// "AS15169" and "GOOGLE, US" for an address, or "private" / nothing; a lookup that could
    /// not be answered says so ("AS lookup failed", or the number and "AS name lookup failed").
    pub fn as_text(&self, ip: IpAddr) -> (String, String) {
        match self.names.get(&ip) {
            Some(n) if n.private => ("private".into(), String::new()),
            Some(Name { asn: Some(a), as_ask, .. }) => {
                let name = self.as_names.get(a).cloned().unwrap_or_default();
                (format!("AS{a}"), if name.is_empty() && *as_ask == Ask::Failed { AS_NAME_FAILED.into() } else { name })
            }
            Some(n) if n.as_ask == Ask::Failed => (String::new(), AS_FAILED.into()),
            _ => (String::new(), String::new()),
        }
    }

    pub fn host(&self, ip: IpAddr) -> Option<&str> {
        self.names.get(&ip).and_then(|n| n.host.as_deref())
    }

    /// The reverse lookup of `ip` could not be answered (no name is known).
    pub fn host_failed(&self, ip: IpAddr) -> bool {
        self.names.get(&ip).is_some_and(|n| n.host.is_none() && n.host_ask == Ask::Failed)
    }

    /// Of the lookups `ips` need (names and AS numbers as switched on): how many are not
    /// answered yet, how many could not be answered, and how many were never asked (an address
    /// the trace did not hand in past its lookup caps, or one the resolver let go: RF4-6). An
    /// address is in `names` from the moment it is asked, so one missing was not asked, and is
    /// never counted as waiting for an answer.
    pub fn open(&self, ips: impl Iterator<Item = IpAddr>, names: bool, asn: bool) -> (usize, usize, usize) {
        let (mut pending, mut failed, mut not_asked) = (0, 0, 0);
        for ip in ips {
            let n = self.names.get(&ip);
            for (wanted, ask) in [(names, n.map(|n| n.host_ask)), (asn && !is_private(ip), n.map(|n| n.as_ask))] {
                match ask {
                    _ if !wanted => {}
                    None => not_asked += 1,
                    Some(Ask::Pending) => pending += 1,
                    Some(Ask::Failed) => failed += 1,
                    Some(Ask::Answered) => {}
                }
            }
        }
        (pending, failed, not_asked)
    }
}

/// Lookups waiting for the resolver thread at most; one past it is "not answered now" and asked
/// again with the failed ones (IN-VibeTrace-1).
pub const QUEUE: usize = 256;

/// Addresses the resolver keeps at most, asked and answered (RIN4-5, RF4-6). Past it the one
/// wanted least recently goes, with its names, so a new address is always asked: what bounds
/// the lookups is the trace (`trace::LOOKUPS_PER_HOP`, `trace::MAX_LOOKED_UP`), and a trace
/// wants at most 512 addresses, so the running trace's own are never the ones that go.
pub const MAX_ASKED: usize = 8192;

/// The addresses asked for, least recently wanted first (RF4-6).
#[derive(Default)]
struct Asked {
    /// Address -> (when last wanted, the (names, AS) switches it was asked with: a bit each).
    by_ip: HashMap<IpAddr, (u64, u8)>,
    /// When last wanted -> address: the oldest first.
    order: BTreeMap<u64, IpAddr>,
    tick: u64,
}

impl Asked {
    /// `ip` wanted with the switches `bit`: whether that is a new question, and the address let
    /// go to make room for it.
    fn want(&mut self, ip: IpAddr, bit: u8) -> (bool, Option<IpAddr>) {
        self.tick += 1;
        let now = self.tick;
        if let Some((when, mask)) = self.by_ip.get_mut(&ip) {
            // A hit counts as use: the running trace hands its addresses in again.
            self.order.remove(when);
            *when = now;
            self.order.insert(now, ip);
            let fresh = *mask & bit == 0;
            *mask |= bit;
            return (fresh, None);
        }
        let mut gone = None;
        if self.by_ip.len() >= MAX_ASKED
            && let Some((_, old)) = self.order.pop_first()
        {
            self.by_ip.remove(&old);
            gone = Some(old);
        }
        self.by_ip.insert(ip, (now, bit));
        self.order.insert(now, ip);
        (true, gone)
    }
}

/// One thread that looks up responders in turn, as they appear. Inline (tests): the lookups run
/// on the caller's thread at once.
pub struct Resolver {
    pub known: Arc<Mutex<Known>>,
    tx: Option<SyncSender<(IpAddr, bool, bool)>>,
    lookup: Arc<dyn Lookup>,
    asked: Mutex<Asked>,
}

impl Resolver {
    pub fn new(lookup: Arc<dyn Lookup>, inline: bool) -> Resolver {
        let known = Arc::new(Mutex::new(Known::default()));
        let tx = (!inline).then(|| {
            let (tx, rx) = sync_channel::<(IpAddr, bool, bool)>(QUEUE);
            let (k, l) = (known.clone(), lookup.clone());
            let _ = std::thread::Builder::new().name("resolver".into()).stack_size(256 * 1024).spawn(move || {
                while let Ok((ip, names, asn)) = rx.recv() {
                    work(&*l, &k, ip, names, asn);
                }
            });
            tx
        });
        Resolver { known, tx, lookup, asked: Mutex::new(Asked::default()) }
    }

    pub fn lookup(&self) -> &Arc<dyn Lookup> {
        &self.lookup
    }

    /// Look up `ip` (its name, its AS, as switched on); each once per session, unless it could
    /// not be answered (`retry_failed`).
    pub fn want(&self, ip: IpAddr, names: bool, asn: bool) {
        if !names && !asn {
            return;
        }
        let fresh = {
            let mut asked = self.asked.lock().unwrap();
            // At most MAX_ASKED addresses kept (RIN4-5): `Known::names` gets an address here
            // and loses it with `asked`, so it stays bounded too, over any number of traces,
            // and a spent budget never leaves a later trace's hops unasked (RF4-6).
            let (fresh, gone) = asked.want(ip, 1 << (names as u8 | (asn as u8) << 1));
            let mut k = self.known.lock().unwrap();
            if let Some(old) = gone {
                k.names.remove(&old);
            }
            k.names.entry(ip).or_insert_with(|| Name { private: is_private(ip), ..Name::default() });
            fresh
        };
        if fresh {
            self.send(ip, names, asn);
        }
    }

    /// Ask again every lookup that could not be answered (of those switched on now): a failure
    /// is never kept as the answer.
    pub fn retry_failed(&self, names: bool, asn: bool) {
        let failed: Vec<(IpAddr, bool, bool)> = {
            let k = self.known.lock().unwrap();
            k.names
                .iter()
                .filter_map(|(ip, n)| {
                    let (h, a) = (names && n.host_ask == Ask::Failed, asn && n.as_ask == Ask::Failed);
                    (h || a).then_some((*ip, h, a))
                })
                .collect()
        };
        for (ip, h, a) in failed {
            self.send(ip, h, a);
        }
    }

    fn send(&self, ip: IpAddr, names: bool, asn: bool) {
        match &self.tx {
            Some(tx) => {
                if let Err(std::sync::mpsc::TrySendError::Full(_)) = tx.try_send((ip, names, asn)) {
                    // The queue is full (IN-VibeTrace-1): not answered now, so asked again with
                    // the failed ones (`retry_failed`), never queued without end.
                    let mut k = self.known.lock().unwrap();
                    // Only an address still kept (one let go is not brought back: RF4-6).
                    let Some(n) = k.names.get_mut(&ip) else { return };
                    if names && n.host_ask != Ask::Answered {
                        n.host_ask = Ask::Failed;
                    }
                    if asn && !n.private && n.as_ask != Ask::Answered {
                        n.as_ask = Ask::Failed;
                    }
                }
            }
            None => work(&*self.lookup, &self.known, ip, names, asn),
        }
    }
}

/// One address's lookups. `want` puts the address in `Known::names`; an answer for one let go
/// since (RF4-6) is dropped, never brought back, so the map stays as bounded as `asked`.
fn work(l: &dyn Lookup, known: &Mutex<Known>, ip: IpAddr, names: bool, asn: bool) {
    let (need_host, need_as) = {
        let k = known.lock().unwrap();
        let Some(n) = k.names.get(&ip) else { return };
        (names && n.host_ask != Ask::Answered, asn && !n.private && n.as_ask != Ask::Answered)
    };
    if need_host {
        let r = l.reverse(ip);
        let mut k = known.lock().unwrap();
        let Some(n) = k.names.get_mut(&ip) else { return };
        match r {
            Ok(h) => {
                // What the network says is shown and reported: cleaned once, here.
                n.host = h.map(|h| clean_name(&h));
                n.host_ask = Ask::Answered;
            }
            Err(_) => n.host_ask = Ask::Failed,
        }
    }
    if need_as {
        let ask = match l.origin(ip) {
            Err(_) => Ask::Failed,
            Ok(None) => Ask::Answered,
            Ok(Some((a, prefix))) => {
                let have_name = {
                    let mut k = known.lock().unwrap();
                    let Some(n) = k.names.get_mut(&ip) else { return };
                    n.asn = Some(a);
                    // A TXT field as sent: cleaned and capped like the names (SNB7).
                    n.prefix = clean_name(&prefix);
                    k.as_names.contains_key(&a)
                };
                match if have_name { Ok(None) } else { l.as_name(a) } {
                    Err(_) => Ask::Failed,
                    Ok(name) => {
                        if let Some(name) = name {
                            let mut k = known.lock().unwrap();
                            k.as_names.insert(a, clean_name(&name));
                            // AS names the kept addresses no longer use go now and then
                            // (RF4-6): at most 2 x MAX_ASKED, cleared at most once per
                            // MAX_ASKED new ones.
                            if k.as_names.len() > 2 * MAX_ASKED {
                                let used: HashSet<u32> = k.names.values().filter_map(|n| n.asn).collect();
                                k.as_names.retain(|a, _| used.contains(a));
                            }
                        }
                        Ask::Answered
                    }
                }
            }
        };
        if let Some(n) = known.lock().unwrap().names.get_mut(&ip) {
            n.as_ask = ask;
        }
    }
}

// ---------- a fake for the tests ----------

/// Scripted names: forward entries, reverse names and AS data, and a log of what was asked.
/// Addresses in `fail` get no answer (a timeout) to their reverse and origin lookups.
#[derive(Default)]
pub struct FakeLookup {
    pub hosts: HashMap<String, Vec<IpAddr>>,
    pub ptr: HashMap<IpAddr, String>,
    pub origins: HashMap<IpAddr, (u32, String)>,
    pub as_names: HashMap<u32, String>,
    pub asked: Mutex<Vec<String>>,
    pub fail: Arc<Mutex<HashSet<IpAddr>>>,
}

impl FakeLookup {
    /// Names for `FakeNet::showcase()`.
    pub fn showcase() -> FakeLookup {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let mut f = FakeLookup::default();
        f.hosts.insert("example.com".into(), vec![ip("93.184.216.34"), ip("2606:2800:220:1:248:1893:25c8:1946")]);
        f.hosts.insert("v6only.example".into(), vec![ip("2001:db8::10")]);
        for (a, n) in [
            ("192.168.1.1", "router.lan"),
            ("193.90.112.1", "ti0001c360-ae3-0.ti.telenor.net"),
            ("62.115.42.118", "osl-b2-link.ip.twelve99.net"),
            ("62.115.42.122", "osl-b3-link.ip.twelve99.net"),
            ("62.115.122.158", "kbn-bb2-link.ip.twelve99.net"),
            ("62.115.138.71", "ldn-bb1-link.ip.twelve99.net"),
            ("152.195.80.141", "ae-66.core1.lhc.edgecastcdn.net"),
            ("93.184.216.34", "example.com"),
        ] {
            f.ptr.insert(ip(a), n.into());
        }
        for (a, asn, p) in [
            ("193.90.112.1", 2119, "193.90.0.0/16"),
            ("62.115.42.118", 1299, "62.115.0.0/16"),
            ("62.115.42.122", 1299, "62.115.0.0/16"),
            ("62.115.122.158", 1299, "62.115.0.0/16"),
            ("62.115.138.71", 1299, "62.115.0.0/16"),
            ("152.195.80.141", 15133, "152.195.80.0/24"),
            ("152.195.80.149", 15133, "152.195.80.0/24"),
            ("93.184.216.34", 15133, "93.184.216.0/24"),
        ] {
            f.origins.insert(ip(a), (asn, p.into()));
        }
        f.as_names.insert(2119, "TELENOR-NEXTEL, NO".into());
        f.as_names.insert(1299, "TWELVE99, SE".into());
        f.as_names.insert(15133, "EDGECAST, US".into());
        f
    }
}

impl Lookup for FakeLookup {
    fn resolve(&self, host: &str, family: Family) -> Result<IpAddr, String> {
        self.asked.lock().unwrap().push(format!("resolve {host}"));
        let addrs = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => self.hosts.get(host).cloned().ok_or_else(|| format!("“{host}” was not found (no such host name)."))?,
        };
        pick(&addrs, family).ok_or_else(|| format!("“{host}” has no {} address.", if family == Family::V6 { "IPv6" } else { "IPv4" }))
    }
    fn reverse(&self, ip: IpAddr) -> Answer<String> {
        self.asked.lock().unwrap().push(format!("ptr {ip}"));
        if self.fail.lock().unwrap().contains(&ip) {
            return Err("timed out".into());
        }
        Ok(self.ptr.get(&ip).cloned())
    }
    fn origin(&self, ip: IpAddr) -> Answer<(u32, String)> {
        self.asked.lock().unwrap().push(format!("origin {ip}"));
        if self.fail.lock().unwrap().contains(&ip) {
            return Err("timed out".into());
        }
        Ok(self.origins.get(&ip).cloned())
    }
    fn as_name(&self, asn: u32) -> Answer<String> {
        self.asked.lock().unwrap().push(format!("asname {asn}"));
        Ok(self.as_names.get(&asn).cloned())
    }
}
