//! The ISP log's DNS checks (SPEC §9.4): every 30 s one lookup through the system resolver
//! (`DnsQuery_W`, past its cache and the hosts file: what applications get) and one through a
//! public resolver over our own UDP query (1.1.1.1), so "my ISP's DNS is down" can be told from
//! "the line is down". Any answer counts as working, "no such name" included; a server failure,
//! a refusal or no answer in 5 s is a failure with its reason.
//!
//! The public resolver's answer is read as hostile input: only a reply from that server, to our
//! ID, with the question echoed back exactly, is an answer; anything else is ignored.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Windows' own connectivity check name (NCSI): stable for years, and what Windows itself
/// resolves to decide whether DNS works.
pub const NAME: &str = "dns.msftncsi.com";
/// A check that has not answered in this long has failed.
pub const TIMEOUT_MS: u64 = 5000;
/// The public resolver: Cloudflare's, outside any ISP.
pub const PUBLIC_V4: &str = "1.1.1.1";
pub const PUBLIC_V6: &str = "2606:4700:4700::1111";

/// Which resolver a check asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Which {
    System,
    Public,
}

/// A check's result: the round trip in microseconds, or why it failed.
pub type Check = Result<u32, String>;

/// The public resolver for a trace of this family.
pub fn public_server(ipv6: bool) -> IpAddr {
    (if ipv6 { PUBLIC_V6 } else { PUBLIC_V4 }).parse().unwrap()
}

/// What the public resolver is called in the window and the reports.
pub fn public_name(ipv6: bool) -> &'static str {
    if ipv6 { PUBLIC_V6 } else { PUBLIC_V4 }
}

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

/// A standard query (RD set) for `name`'s A or AAAA record, with `id`. None for a name DNS
/// cannot carry (an empty label, a label over 63 bytes, over 253 in all, a non-ASCII byte).
pub fn query(id: u16, name: &str, aaaa: bool) -> Option<Vec<u8>> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return None;
    }
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT 1
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&(if aaaa { TYPE_AAAA } else { TYPE_A }).to_be_bytes());
    q.extend_from_slice(&[0, 1]); // IN
    Some(q)
}

/// What a datagram that came back says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The resolver answered (an address, no such name, no record of that type).
    Answer,
    /// The resolver answered with an error (server failure, refused...).
    Failure(String),
    /// Not an answer to our question (another ID, a query, a mangled packet): ignored.
    NotOurs,
}

/// Read a reply to `query(id, name, aaaa)`. Hostile input: every length is checked, nothing is
/// trusted but the header and the echoed question (compression pointers there are refused).
pub fn parse(resp: &[u8], id: u16, name: &str, aaaa: bool) -> Reply {
    if resp.len() < 12 || u16::from_be_bytes([resp[0], resp[1]]) != id {
        return Reply::NotOurs;
    }
    let (flags, rcode) = (resp[2], resp[3] & 0x0f);
    let qr = flags & 0x80 != 0;
    let opcode = (flags >> 3) & 0x0f;
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    if !qr || opcode != 0 || qdcount != 1 {
        return Reply::NotOurs;
    }
    // The question, label by label, must be ours (case aside: DNS names are case-blind and
    // some resolvers randomise the case they send on).
    let mut at = 12usize;
    let mut labels = Vec::new();
    loop {
        let Some(&len) = resp.get(at) else { return Reply::NotOurs };
        at += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || len > 63 {
            return Reply::NotOurs; // a pointer or a reserved label type in the question
        }
        let Some(label) = resp.get(at..at + len as usize) else { return Reply::NotOurs };
        labels.push(label);
        at += len as usize;
        if at > 12 + 255 {
            return Reply::NotOurs;
        }
    }
    let want: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    if labels.len() != want.len() || !labels.iter().zip(&want).all(|(a, b)| a.eq_ignore_ascii_case(b.as_bytes())) {
        return Reply::NotOurs;
    }
    let Some(tail) = resp.get(at..at + 4) else { return Reply::NotOurs };
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    let qclass = u16::from_be_bytes([tail[2], tail[3]]);
    if qtype != if aaaa { TYPE_AAAA } else { TYPE_A } || qclass != 1 {
        return Reply::NotOurs;
    }
    match rcode {
        0 | 3 => Reply::Answer, // NOERROR (an address, or no record of that type), NXDOMAIN
        1 => Reply::Failure("the server did not understand the question (format error)".into()),
        2 => Reply::Failure("the server failed (server failure)".into()),
        4 => Reply::Failure("the server does not do this (not implemented)".into()),
        5 => Reply::Failure("the server refused to answer".into()),
        r => Reply::Failure(format!("the server answered with error {r}")),
    }
}

/// A query ID nobody can guess from outside in a hurry (not security: the check only reads the
/// header). The performance counter's low bits, the process id and a counter, mixed.
fn fresh_id() -> u16 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    let mut x = t ^ ((std::process::id() as u64) << 32) ^ (N.fetch_add(0x9e37, Ordering::Relaxed) as u64).rotate_left(17);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x as u16
}

/// One check through `server` (UDP port 53): the round trip, or why not. Waits at most
/// `timeout`; datagrams that are not the answer are ignored meanwhile.
pub fn public_check(server: IpAddr, name: &str, aaaa: bool, timeout: Duration) -> Check {
    check_at(SocketAddr::new(server, 53), name, aaaa, timeout)
}

/// `public_check` against a server at any address and port (the tests' own on loopback).
pub fn check_at(to: SocketAddr, name: &str, aaaa: bool, timeout: Duration) -> Check {
    let server = to.ip();
    let id = fresh_id();
    let q = query(id, name, aaaa).ok_or("not a name DNS can carry")?;
    let local: SocketAddr = if server.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let sock = UdpSocket::bind(local).map_err(|e| format!("could not open a socket: {e}"))?;
    // Connected: Windows hands us datagrams from that server and port only.
    sock.connect(to).map_err(|e| format!("could not reach {server}: {e}"))?;
    let t0 = Instant::now();
    sock.send(&q).map_err(|e| format!("could not send to {server}: {e}"))?;
    let mut buf = [0u8; 1500];
    loop {
        let left = timeout.saturating_sub(t0.elapsed());
        if left.is_zero() {
            return Err(format!("no answer in {} s", timeout.as_secs()));
        }
        sock.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
        match sock.recv(&mut buf) {
            Ok(n) => match parse(&buf[..n], id, name, aaaa) {
                Reply::Answer => return Ok(t0.elapsed().as_micros().min(u32::MAX as u128) as u32),
                Reply::Failure(why) => return Err(why),
                Reply::NotOurs => continue,
            },
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Err(format!("no answer in {} s", timeout.as_secs()));
            }
            // An ICMP port unreachable comes back as a reset on a connected UDP socket.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => return Err(format!("{server} refused the query (port unreachable)")),
            Err(e) => return Err(format!("no answer: {e}")),
        }
    }
}

/// The checks, behind a trait so the window runs against a fake.
pub trait DnsChecker: Send + Sync {
    /// One check through `which` for the name's A (or AAAA) record; blocks up to the timeout.
    fn check(&self, which: Which, aaaa: bool) -> Check;
}

/// The real checks: Windows' resolver, and our own query to the public resolver.
pub struct SystemDns;

impl DnsChecker for SystemDns {
    fn check(&self, which: Which, aaaa: bool) -> Check {
        let t = Duration::from_millis(TIMEOUT_MS);
        match which {
            Which::System => system_check(NAME, aaaa, t),
            Which::Public => public_check(public_server(aaaa), NAME, aaaa, t),
        }
    }
}

/// A `DnsQuery_W` status in words: which ones are answers (none of them errors for the check).
pub fn system_status(status: u32) -> Result<(), String> {
    match status {
        0 | 9003 | 9501 => Ok(()), // an answer, NXDOMAIN, no records of that type
        9002 => Err("the DNS server failed (server failure)".into()),
        9005 => Err("the DNS server refused to answer".into()),
        9001 => Err("the DNS server did not understand the question (format error)".into()),
        1460 | 10060 => Err("no answer from the DNS server".into()),
        s => Err(format!("the lookup failed ({})", std::io::Error::from_raw_os_error(s as i32))),
    }
}

/// One check through the system resolver: what applications get (the configured servers, DoH,
/// VPN rules), past its cache and the hosts file. An answer after `timeout` is a failure too.
pub fn system_check(name: &str, aaaa: bool, timeout: Duration) -> Check {
    use windows_sys::Win32::NetworkManagement::Dns::*;
    let w = crate::host::wide(name);
    let mut list: *mut DNS_RECORDA = std::ptr::null_mut();
    let t0 = Instant::now();
    let ty = if aaaa { DNS_TYPE_AAAA } else { DNS_TYPE_A };
    // SAFETY: a NUL-terminated name; the answer list is ours to free with DnsFree.
    let r = unsafe { DnsQuery_W(w.as_ptr(), ty, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE, std::ptr::null_mut(), &mut list, std::ptr::null_mut()) };
    let took = t0.elapsed();
    if !list.is_null() {
        // SAFETY: the list DnsQuery_W returned, freed once.
        unsafe { DnsFree(list as *const _, DnsFreeRecordList) };
    }
    system_status(r as u32)?;
    if took > timeout {
        return Err(format!("no answer in {} s (it came after {:.1} s)", timeout.as_secs(), took.as_secs_f64()));
    }
    Ok(took.as_micros().min(u32::MAX as u128) as u32)
}
