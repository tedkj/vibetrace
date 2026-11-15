//! Windows' ICMP API: echo requests with a TTL (hop limit), no admin rights and no raw socket.
//! `IcmpSendEcho2` for IPv4 and `Icmp6SendEcho2` for IPv6, called synchronously; the round trip
//! is timed around the call with the performance counter (`Instant`), because the API's own
//! `RoundTripTime` is whole milliseconds, useless on a LAN.
//!
//! The unsafe code is the three calls (open, send, close) and reading the reply struct the API
//! wrote at the start of our buffer; everything else is plain Rust.

use crate::trace::{Kind, Network, Opts, Outcome, Prober};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
use windows_sys::Win32::Foundation::{ERROR_HOST_UNREACHABLE, ERROR_NETWORK_UNREACHABLE, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};

pub const SUCCESS: u32 = IP_SUCCESS;
pub const TIMED_OUT: u32 = IP_REQ_TIMED_OUT;
pub const GENERAL_FAILURE: u32 = IP_GENERAL_FAILURE;

/// A status in plain words (the window and the report show these).
pub fn words(status: u32, ipv6: bool) -> &'static str {
    match status {
        IP_SUCCESS => "reply",
        IP_REQ_TIMED_OUT => "no reply in time",
        IP_TTL_EXPIRED_TRANSIT | IP_TIME_EXCEEDED => "time exceeded",
        IP_TTL_EXPIRED_REASSEM => "time exceeded while reassembling",
        IP_DEST_NET_UNREACHABLE => "network unreachable",
        IP_DEST_HOST_UNREACHABLE => "host unreachable",
        IP_DEST_PROT_UNREACHABLE => "prohibited by a filter",
        IP_DEST_PORT_UNREACHABLE => "port unreachable",
        IP_DEST_UNREACHABLE => "destination unreachable",
        IP_DEST_SCOPE_MISMATCH => "the address is out of scope",
        IP_PACKET_TOO_BIG => "packet too big for the path",
        IP_SOURCE_QUENCH => "source quench",
        IP_PARAM_PROBLEM => "parameter problem",
        IP_BAD_DESTINATION => "not an address that can be pinged",
        IP_BAD_ROUTE => "bad route",
        IP_NO_RESOURCES => "out of network resources on this computer",
        IP_HW_ERROR => "a network hardware error on this computer",
        IP_BUF_TOO_SMALL => "the reply did not fit",
        IP_GENERAL_FAILURE if ipv6 => "This computer has no IPv6 route to that address",
        IP_GENERAL_FAILURE => "Windows could not send the probe (general failure)",
        IP_BAD_HEADER => "parameter problem (bad header)",
        IP_UNRECOGNIZED_NEXT_HEADER => "parameter problem (unrecognized next header)",
        IP_ICMP_ERROR => "an ICMP error",
        // Win32 errors (GetLastError) when nothing went out: what this Windows says for "no
        // route", where older ones said general failure.
        ERROR_NETWORK_UNREACHABLE | ERROR_HOST_UNREACHABLE if ipv6 => "This computer has no IPv6 route to that address",
        ERROR_NETWORK_UNREACHABLE => "This computer has no route to that network",
        ERROR_HOST_UNREACHABLE => "This computer has no route to that host",
        _ => "an unexpected ICMP status",
    }
}

/// What a reply's status says about who sent it.
pub fn kind_of(status: u32) -> Option<Kind> {
    match status {
        IP_SUCCESS => Some(Kind::Echo),
        IP_TTL_EXPIRED_TRANSIT | IP_TIME_EXCEEDED | IP_TTL_EXPIRED_REASSEM => Some(Kind::TtlExpired),
        IP_DEST_NET_UNREACHABLE | IP_DEST_HOST_UNREACHABLE | IP_DEST_PROT_UNREACHABLE | IP_DEST_PORT_UNREACHABLE | IP_DEST_UNREACHABLE
        | IP_DEST_SCOPE_MISMATCH => Some(Kind::Unreachable(status)),
        // Router errors that name a sender: a hop like any other, not a local failure.
        IP_PACKET_TOO_BIG | IP_SOURCE_QUENCH | IP_PARAM_PROBLEM | IP_BAD_ROUTE | IP_BAD_HEADER | IP_UNRECOGNIZED_NEXT_HEADER | IP_ICMP_ERROR => {
            Some(Kind::Other(status))
        }
        _ => None,
    }
}

/// Turn what the API wrote into an outcome. `from` is the replying address if the reply struct
/// was filled in (unspecified when not), `status` its status (or the last error when the call
/// returned no reply).
pub fn outcome(from: Option<IpAddr>, status: u32, rtt_us: u32) -> Outcome {
    if status == IP_REQ_TIMED_OUT {
        return Outcome::Lost;
    }
    match (from.filter(|a| !a.is_unspecified()), kind_of(status)) {
        (Some(from), Some(kind)) => Outcome::Reply { from, kind, rtt_us },
        _ => Outcome::Failed(status),
    }
}

/// What `IcmpSendEcho2` / `Icmp6SendEcho2` gave, as an outcome: `n` replies counted, the
/// reply struct's sender and status, the last error when `n` is 0. Some Windows versions fill
/// in the reply (a time-exceeded, a "fragmentation needed", with its sender) and return 0:
/// trusted when they do. Without a sender it never left this computer (Windows' own "too big"
/// refusal is that). The fake network answers through this too.
///
/// An echo reply counts only from `dest`, the address the probe went to: from any other address
/// it is not the destination answering, so it is a loss (SNB5, the same rule as VibePing's
/// `icmp::result`). It neither marks the destination reached nor ends an outage in the ISP log.
/// An echo with no sender (0.0.0.0 or ::) is not the destination either: a loss too, not a
/// failure on this computer (APB4, as in VibePing).
/// Windows itself matches a reply to its request (identifier, sequence).
pub fn sent_outcome(n: u32, from: IpAddr, status: u32, last_error: u32, dest: IpAddr, rtt_us: u32) -> Outcome {
    if n > 0 && status == IP_SUCCESS && from.is_unspecified() {
        return Outcome::Lost;
    }
    let o = if n > 0 || (status != 0 && !from.is_unspecified()) { outcome(Some(from), status, rtt_us) } else { outcome(None, last_error, rtt_us) };
    match o {
        Outcome::Reply { from, kind: Kind::Echo, .. } if from != dest => Outcome::Lost,
        o => o,
    }
}

pub struct Icmp;

/// A socket address for the IP helper calls.
fn sockaddr_inet(a: IpAddr) -> windows_sys::Win32::Networking::WinSock::SOCKADDR_INET {
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};
    let mut s: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match a {
        IpAddr::V4(v) => {
            s.Ipv4.sin_family = AF_INET;
            s.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v.octets());
        }
        IpAddr::V6(v) => {
            s.Ipv6.sin6_family = AF_INET6;
            s.Ipv6.sin6_addr.u.Byte = v.octets();
        }
    }
    s
}

/// The address in a SOCKADDR_INET (None for another family).
fn from_sockaddr_inet(s: &windows_sys::Win32::Networking::WinSock::SOCKADDR_INET) -> Option<IpAddr> {
    use windows_sys::Win32::Networking::WinSock::AF_INET;
    // SAFETY: the family says which member of the union is filled in.
    unsafe {
        match s.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(s.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(s.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

/// What Windows' path cache has learned for `dest` (R-10): of its rows (destination, interface
/// index, PathMtu), only those of the interface the route to `dest` uses (`index`), and only
/// below that interface's own MTU: a row exists for any destination recently talked to, and
/// holds the interface MTU until a "too big" lowers it. Another adapter's row (a VPN or
/// Tailscale switched off minutes ago) says nothing about this path.
pub fn learned_mtu(rows: &[(IpAddr, u32, u32)], dest: IpAddr, index: u32, link_mtu: u32) -> Option<u32> {
    rows.iter().filter(|r| r.0 == dest && r.1 == index && r.2 >= 68 && r.2 < link_mtu).map(|r| r.2).min()
}

/// The interface Windows would send to `dest` through (GetBestInterfaceEx) and its IP MTU.
fn best_interface(dest: IpAddr) -> Option<(u32, u32)> {
    let sa = sockaddr_inet(dest);
    let mut index = 0u32;
    // SAFETY: a filled-in socket address (the union's first bytes are the family).
    if unsafe { GetBestInterfaceEx((&sa as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_INET).cast(), &mut index) } != 0 {
        return None;
    }
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    row.Family = if dest.is_ipv6() { AF_INET6 } else { windows_sys::Win32::Networking::WinSock::AF_INET };
    row.InterfaceIndex = index;
    // SAFETY: the family and index are set, as the call asks; it fills in the rest.
    if unsafe { GetIpInterfaceEntry(&mut row) } != 0 {
        return None;
    }
    Some((index, row.NlMtu))
}

impl Network for Icmp {
    /// The MTU of the interface Windows would send to `dest` through (GetBestInterfaceEx, then
    /// the interface's IP MTU). No admin rights.
    fn link_mtu(&self, dest: IpAddr) -> Option<u32> {
        best_interface(dest).map(|x| x.1).filter(|m| *m >= 68)
    }

    /// The path MTU Windows has learned for `dest` on the interface the route uses (a
    /// "fragmentation needed" / "packet too big" lowered it below that interface's MTU):
    /// `learned_mtu` over `GetIpPathTable`. No admin rights.
    fn cached_mtu(&self, dest: IpAddr) -> Option<u32> {
        let (index, link) = best_interface(dest)?;
        let mut table: *mut MIB_IPPATH_TABLE = std::ptr::null_mut();
        let family = if dest.is_ipv6() { AF_INET6 } else { windows_sys::Win32::Networking::WinSock::AF_INET };
        // SAFETY: the table is allocated by the call and freed with FreeMibTable below.
        if unsafe { GetIpPathTable(family, &mut table) } != 0 || table.is_null() {
            return None;
        }
        let mut rows = Vec::new();
        // SAFETY: NumEntries rows follow the header, as the call wrote them.
        unsafe {
            for r in std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize) {
                if let Some(d) = from_sockaddr_inet(&r.Destination).filter(|d| *d == dest) {
                    rows.push((d, r.InterfaceIndex, r.PathMtu));
                }
            }
            FreeMibTable(table as *const _);
        }
        learned_mtu(&rows, dest, index, link)
    }

    /// The interface the route to `dest` uses (GetBestInterfaceEx), by its name as the network
    /// settings show it (`Alias`; the adapter's description when that is empty) and what it is
    /// (`ViaKind::of` its type and tunnel type): `GetIfEntry2`. No admin rights.
    fn via(&self, dest: IpAddr) -> Option<crate::isplog::Via> {
        let (index, _) = best_interface(dest)?;
        // SAFETY: a plain struct; the call reads the index (the LUID left zero) and fills in
        // the rest.
        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceIndex = index;
        if unsafe { GetIfEntry2(&mut row) } != 0 {
            return None;
        }
        let text = |w: &[u16]| String::from_utf16_lossy(&w[..w.iter().position(|c| *c == 0).unwrap_or(w.len())]).trim().to_string();
        let name = Some(text(&row.Alias)).filter(|n| !n.is_empty()).unwrap_or_else(|| text(&row.Description));
        (!name.is_empty()).then(|| crate::isplog::Via { name, kind: crate::isplog::ViaKind::of(row.Type, row.TunnelType) })
    }

    fn open(&self, dest: IpAddr, opts: &Opts) -> Result<Box<dyn Prober>, String> {
        // SAFETY: no arguments; INVALID_HANDLE_VALUE on failure.
        let handle = unsafe { if dest.is_ipv6() { Icmp6CreateFile() } else { IcmpCreateFile() } };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(format!("Windows' ICMP service did not open: {}", std::io::Error::last_os_error()));
        }
        // The reply struct, the echoed payload, 8 bytes for an ICMP error and room for the
        // offending packet's IP header (IPv6: 40, IPv4: up to 60) it may quote. u64s keep the
        // struct (which holds a pointer) aligned.
        let reply = if dest.is_ipv6() { size_of::<ICMPV6_ECHO_REPLY_LH>() } else { size_of::<ICMP_ECHO_REPLY>() };
        let bytes = reply + opts.size as usize + 8 + 64 + 64;
        Ok(Box::new(IcmpProber {
            handle,
            dest,
            payload: (0..opts.size).map(|i| b'a' + (i % 23) as u8).collect(),
            reply: vec![0u64; bytes.div_ceil(8)],
            timeout_ms: opts.timeout_ms,
        }))
    }
}

struct IcmpProber {
    handle: HANDLE,
    dest: IpAddr,
    payload: Vec<u8>,
    reply: Vec<u64>,
    timeout_ms: u32,
}

// SAFETY: the handle belongs to this prober alone and is used by one thread at a time.
unsafe impl Send for IcmpProber {}

impl Drop for IcmpProber {
    fn drop(&mut self) {
        // SAFETY: opened in `open`, closed once.
        unsafe { IcmpCloseHandle(self.handle) };
    }
}

impl Prober for IcmpProber {
    fn probe(&mut self, ttl: u8) -> Outcome {
        self.probe_size(ttl, self.payload.len() as u16, false)
    }

    fn probe_size(&mut self, ttl: u8, payload: u16, df: bool) -> Outcome {
        // IP_FLAG_DF: routers must not fragment it (IPv4; Icmp6SendEcho2 ignores it, IPv6
        // routers never fragment).
        let opt = IP_OPTION_INFORMATION { Ttl: ttl, Flags: if df { IP_FLAG_DF as u8 } else { 0 }, ..Default::default() };
        self.reply.fill(0);
        let size = (self.reply.len() * 8) as u32;
        let buf = self.reply.as_mut_ptr().cast::<core::ffi::c_void>();
        let len = payload.min(self.payload.len() as u16);
        let data = self.payload.as_ptr().cast();
        let t0 = Instant::now();
        // The last error is read on the line after each send (FA4/FA17): no reply counted, it
        // says why.
        // SAFETY (each GetLastError): no arguments.
        let (n, err, from, status) = match self.dest {
            IpAddr::V4(d) => {
                // SAFETY: a synchronous call (no event, no APC): it writes at most `size` bytes
                // into `buf` and returns when a reply came or the timeout passed.
                let n = unsafe {
                    IcmpSendEcho2(self.handle, std::ptr::null_mut(), None, std::ptr::null(), u32::from_ne_bytes(d.octets()), data, len, &opt, buf, size, self.timeout_ms)
                };
                let err = if n > 0 { 0 } else { unsafe { GetLastError() } };
                // SAFETY: the buffer is zeroed, aligned and at least one ICMP_ECHO_REPLY long;
                // the API writes the first reply at its start.
                let r = unsafe { &*(buf as *const ICMP_ECHO_REPLY) };
                (n, err, IpAddr::V4(Ipv4Addr::from(r.Address.to_ne_bytes())), r.Status)
            }
            IpAddr::V6(d) => {
                let mut src: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
                src.sin6_family = AF_INET6;
                let mut dst: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
                dst.sin6_family = AF_INET6;
                dst.sin6_addr.u.Byte = d.octets();
                // SAFETY: as above; the source is "any" (the system picks the address).
                let n = unsafe {
                    Icmp6SendEcho2(self.handle, std::ptr::null_mut(), None, std::ptr::null(), &src, &dst, data, len, &opt, buf, size, self.timeout_ms)
                };
                let err = if n > 0 { 0 } else { unsafe { GetLastError() } };
                // No Icmp6ParseReplies (FA17): that is for the asynchronous form; the
                // synchronous call hands the buffer back parsed, and a second parse can rewrite
                // a non-echo reply's Status.
                // SAFETY: zeroed, aligned, at least one ICMPV6_ECHO_REPLY_LH long; the API
                // writes the first reply at its start.
                let r = unsafe { &*(buf as *const ICMPV6_ECHO_REPLY_LH) };
                // The address words are in network byte order.
                let words = r.Address.sin6_addr.map(u16::from_be);
                (n, err, IpAddr::V6(Ipv6Addr::from(words)), r.Status)
            }
        };
        let rtt_us = t0.elapsed().as_micros().min(u32::MAX as u128) as u32;
        sent_outcome(n, from, status, err, self.dest, rtt_us)
    }
}
