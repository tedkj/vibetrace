//! The app's one way online: About's "Check this install" fetches the signed release list, and
//! only when the button is pressed. WinHTTP (Windows' own, through windows-sys): HTTPS only, to
//! `check::HOST` only, port 443, TLS 1.2 or newer, redirects off, the system's proxy settings,
//! short timeouts for each step and `check::FETCH_DEADLINE` for the whole fetch, at most
//! `check::LIST_CAP` bytes per file. Every setting must take, or nothing is fetched (review
//! RAB-3). What comes back is checked elsewhere (`check`): its minisign signature first, then
//! its contents.
//!
//! No test can reach the network: this module is the exe's alone and in no test build (main.rs
//! declares it `#[cfg(not(test))] mod net;`; the lib, the integration tests and the exe's own
//! unit tests never have it, review RAB-2), and it holds no test of its own (review RRAB-1). The
//! rules it follows that can be pure are in `check` and tested there; tests/pe.rs pins the rest
//! by this file's tokens, their order too (review RRAB-2), and that only `main` names
//! `fetch_release_list`. winhttp.dll is delay-loaded (build.rs), so it loads on the first
//! press, after `main`'s SetDefaultDllDirectories, from System32 only.

use std::time::Instant;
use vibetrace::check::{Fetched, HOST, fetch_budget, http_status, read_size, valid_list_path};
use windows_sys::Win32::Networking::WinHttp::*;

/// The release list at `path` on HOST, then its `.minisig` (`path` as `check::list_path` makes
/// it; anything else is refused without a request). Blocking: the check's worker calls it, and
/// waits for it at most FETCH_DEADLINE.
pub fn fetch_release_list(path: &str) -> Fetched {
    if !valid_list_path(path) {
        return Fetched::Failed("not a release-list address".into());
    }
    let started = Instant::now();
    let session = match Session::open() {
        Ok(s) => s,
        Err(e) => return e,
    };
    let list = match session.get(path, started) {
        Ok(b) => b,
        Err(e) => return e,
    };
    match session.get(&format!("{path}.minisig"), started) {
        Ok(sig) => Fetched::Got { list, sig },
        Err(e) => e,
    }
}

/// A WinHTTP handle, closed when dropped.
struct Handle(*mut core::ffi::c_void);

impl Handle {
    /// One DWORD option on this handle. WinHTTP must take it, or nothing is fetched.
    fn set(&self, option: u32, value: u32) -> Result<(), Fetched> {
        // SAFETY: a live handle, and a DWORD that outlives the call.
        if unsafe { WinHttpSetOption(self.0, option, (&value as *const u32).cast(), 4) } == 0 {
            return Err(Fetched::Failed(format!("WinHTTP refused setting {option}")));
        }
        Ok(())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: a handle WinHTTP gave out, closed once.
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

/// Fields drop in order: the connection before its session.
struct Session {
    connect: Handle,
    _session: Handle,
}

fn wide(s: &str) -> Vec<u16> {
    vibetrace::host::wide(s)
}

/// The last WinHTTP error as the fetcher's answer.
fn failure() -> Fetched {
    let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
    match code {
        ERROR_WINHTTP_NAME_NOT_RESOLVED | ERROR_WINHTTP_CANNOT_CONNECT | ERROR_WINHTTP_TIMEOUT | ERROR_WINHTTP_CONNECTION_ERROR | ERROR_WINHTTP_AUTODETECTION_FAILED => Fetched::Offline,
        ERROR_WINHTTP_SECURE_FAILURE | ERROR_WINHTTP_SECURE_FAILURE_PROXY => Fetched::Failed("the site's certificate didn't check out".into()),
        ERROR_WINHTTP_REDIRECT_FAILED => Fetched::Failed("the site sent it elsewhere".into()),
        other => Fetched::Failed(format!("WinHTTP error {other}")),
    }
}

impl Session {
    fn open() -> Result<Session, Fetched> {
        let agent = wide("VibeWare");
        let host = wide(HOST);
        // SAFETY: NUL-terminated strings that outlive the calls; each handle is closed by Handle.
        unsafe {
            let session = Handle(WinHttpOpen(agent.as_ptr(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, std::ptr::null(), std::ptr::null(), 0));
            if session.0.is_null() {
                return Err(Fetched::Failed("WinHTTP couldn't start".into()));
            }
            if WinHttpSetTimeouts(session.0, 5_000, 5_000, 5_000, 8_000) == 0 {
                return Err(Fetched::Failed("WinHTTP refused its timeouts".into()));
            }
            session.set(WINHTTP_OPTION_REDIRECT_POLICY, WINHTTP_OPTION_REDIRECT_POLICY_NEVER)?;
            // TLS 1.2 or newer: with 1.3 where this Windows has it, else 1.2 alone, else nothing.
            if session.set(WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3).is_err() {
                session.set(WINHTTP_OPTION_SECURE_PROTOCOLS, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2)?;
            }
            let connect = Handle(WinHttpConnect(session.0, host.as_ptr(), INTERNET_DEFAULT_HTTPS_PORT, 0));
            if connect.0.is_null() {
                return Err(failure());
            }
            Ok(Session { connect, _session: session })
        }
    }

    /// One GET over HTTPS: the body on 200, the fetcher's answer otherwise. `started`: when the
    /// whole fetch began (its deadline counts from there).
    fn get(&self, path: &str, started: Instant) -> Result<Vec<u8>, Fetched> {
        fetch_budget(0, started.elapsed())?;
        let verb = wide("GET");
        let object = wide(path);
        // SAFETY: NUL-terminated strings and buffers that outlive the calls; the request handle is
        // closed by Handle.
        unsafe {
            let req = Handle(WinHttpOpenRequest(self.connect.0, verb.as_ptr(), object.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null(), WINHTTP_FLAG_SECURE));
            if req.0.is_null() {
                return Err(failure());
            }
            req.set(WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION)?;
            if WinHttpSendRequest(req.0, std::ptr::null(), 0, std::ptr::null(), 0, 0, 0) == 0 || WinHttpReceiveResponse(req.0, std::ptr::null_mut()) == 0 {
                return Err(failure());
            }
            let mut status = 0u32;
            let mut len = 4u32;
            if WinHttpQueryHeaders(req.0, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, std::ptr::null(), (&mut status as *mut u32).cast(), &mut len, std::ptr::null_mut()) == 0 {
                return Err(failure());
            }
            http_status(status)?;
            let mut body = Vec::new();
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                fetch_budget(body.len(), started.elapsed())?;
                // What has come in (this waits at most the receive timeout), then that much: each
                // turn is bounded, so a peer that trickles bytes meets the deadline above.
                let mut ready = 0u32;
                if WinHttpQueryDataAvailable(req.0, &mut ready) == 0 {
                    return Err(failure());
                }
                if ready == 0 {
                    break;
                }
                let mut got = 0u32;
                if WinHttpReadData(req.0, buf.as_mut_ptr().cast(), read_size(ready, buf.len()), &mut got) == 0 {
                    return Err(failure());
                }
                if got == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..got as usize]);
            }
            Ok(body)
        }
    }
}
