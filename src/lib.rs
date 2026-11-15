//! VibeTrace: a proper traceroute for Windows: every hop, live. A VibeWare app: Rust and Slint on
//! the software renderer, one small exe, no runtime beside it.
//!
//! The engine (`icmp`, `trace`, `stats`, `resolve`) measures; `view` and `report` say what it
//! means; `controller` ties it to the window, which only lays out and draws.

pub mod check;
pub mod controller;
pub mod csvformat;
pub mod dnscheck;
pub mod fake;
pub mod host;
pub mod icmp;
pub mod isplog;
pub mod ispreport;
pub mod launch;
pub mod logfile;
pub mod mtu;
pub mod prefs;
pub mod report;
pub mod resolve;
pub mod stats;
pub mod text;
pub mod trace;
pub mod tray;
pub mod trust;
pub mod view;

use serde::{Deserialize, Serialize};
use slint::ComponentHandle;

slint::include_modules!();

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The choices the Options popup offers (index = the Segmented's option).
pub const INTERVALS_MS: [u32; 4] = [500, 1000, 2000, 5000];
pub const SIZES: [u16; 3] = [56, 512, 1400];
pub const MAX_HOPS: [u8; 3] = [15, 30, 64];
/// Recent targets remembered.
pub const RECENT: usize = 12;

/// What the window remembers between runs (prefs.json in %APPDATA%\com.tedkj.vibetrace).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// "dark" or "light" once the user has picked one; until then the system's choice.
    pub theme: Option<String>,
    /// Newest first.
    pub recent: Vec<String>,
    /// "auto", "ipv4" or "ipv6".
    pub family: String,
    pub interval_ms: u32,
    pub size: u16,
    pub max_hops: u8,
    /// Reverse DNS names (off: addresses only).
    pub names: bool,
    /// AS numbers through Team Cymru's DNS.
    pub asn: bool,
}

impl Default for Prefs {
    fn default() -> Self {
        Prefs { theme: None, recent: Vec::new(), family: "auto".into(), interval_ms: 1000, size: 56, max_hops: 30, names: true, asn: true }
    }
}

impl Prefs {
    pub fn dark(&self) -> bool {
        match self.theme.as_deref() {
            Some("dark") => true,
            Some("light") => false,
            _ => host::system_dark(),
        }
    }

    /// Only the values the window offers survive a hand-edited file; the rest fall back.
    pub fn sanitized(mut self) -> Prefs {
        let d = Prefs::default();
        if !INTERVALS_MS.contains(&self.interval_ms) {
            self.interval_ms = d.interval_ms;
        }
        if !SIZES.contains(&self.size) {
            self.size = d.size;
        }
        if !MAX_HOPS.contains(&self.max_hops) {
            self.max_hops = d.max_hops;
        }
        if !["auto", "ipv4", "ipv6"].contains(&self.family.as_str()) {
            self.family = d.family;
        }
        // Shown in the window as they are: each must still be a target the box would take
        // (`clean_target`: no invisible characters, no spaces) and a DNS name's length at most
        // (IN-VibeTrace-6).
        self.recent = std::mem::take(&mut self.recent).into_iter().filter_map(|r| resolve::clean_target(&r).ok()).filter(|h| h.chars().count() <= 253).take(RECENT).collect();
        self
    }

    pub fn family(&self) -> resolve::Family {
        match self.family.as_str() {
            "ipv4" => resolve::Family::V4,
            "ipv6" => resolve::Family::V6,
            _ => resolve::Family::Auto,
        }
    }

    pub fn set_family(&mut self, f: resolve::Family) {
        self.family = match f {
            resolve::Family::Auto => "auto",
            resolve::Family::V4 => "ipv4",
            resolve::Family::V6 => "ipv6",
        }
        .into();
    }

    /// `host` to the front of the recent targets (once, newest first, at most `RECENT`).
    pub fn remember(&mut self, host: &str) {
        self.recent.retain(|r| !r.eq_ignore_ascii_case(host));
        self.recent.insert(0, host.to_string());
        self.recent.truncate(RECENT);
    }

    pub fn opts(&self) -> trace::Opts {
        trace::Opts { interval_ms: self.interval_ms, timeout_ms: 2000, size: self.size, max_hops: self.max_hops }
    }
}

/// The command line, `VibeTrace.exe [<host>]` (`args` with the exe's own name first): the
/// target, any units (one that is not Unicode is shown with U+FFFD and refused by the target
/// check, never a panic at start, IN-VibeTrace-4); None when there is none or it is blank.
/// Err (SUP-2, the family rule: main ends the process with exit code 2 before any window or
/// file) for what the app does not take: a second argument, or an option (`--...`; no host
/// name or address starts with a dash).
pub fn target_arg(mut args: impl Iterator<Item = std::ffi::OsString>) -> Result<Option<String>, String> {
    let target = args.nth(1).map(|a| a.to_string_lossy().into_owned());
    if let Some(extra) = args.next() {
        return Err(format!("one target only, not also {}", extra.to_string_lossy()));
    }
    match target {
        Some(t) if t.starts_with("--") => Err(format!("unknown option {t}")),
        t => Ok(t.filter(|t| !t.trim().is_empty())),
    }
}

/// The window with its basics wired: theme, About, copying. The controller adds the rest (the
/// theme switch too: it saves on the prefs thread).
pub fn window(prefs: prefs::Store<Prefs>) -> Result<AppWindow, slint::PlatformError> {
    let ui = AppWindow::new()?;
    let p = prefs.load();
    ui.global::<Theme>().set_dark(p.dark());
    ui.set_version(VERSION.into());
    ui.on_copy_text(|t| host::copy_text(&t).is_ok());
    Ok(ui)
}
