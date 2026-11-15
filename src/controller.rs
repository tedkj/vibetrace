//! The window's brain. It lives on the UI thread: it starts and stops traces, and on a ~200 ms
//! timer (only while something is running) copies a snapshot of the shared `Trace` and the
//! names into the window's models. The .slint files lay out what it hands them; every number,
//! word and colour choice is made here or in `view`.

use crate::check::{Dot, Fetched, Local, Release, Rows};
use crate::dnscheck::{Check, DnsChecker, Which};
pub use crate::host::{SaveKind, SaveOffer};
use crate::isplog::{HopLook, Outage, OutageRec, Record, RunRec};
use crate::logfile::{self, LogWriter};
use crate::mtu::{MtuRun, Plan};
use crate::prefs::{Change, Store, write_atomic};
use crate::report::{self, Context};
use crate::resolve::{self, Family, Lookup, Resolver};
use crate::stats::LossClass;
use crate::trace::{EventKind, Hop, Network, Session, Trace, WallClock};
use crate::tray::{self, TrayHost};
use std::sync::atomic::AtomicBool;
use crate::view::{self, HopView, PathView};
use crate::{AppWindow, CheckDot, CheckRow, DetailInfo, EventRow, HopRow, INTERVALS_MS, MAX_HOPS, Prefs, ResponderRow, SIZES, SummaryInfo, Theme, ToastItem, ToastKind};
use slint::platform::Key;
use slint::{ComponentHandle, Model, ModelRc, SharedString, Timer, TimerMode, VecModel, Weak};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, TryRecvError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How often the window looks at the trace while it runs.
pub const POLL_MS: u64 = 200;
/// The wall clock running ahead of the session's clock by more than this while logging (sleep
/// or hibernate, which the monotonic clock may not count; a clock set forward): the log's times
/// follow the wall clock from there on.
pub const CLOCK_STEP_MS: u64 = 5_000;
/// Polls after a stop that still pick up names arriving late (5 s).
const LINGER: u32 = 25;
/// Probes in a row's sparkline: 50 bars of 2 px with a 1 px gap (150 px).
pub const BARS: usize = 50;
/// Polls between asking again the name and AS lookups that could not be answered (30 s).
pub const RETRY_POLLS: u32 = 150;
/// The detail chart's span grows with the trace up to this.
const CHART_SPAN_MAX_MS: u64 = 600_000;

/// What the controller needs from the outside world; the tests hand it fakes.
pub struct Services {
    pub net: Arc<dyn Network>,
    pub lookup: Arc<dyn Lookup>,
    /// Tests: no threads anywhere (the target resolves inline, sessions run when stepped).
    pub manual: bool,
    pub copy: Box<dyn Fn(&str) -> bool>,
    /// A path to save a report to (the system's dialog), from a suggested file name.
    pub save_as: SaveAs,
    pub reveal: Box<dyn Fn(&std::path::Path)>,
    pub now: Box<dyn Fn() -> WallClock>,
    /// The user's list separator and decimal symbol, asked at each CSV export.
    pub csv_format: Box<dyn Fn() -> crate::csvformat::CsvFormat>,
    /// UTC milliseconds now, and the local time of one (the ISP log and its report).
    pub clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub local: Arc<dyn Fn(u64) -> WallClock + Send + Sync>,
    /// Where the ISP logs live (%LOCALAPPDATA%\com.tedkj.vibetrace\logs).
    pub logs: PathBuf,
    /// The ISP log's DNS checks.
    pub dns: Arc<dyn DnsChecker>,
    /// The tray icon while the window is hidden in it.
    pub tray: Box<dyn TrayHost>,
    /// Leave the event loop (Quit from the tray, Windows ending the session).
    pub quit: Box<dyn Fn()>,
    /// A web page in the browser (About's link).
    pub open_url: Box<dyn Fn(&str)>,
    /// The install check's offline half, on its worker: this copy's files, their signatures and
    /// hashes (`trust::inspect_from`; true: installed, so the uninstaller too).
    pub inspect: Fetcher<bool, Local>,
    /// The install check's online half, on its worker: the release list at a path on the site,
    /// waited for at most `release.wait`. Only `main` hands in the real one (the exe's
    /// `net::fetch_release_list`, in no test build); the tests hand in fakes.
    pub fetch: Fetcher<str, Fetched>,
    /// What the check holds the list to: the app, its version, the list's key, the code signer.
    pub release: Release,
}

/// A blocking call the check's worker makes.
pub type Fetcher<A, R> = Arc<dyn Fn(&A) -> R + Send + Sync>;

impl Services {
    /// The real world; `logs` is the ISP logs' folder. `fetch` is the release-list fetcher:
    /// `main` hands in the exe's `net::fetch_release_list`, and is the only place that names it.
    pub fn system(logs: PathBuf, fetch: Fetcher<str, Fetched>) -> Services {
        // The exe's identity as this process started from it, taken now, before an install
        // could replace it, and handed to every check (FED3, RVD7).
        let started = crate::trust::exe_identity();
        Services {
            net: Arc::new(crate::icmp::Icmp),
            lookup: Arc::new(resolve::System),
            manual: false,
            copy: Box::new(|t| crate::host::copy_text(t).is_ok()),
            save_as: Box::new(crate::host::save_dialog),
            reveal: Box::new(|p| {
                let _ = crate::host::reveal(p, true);
            }),
            now: Box::new(WallClock::now),
            csv_format: Box::new(crate::host::csv_format),
            clock: Arc::new(crate::host::unix_now),
            local: Arc::new(crate::host::local_time),
            logs,
            dns: Arc::new(crate::dnscheck::SystemDns),
            tray: Box::new(tray::SystemTray::default()),
            quit: Box::new(|| {
                let _ = slint::quit_event_loop();
            }),
            // The shell can take a moment: never on the window's thread.
            open_url: Box::new(|u| {
                let u = u.to_string();
                std::thread::spawn(move || {
                    let _ = crate::host::open_url(&u);
                });
            }),
            inspect: Arc::new(move |installed: &bool| crate::trust::inspect_from(started, &crate::trust::own_exe(), *installed)),
            fetch,
            release: Release::this(),
        }
    }
}

/// How often the window looks whether a running check has its answer.
const CHECK_POLL_MS: u64 = 50;

/// `fetch` on a thread of its own, waited for at most `deadline` (FETCH_DEADLINE, review RAB-3):
/// past it the answer is `TimedOut`, whatever the site or a proxy is doing, and the thread is
/// left to end by itself (the real fetcher's read loop stops at the same deadline, and WinHTTP's
/// own timeouts bound each step); its late answer goes nowhere.
fn fetch_within(fetch: Fetcher<str, Fetched>, path: String, deadline: Duration) -> Fetched {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let _ = tx.send(fetch(&path));
    });
    match rx.recv_timeout(deadline) {
        Ok(f) => f,
        Err(RecvTimeoutError::Timeout) => Fetched::TimedOut,
        Err(RecvTimeoutError::Disconnected) => Fetched::Failed("the fetch stopped before it answered".into()),
    }
}

type Pending = Arc<Mutex<Option<Result<IpAddr, String>>>>;
/// One change to the prefs, applied by the prefs thread onto the newest saved ones.
type PrefsChange = Change<Prefs>;

/// After a change, when the window looks whether the prefs thread met a garbled file.
const PREFS_TELL_MS: u64 = 500;

/// The thread that saves prefs changes, in order: the store keeps each until it is written, and
/// puts every unwritten one onto the file as read right before the write (another instance's
/// changes included), onto this window's own when the file is garbled or missing, and writes
/// nothing while the file cannot be read. Reading prefs.json is the disk too: never on the
/// window's thread (a profile on a dead share froze it).
fn prefs_writer(store: Store<Prefs>, pending: Arc<AtomicUsize>) -> Sender<PrefsChange> {
    let (tx, rx) = channel::<PrefsChange>();
    std::thread::spawn(move || {
        while let Ok(f) = rx.recv() {
            store.change(Arc::new(move |p: &mut Prefs| {
                *p = std::mem::take(p).sanitized();
                f(p);
            }));
            pending.fetch_sub(1, Ordering::SeqCst);
        }
    });
    tx
}
/// Where to save a report and as what: the system's dialog, from a suggested file name and the
/// types it offers.
pub type SaveAs = Box<dyn Fn(&str, SaveOffer) -> Option<(PathBuf, SaveKind)>>;

/// The ISP log of the running trace (SPEC §9).
struct LogRun {
    /// Its number: the DNS checks' answers carry it.
    run: u64,
    path: PathBuf,
    ipv6: bool,
    /// When it began (UTC ms).
    since_unix: u64,
    /// Session time the next DNS checks are due.
    next_dns_ms: u64,
}

/// A path MTU probe of the trace (a new trace drops it: it belongs to its trace alone).
struct MtuState {
    run: MtuRun,
    /// Its answer was said (a toast).
    told: bool,
}

/// A DNS check's answer: the log run, which resolver, what it gave.
type DnsAnswer = (u64, Which, Check);

#[derive(Default)]
struct State {
    prefs: Prefs,
    session: Option<Session>,
    /// What is traced: the host as typed (cleaned) and its address.
    current: Option<(String, IpAddr)>,
    /// The target field's text as last traced: Escape in the field puts it back.
    committed: String,
    /// A forward lookup under way: the host and where its answer lands.
    resolving: Option<(String, Pending)>,
    /// The selected hop (its index, TTL - 1); none: the detail shows the destination.
    selected: Option<usize>,
    /// Session time the trace was stopped at (elapsed stops there).
    stopped_ms: Option<u64>,
    linger: u32,
    /// The last view built (selection, keys and reports read it).
    path: PathView,
    toast_seq: i32,
    toast_paths: HashMap<i32, PathBuf>,
    /// Each toast's timer generation (only the newest timer counts) and its full time in ms.
    toast_time: HashMap<i32, (u64, u64)>,
    scroll_seq: i32,
    /// Polls since failed lookups were last asked again.
    retry_polls: u32,
    /// A message the status line shows instead of the trace's own line (an error).
    note: Option<(String, bool)>,
    log: Option<LogRun>,
    /// The ISP log was asked for before its trace began (the button with nothing running, or a
    /// restart of a logged trace).
    log_wanted: bool,
    log_seq: u64,
    /// The targets this window has logged (host, IPv6): Save report offers the ISP report.
    logged: Vec<(String, bool)>,
    /// The window is hidden in the tray, and what the icon shows.
    in_tray: bool,
    tray_shown: Option<(tray::State, String)>,
    mtu: Option<MtuState>,
    report_seq: u64,
    /// An ISP report is being written (the window keeps looking until it is done).
    report_pending: bool,
    /// The log file's problem spells told so far, and the one now (for the status line).
    log_spell_told: u64,
    log_problem: Option<String>,
    /// The install check: its number (an answer for another one does nothing), and while it
    /// runs, where its answer comes from.
    check_seq: u64,
    check_rx: Option<Receiver<(u64, Rows)>>,
}

pub struct App {
    ui: Weak<AppWindow>,
    svc: Services,
    store: Store<Prefs>,
    resolver: Resolver,
    st: RefCell<State>,
    prefs_tx: Sender<PrefsChange>,
    /// Changes sent to the prefs thread and not yet handed to the store.
    prefs_pending: Arc<AtomicUsize>,
    rows: Rc<VecModel<HopRow>>,
    responders: Rc<VecModel<ResponderRow>>,
    events: Rc<VecModel<EventRow>>,
    recent: Rc<VecModel<SharedString>>,
    toasts: Rc<VecModel<ToastItem>>,
    check_rows: Rc<VecModel<CheckRow>>,
    check_timer: Timer,
    timer: Timer,
    /// The detail chart's plot size in pixels (reported by the window).
    chart: Cell<(f32, f32)>,
    me: RefCell<std::rc::Weak<App>>,
    /// The ISP log's writer (its own thread).
    writer: LogWriter,
    dns_slot: Arc<Mutex<Vec<DnsAnswer>>>,
    /// A check per resolver at a time.
    dns_busy: [Arc<AtomicBool>; 2],
    /// A report's or an ISP report's answer: its number and where it was saved, or why not.
    report_slot: Arc<Mutex<Option<ReportAnswer>>>,
}

/// A report's number, what it is ("report", "ISP report"), and where it was saved, or why not.
type ReportAnswer = (u64, &'static str, Result<PathBuf, String>);

fn key_is(text: &str, k: Key) -> bool {
    let c: char = k.into();
    text.chars().eq(std::iter::once(c))
}

fn s(t: impl AsRef<str>) -> SharedString {
    t.as_ref().into()
}

impl App {
    /// Wire the controller to a window made by `crate::window`.
    pub fn attach(ui: &AppWindow, store: Store<Prefs>, svc: Services) -> Rc<App> {
        let prefs = store.load().sanitized();
        let resolver = Resolver::new(svc.lookup.clone(), svc.manual);
        let prefs_pending = Arc::new(AtomicUsize::new(0));
        let prefs_tx = prefs_writer(store.clone(), prefs_pending.clone());
        let writer = LogWriter::new(svc.manual, svc.clock.clone());
        let app = Rc::new(App {
            ui: ui.as_weak(),
            svc,
            store,
            resolver,
            st: RefCell::new(State { prefs, ..State::default() }),
            prefs_tx,
            prefs_pending,
            rows: Rc::new(VecModel::default()),
            responders: Rc::new(VecModel::default()),
            events: Rc::new(VecModel::default()),
            recent: Rc::new(VecModel::default()),
            toasts: Rc::new(VecModel::default()),
            check_rows: Rc::new(VecModel::default()),
            check_timer: Timer::default(),
            timer: Timer::default(),
            chart: Cell::new((0.0, 0.0)),
            me: RefCell::new(std::rc::Weak::new()),
            writer,
            dns_slot: Arc::new(Mutex::new(Vec::new())),
            dns_busy: [Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false))],
            report_slot: Arc::new(Mutex::new(None)),
        });
        *app.me.borrow_mut() = Rc::downgrade(&app);
        ui.set_rows(ModelRc::from(app.rows.clone()));
        ui.set_responders(ModelRc::from(app.responders.clone()));
        ui.set_events(ModelRc::from(app.events.clone()));
        ui.set_recent(ModelRc::from(app.recent.clone()));
        ui.set_toasts(ModelRc::from(app.toasts.clone()));
        ui.set_check_rows(ModelRc::from(app.check_rows.clone()));
        app.show_rows(&Rows::idle());
        // About's version line. VibeTrace has no portable mode: it is always installed.
        let bits = if cfg!(target_pointer_width = "64") { "64-bit" } else { "32-bit" };
        ui.set_about_line(s(format!("version {} · {bits} · installed for you", crate::VERSION)));
        app.wire(ui);
        // Windows ending the session (a restart for updates with the window on the desktop,
        // or in the tray): the log's last minute and an open outage's "still out" first.
        let w = Rc::downgrade(&app);
        app.svc.tray.on_session_end(Rc::new(move || {
            if let Some(a) = w.upgrade() {
                a.quit();
            }
        }));
        app.show_prefs();
        app.rebuild();
        if app.store.broken() {
            app.toast("prefs.json could not be read: the settings are back to their defaults, and the old file will be kept as prefs.json.broken.", ToastKind::Error, None);
        }
        ui.invoke_focus_target();
        app
    }

    fn wire(self: &Rc<Self>, ui: &AppWindow) {
        macro_rules! on {
            ($setter:ident, |$a:ident $(, $arg:ident)*| $body:expr) => {{
                let w = Rc::downgrade(self);
                ui.$setter(move |$($arg),*| {
                    let Some($a) = w.upgrade() else { return Default::default() };
                    $body
                });
            }};
        }
        on!(on_trace_clicked, |a| a.trace_clicked());
        on!(on_target_accepted, |a| {
            let text = a.ui().map(|u| u.get_target().to_string()).unwrap_or_default();
            a.start(&text)
        });
        on!(on_target_edited, |a, _t| a.target_edited());
        on!(on_target_escaped, |a| a.target_escaped());
        on!(on_family_picked, |a, i| a.family_picked(i));
        on!(on_recent_picked, |a, i| a.recent_picked(i));
        on!(on_reset, |a| a.reset());
        on!(on_copy_report, |a| a.copy_report(false));
        on!(on_save_report, |a| a.save_report());
        on!(on_option, |a, k, v| a.option(k, v));
        on!(on_row_clicked, |a, i| a.row_clicked(i));
        on!(on_row_opened, |a, i| a.row_opened(i));
        on!(on_key, |a, t, c, sh| a.key(&t, c, sh));
        on!(on_chart_resized, |a, w, h| a.chart_resized(w, h));
        on!(on_toggle_theme, |a| a.toggle_theme());
        on!(on_copy_text, |a, t| (a.svc.copy)(&t));
        on!(on_toast_dismissed, |a, id| a.drop_toast(id));
        on!(on_toast_action, |a, id| a.toast_action(id));
        on!(on_dialogs_closed, |a| a.dialogs_closed());
        on!(on_check_install, |a| a.check_install());
        on!(on_open_site, |a| (a.svc.open_url)(crate::check::SITE));
        on!(on_toggle_log, |a| a.toggle_log());
        on!(on_toggle_mtu, |a| a.toggle_mtu());
    }

    fn ui(&self) -> Option<AppWindow> {
        self.ui.upgrade()
    }

    /// One change to the prefs: at once in memory (this window's own choices), and by the prefs
    /// thread onto the newest saved ones, which may hold another instance's changes (its recent
    /// targets, its theme). A file found garbled on the way is told shortly after.
    fn save_prefs(&self, change: impl Fn(&mut Prefs) + Send + Sync + 'static) {
        let f: PrefsChange = Arc::new(change);
        f(&mut self.st.borrow_mut().prefs);
        self.prefs_pending.fetch_add(1, Ordering::SeqCst);
        if self.prefs_tx.send(f).is_err() {
            self.prefs_pending.fetch_sub(1, Ordering::SeqCst);
        }
        let w = self.me.borrow().clone();
        Timer::single_shot(Duration::from_millis(PREFS_TELL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.tell_garbled();
            }
        });
    }

    /// prefs.json turned garbled while the window was open: said once, after it was kept aside
    /// and this window's prefs written in its place.
    fn tell_garbled(&self) {
        if self.store.take_garbled() {
            self.toast("prefs.json was damaged: it is kept as prefs.json.broken, and this window's settings are saved in its place.", ToastKind::Error, None);
        }
    }

    /// At exit (and in tests): let the prefs thread hand its last change to the store (at most
    /// two seconds), then write what is unwritten onto the file as it is now. A file that still
    /// cannot be read gets nothing (the change is lost, the other instance's prefs are not).
    ///
    /// The last write runs on a thread of its own, waited for at most two seconds: a prefs file
    /// on a share that stopped answering never holds the window's thread for good (VibePing
    /// PING-8, review X15CON-4). A prefs thread still busy after its two seconds is not waited
    /// for: at exit the process ends it, and the changes it had not written are lost, unsaid.
    pub fn finish_prefs(&self) {
        let start = Instant::now();
        let limit = Duration::from_secs(2);
        while self.prefs_pending.load(Ordering::SeqCst) > 0 && start.elapsed() < limit {
            std::thread::sleep(Duration::from_millis(2));
        }
        if self.prefs_pending.load(Ordering::SeqCst) > 0 {
            return;
        }
        let store = self.store.clone();
        let (tx, rx) = channel::<()>();
        std::thread::spawn(move || {
            store.flush();
            let _ = tx.send(());
        });
        let _ = rx.recv_timeout(limit);
    }

    /// The remembered choices onto the bar and the options popup.
    fn show_prefs(&self) {
        let Some(ui) = self.ui() else { return };
        let p = self.st.borrow().prefs.clone();
        ui.set_family(p.family().index());
        ui.set_opt_interval(INTERVALS_MS.iter().position(|v| *v == p.interval_ms).unwrap_or(1) as i32);
        ui.set_opt_size(SIZES.iter().position(|v| *v == p.size).unwrap_or(0) as i32);
        ui.set_opt_hops(MAX_HOPS.iter().position(|v| *v == p.max_hops).unwrap_or(1) as i32);
        ui.set_opt_names(p.names);
        ui.set_opt_asn(p.asn);
        self.recent.set_vec(p.recent.iter().map(s).collect::<Vec<_>>());
    }

    // ---------- starting and stopping ----------

    pub fn running(&self) -> bool {
        let st = self.st.borrow();
        st.resolving.is_some() || st.session.as_ref().is_some_and(|s| !s.stopped())
    }

    fn trace_clicked(&self) {
        if self.running() {
            self.stop();
        } else {
            let text = self.ui().map(|u| u.get_target().to_string()).unwrap_or_default();
            self.start(&text);
        }
    }

    /// Trace what the user typed (or the command line named).
    pub fn start(&self, text: &str) {
        self.start_with(text, false);
    }

    /// Trace `text`, with the ISP log on from the start when `log`.
    fn start_with(&self, text: &str, log: bool) {
        let host = match resolve::clean_target(text) {
            Ok(h) => h,
            Err(e) => {
                if let Some(ui) = self.ui() {
                    ui.set_target_invalid(true);
                }
                self.toast(&e, ToastKind::Error, None);
                return;
            }
        };
        self.stop_quietly();
        let family = {
            let mut st = self.st.borrow_mut();
            st.note = None;
            st.committed = text.trim().to_string();
            st.log_wanted = log;
            st.prefs.family()
        };
        let h = host.clone();
        self.save_prefs(move |p| p.remember(&h));
        self.show_prefs();
        if let Some(ui) = self.ui() {
            ui.set_target_invalid(false);
            if ui.get_target().trim() != text.trim() || ui.get_target().is_empty() {
                ui.set_target(s(text.trim()));
            }
        }
        if self.svc.manual {
            let r = self.svc.lookup.resolve(&host, family);
            self.resolved(&host, r);
            return;
        }
        let slot: Pending = Arc::new(Mutex::new(None));
        let (out, lookup, h) = (slot.clone(), self.svc.lookup.clone(), host.clone());
        std::thread::spawn(move || {
            let r = lookup.resolve(&h, family);
            *out.lock().unwrap() = Some(r);
        });
        self.st.borrow_mut().resolving = Some((host, slot));
        self.run_timer();
        self.rebuild();
    }

    fn resolved(&self, host: &str, r: Result<IpAddr, String>) {
        self.st.borrow_mut().resolving = None;
        match r {
            Ok(ip) => self.begin(host, ip),
            Err(e) => {
                if let Some(ui) = self.ui() {
                    ui.set_target_invalid(true);
                }
                let mut st = self.st.borrow_mut();
                st.note = Some((e.clone(), true));
                st.log_wanted = false; // nothing to log: the button is off again
                drop(st);
                self.toast(&e, ToastKind::Error, None);
                self.rebuild();
            }
        }
    }

    /// A fresh trace of `ip` (named `host`) with the current options.
    fn begin(&self, host: &str, ip: IpAddr) {
        let opts = self.st.borrow().prefs.opts();
        let mut trace = Trace::new(ip, host, opts, (self.svc.now)());
        trace.started_unix = (self.svc.clock)();
        let started = if self.svc.manual { Session::manual(&*self.svc.net, trace) } else { Session::start(&*self.svc.net, trace) };
        let ok = started.is_ok();
        match started {
            Ok(session) => {
                let mut st = self.st.borrow_mut();
                st.session = Some(session);
                st.mtu = None; // a probe of another trace says nothing about this one
                st.current = Some((host.to_string(), ip));
                st.selected = None;
                st.stopped_ms = None;
                st.note = None;
                st.retry_polls = 0; // the retry interval starts with the trace
            }
            Err(e) => {
                let mut st = self.st.borrow_mut();
                st.note = Some((e.clone(), true));
                st.log_wanted = false;
                drop(st);
                self.toast(&e, ToastKind::Error, None);
            }
        }
        if ok && self.st.borrow().log_wanted {
            self.start_log();
        }
        self.run_timer();
        self.rebuild();
    }

    /// Stop probing; what was measured stays on screen (and in the reports).
    pub fn stop(&self) {
        self.stop_quietly();
        self.rebuild();
    }

    fn stop_quietly(&self) {
        self.end_log();
        if let Some(m) = &self.st.borrow().mtu {
            m.run.stop();
        }
        let mut st = self.st.borrow_mut();
        st.resolving = None;
        if let Some(sess) = &st.session
            && !sess.stopped()
        {
            sess.stop();
            st.stopped_ms = Some(sess.now_ms());
        }
        st.linger = LINGER;
    }

    fn reset(&self) {
        {
            let st = self.st.borrow();
            let Some(sess) = st.session.as_ref().filter(|s| !s.stopped()) else { return };
            let now = sess.now_ms();
            sess.trace.lock().unwrap().reset(now);
        }
        self.rebuild();
    }

    /// Restart the running trace (a new interval, size or hop limit): stats start over. A
    /// lookup still under way just goes on (its trace starts with the new options).
    fn restart(&self) {
        let current = {
            let st = self.st.borrow();
            if st.resolving.is_some() || !st.session.as_ref().is_some_and(|s| !s.stopped()) {
                return;
            }
            st.current.clone()
        };
        if let Some((host, ip)) = current {
            // A logged trace keeps logging: a new run in the same log.
            let logging = self.st.borrow().log.is_some();
            self.stop_quietly();
            self.st.borrow_mut().log_wanted = logging;
            self.begin(&host, ip);
        }
    }

    /// Tests: run `rounds` rounds of a manual session (then let the timer pick them up).
    pub fn step(&self, rounds: u32) {
        if let Some(sess) = &self.st.borrow().session {
            sess.step(rounds);
        }
    }

    fn run_timer(&self) {
        if self.timer.running() {
            return;
        }
        let w = self.me.borrow().clone();
        self.timer.start(TimerMode::Repeated, Duration::from_millis(POLL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.poll();
            }
        });
    }

    /// The timer's work: a finished lookup starts its trace; a changed trace is redrawn.
    pub fn poll(&self) {
        let done = {
            let st = self.st.borrow();
            st.resolving.as_ref().and_then(|(h, slot)| slot.lock().unwrap().take().map(|r| (h.clone(), r)))
        };
        if let Some((host, r)) = done {
            self.resolved(&host, r);
        }
        // A probe that cannot be sent from this computer stops the trace.
        let fatal = {
            let st = self.st.borrow();
            st.session.as_ref().filter(|s| !s.stopped()).and_then(|s| s.trace.lock().unwrap().fatal.clone())
        };
        if let Some(f) = fatal {
            self.stop_quietly();
            self.st.borrow_mut().note = Some((f.clone(), true));
            self.toast(&f, ToastKind::Error, None);
        }
        // A lookup that could not be answered is asked again now and then, never kept as "none".
        let retry = {
            let mut st = self.st.borrow_mut();
            st.retry_polls += 1;
            (st.retry_polls >= RETRY_POLLS).then(|| {
                st.retry_polls = 0;
                (st.prefs.names, st.prefs.asn)
            })
        };
        if let Some((names, asn)) = retry {
            self.resolver.retry_failed(names, asn);
        }
        self.log_tick();
        self.disk_tick();
        self.report_tick();
        self.mtu_tick();
        self.tray_tick();
        self.rebuild();
        let idle = {
            let mut st = self.st.borrow_mut();
            let running = st.resolving.is_some() || st.session.as_ref().is_some_and(|s| !s.stopped());
            let busy = st.mtu.as_ref().is_some_and(|m| !m.told) || st.in_tray || st.report_pending;
            if !running && !busy {
                st.linger = st.linger.saturating_sub(1);
            }
            !running && !busy && st.linger == 0
        };
        if idle {
            self.timer.stop();
        }
    }

    // ---------- the bar ----------

    fn target_edited(&self) {
        if let Some(ui) = self.ui() {
            ui.set_target_invalid(false);
        }
    }

    /// Escape in the target field: what was typed since the last trace goes, the traced target
    /// comes back, and the key goes no further. With nothing to put back it goes on (it stops).
    fn target_escaped(&self) -> bool {
        let Some(ui) = self.ui() else { return false };
        let committed = self.st.borrow().committed.clone();
        // Spaces round the host are not a change (`start` traces it trimmed).
        if ui.get_target().trim() == committed {
            return false;
        }
        ui.set_target(s(&committed));
        ui.set_target_invalid(false);
        true
    }

    fn family_picked(&self, i: i32) {
        // The Segmented reports a click on the selected tab too.
        if Family::from_index(i) == self.st.borrow().prefs.family() {
            return;
        }
        self.save_prefs(move |p| p.set_family(Family::from_index(i)));
        self.show_prefs();
        // A running trace (or lookup) follows: the name may have an address of the other family.
        let host = {
            let st = self.st.borrow();
            match &st.resolving {
                Some((h, _)) => Some(h.clone()),
                None if st.session.as_ref().is_some_and(|s| !s.stopped()) => st.current.clone().map(|c| c.0),
                None => None,
            }
        };
        if let Some(h) = host {
            self.start(&h);
        }
    }

    fn recent_picked(&self, i: i32) {
        let Some(t) = self.st.borrow().prefs.recent.get(i as usize).cloned() else { return };
        if let Some(ui) = self.ui() {
            ui.set_target(s(&t));
        }
        self.start(&t);
    }

    fn option(&self, kind: i32, value: i32) {
        let v = value.max(0) as usize;
        let probes = |p: &Prefs| (p.interval_ms, p.size, p.max_hops);
        let before = probes(&self.st.borrow().prefs);
        self.save_prefs(move |p| match kind {
            0 => p.interval_ms = INTERVALS_MS[v.min(INTERVALS_MS.len() - 1)],
            1 => p.size = SIZES[v.min(SIZES.len() - 1)],
            2 => p.max_hops = MAX_HOPS[v.min(MAX_HOPS.len() - 1)],
            3 => p.names = value != 0,
            _ => p.asn = value != 0,
        });
        let restart = probes(&self.st.borrow().prefs) != before;
        self.show_prefs();
        if restart {
            self.restart();
        } else {
            self.ask_names_for_all();
        }
        // Also when nothing runs (restart does nothing then): the idle status line names them.
        self.rebuild();
    }

    fn toggle_theme(&self) {
        let Some(ui) = self.ui() else { return };
        let theme = ui.global::<Theme>();
        let dark = !theme.get_dark();
        theme.set_dark(dark);
        self.save_prefs(move |p| p.theme = Some(if dark { "dark" } else { "light" }.into()));
    }

    /// Lookups for every responder seen (names or AS lookups just switched on).
    fn ask_names_for_all(&self) {
        let (names, asn) = {
            let st = self.st.borrow();
            (st.prefs.names, st.prefs.asn)
        };
        let addrs: Vec<IpAddr> = {
            let st = self.st.borrow();
            let Some(sess) = &st.session else { return };
            let t = sess.trace.lock().unwrap();
            t.hops.iter().flat_map(|h| h.responders.list.iter().map(|r| r.addr)).collect()
        };
        for a in addrs {
            self.resolver.want(a, names, asn);
        }
    }

    // ---------- the table and the keys ----------

    fn row_clicked(&self, i: i32) {
        {
            let mut st = self.st.borrow_mut();
            let Ok(i) = usize::try_from(i) else { return };
            st.selected = if st.selected == Some(i) { None } else { Some(i) };
        }
        self.rebuild();
    }

    /// A double-click: the row ends selected (its second click toggled it off again).
    fn row_opened(&self, i: i32) {
        let Ok(i) = usize::try_from(i) else { return };
        self.st.borrow_mut().selected = Some(i);
        self.rebuild();
    }

    fn key(&self, text: &str, ctrl: bool, _shift: bool) -> bool {
        if key_is(text, Key::UpArrow) || key_is(text, Key::DownArrow) {
            let down = key_is(text, Key::DownArrow);
            {
                let mut st = self.st.borrow_mut();
                let n = st.path.hops.len();
                if n == 0 {
                    return false;
                }
                st.selected = Some(match st.selected {
                    None if down => 0,
                    None => n - 1,
                    Some(i) if down => (i + 1).min(n - 1),
                    Some(i) => i.saturating_sub(1),
                });
                st.scroll_seq += 1;
            }
            self.rebuild();
            return true;
        }
        if key_is(text, Key::Escape) {
            if self.running() {
                self.stop();
                return true;
            }
            if self.st.borrow().selected.is_some() {
                self.st.borrow_mut().selected = None;
                self.rebuild();
                return true;
            }
            return false;
        }
        if ctrl && text.eq_ignore_ascii_case("c") {
            return self.has_trace() && self.copy_report(true);
        }
        if ctrl && text.eq_ignore_ascii_case("r") {
            if self.running() {
                self.reset();
                return true;
            }
            return false;
        }
        if ctrl && text.eq_ignore_ascii_case("l") {
            self.toggle_log();
            return true;
        }
        false
    }

    fn chart_resized(&self, w: f32, h: f32) {
        let new = (w.round(), h.round());
        if self.chart.get() != new {
            self.chart.set(new);
            if self.st.try_borrow_mut().is_ok() {
                self.rebuild();
            }
        }
    }

    // ---------- reports ----------

    fn has_trace(&self) -> bool {
        self.st.borrow().session.is_some()
    }

    /// The report as text or CSV, or None before the first trace.
    pub fn report(&self, csv: bool) -> Option<String> {
        // Responders that appeared since the last redraw are asked first, so the report counts
        // them as not answered yet, not as never looked up (RF4-6).
        self.feed_resolver();
        let st = self.st.borrow();
        let sess = st.session.as_ref()?;
        let ran = st.stopped_ms.unwrap_or_else(|| sess.now_ms());
        let t = sess.trace.lock().unwrap();
        let known = self.resolver.known.lock().unwrap();
        let path = view::path(&t, &known, st.prefs.names);
        let mtu = st.mtu.as_ref().map(|m| m.run.state.lock().unwrap().clone());
        let c = Context { trace: &t, path: &path, known: &known, names: st.prefs.names, asn: st.prefs.asn, ran_ms: ran.saturating_sub(t.origin_ms), mtu: mtu.as_ref() };
        Some(if csv { report::csv(&c, &(self.svc.csv_format)()) } else { report::text(&c) })
    }

    /// Copy the text report. From the keyboard a toast says so (the button shows its check).
    fn copy_report(&self, say: bool) -> bool {
        let Some(text) = self.report(false) else { return false };
        let ok = (self.svc.copy)(&text);
        if !ok {
            self.toast("Could not copy the report: the clipboard is busy.", ToastKind::Error, None);
        } else if say {
            self.toast("Report copied.", ToastKind::Ok, None);
        }
        ok
    }

    fn save_report(&self) {
        let (name, offer) = {
            let st = self.st.borrow();
            let Some(sess) = &st.session else { return };
            let t = sess.trace.lock().unwrap();
            let w = t.started;
            let host: String = t.name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' }).collect();
            let offer = SaveOffer { isp: st.logged.contains(&(t.name.clone(), t.target.is_ipv6())), isp_first: st.log.is_some() };
            let what = if offer.isp_first { "VibeTrace ISP log" } else { "VibeTrace" };
            (format!("{what} {host} {:04}-{:02}-{:02} {:02}{:02}.txt", w.year, w.month, w.day, w.hour, w.minute), offer)
        };
        let Some((path, kind)) = (self.svc.save_as)(&name, offer) else { return };
        if matches!(kind, SaveKind::IspText | SaveKind::IspCsv) {
            if offer.isp {
                self.isp_report(path, kind == SaveKind::IspCsv);
            }
            return;
        }
        let csv = kind == SaveKind::Csv;
        let Some(body) = self.report(csv) else { return };
        let body = if csv { body } else { crate::host::clipboard_text(&body) };
        // Written on the writer's thread, as the ISP report (X15CON-6): a drive that went away
        // keeps that thread waiting, never the window; said from the tick.
        let seq = {
            let mut st = self.st.borrow_mut();
            st.report_seq += 1;
            st.report_pending = true;
            st.report_seq
        };
        let slot = self.report_slot.clone();
        self.writer.run(move |_| {
            let r = write_atomic(&path, body.as_bytes()).map(|_| path.clone()).map_err(|e| e.to_string());
            *slot.lock().unwrap() = Some((seq, "report", r));
        });
        self.run_timer();
        self.report_tick();
    }

    // ---------- the ISP log ----------

    /// The ISP log button (and Ctrl+L): on for the running trace (no restart), off again; with
    /// nothing running it traces the field's target with the log on.
    fn toggle_log(&self) {
        if self.st.borrow().log.is_some() {
            self.end_log();
            self.rebuild();
            return;
        }
        let (tracing, resolving) = {
            let st = self.st.borrow();
            (st.resolving.is_none() && st.session.as_ref().is_some_and(|s| !s.stopped()), st.resolving.is_some())
        };
        if tracing {
            self.start_log();
            self.run_timer();
            self.rebuild();
        } else if resolving {
            let mut st = self.st.borrow_mut();
            st.log_wanted = !st.log_wanted;
            drop(st);
            self.rebuild();
        } else {
            let text = self.ui().map(|u| u.get_target().to_string()).unwrap_or_default();
            self.start_with(&text, true);
        }
    }

    pub fn logging(&self) -> bool {
        self.st.borrow().log.is_some()
    }

    /// Logging begins for the running trace: a run record, the DNS checks due at once.
    fn start_log(&self) {
        let mut st = self.st.borrow_mut();
        st.log_wanted = false;
        let Some((host, ip)) = st.current.clone() else { return };
        let Some((now, trace)) = st.session.as_ref().filter(|s| !s.stopped()).map(|s| (s.now_ms(), s.trace.clone())) else { return };
        st.log_seq += 1;
        let run = st.log_seq;
        let at = (self.svc.clock)();
        let opts = {
            let mut t = trace.lock().unwrap();
            // The wall clock is only followed while logging: a sleep while tracing un-logged
            // left the anchor stale. Follow it now, before the log begins, so an outage already
            // under way is dated from the log's real start (NET3-1).
            if at > t.unix(now) + CLOCK_STEP_MS {
                t.reanchor(now, at);
            }
            t.start_log(run, now);
            t.opts
        };
        let path = self.svc.logs.join(logfile::file_name(&host, ip.is_ipv6()));
        let rec = RunRec {
            v: crate::isplog::LOG_VERSION,
            at,
            target: host.clone(),
            addr: ip,
            interval_ms: opts.interval_ms,
            size: opts.size,
            timeout_ms: opts.timeout_ms,
            max_hops: opts.max_hops,
            version: crate::VERSION.into(),
            via: None,
        };
        st.log = Some(LogRun { run, path: path.clone(), ipv6: ip.is_ipv6(), since_unix: at, next_dns_ms: now });
        let key = (host, ip.is_ipv6());
        if !st.logged.contains(&key) {
            st.logged.push(key);
        }
        drop(st);
        // The interface the trace leaves through (R-4) is read on the log's thread (an IP
        // helper call: never on the window's), right before the record goes out, in order.
        let net = self.svc.net.clone();
        self.writer.run(move |disk| {
            let rec = Record::Run(RunRec { via: net.via(ip), ..rec });
            disk.write(&path, vec![rec.line()]);
        });
    }

    /// The log ends (switched off, a stop, another target): what it holds is written, an
    /// outage still open as "still out when the log stopped".
    fn end_log(&self) {
        let Some(lr) = self.st.borrow_mut().log.take() else { return };
        let lines = {
            let st = self.st.borrow();
            match &st.session {
                Some(sess) => {
                    let now = st.stopped_ms.unwrap_or_else(|| sess.now_ms());
                    let mut t = sess.trace.lock().unwrap();
                    t.end_log();
                    let lines = self.log_lines(&mut t, now, true, None);
                    t.log = None;
                    lines
                }
                None => Vec::new(),
            }
        };
        self.writer.write(lr.path, lines);
        if self.st.borrow().in_tray {
            self.restore();
        }
    }

    /// The log's new lines: the minutes complete at `now` (all of them with `all`) and the
    /// outages found or ended since the last look (with `open_note`, the open one too, so a
    /// report can say it is still on).
    fn log_lines(&self, t: &mut Trace, now: u64, all: bool, open_note: Option<&str>) -> Vec<String> {
        let mut out: Vec<String> = t.take_minutes(now, all).into_iter().map(|m| Record::Min(m).line()).collect();
        let mut changed = t.log.as_mut().map(|l| std::mem::take(&mut l.changed)).unwrap_or_default();
        let open = t.log.as_ref().and_then(|l| l.open);
        if let (Some(_), Some(id)) = (open_note, open) {
            changed.push(id);
        }
        if changed.is_empty() {
            return out;
        }
        let known = self.resolver.known.lock().unwrap();
        let mut seen = std::collections::HashSet::new();
        for id in changed.into_iter().filter(|id| seen.insert(*id)) {
            if let Some(o) = t.log.as_ref().and_then(|l| l.outage(id)) {
                let note = open_note.filter(|_| Some(id) == open && o.end_ms.is_none()).map(str::to_string);
                out.push(Record::Outage(outage_rec(t, o, &known, note)).line());
            }
        }
        out
    }

    /// While logging: the complete minutes and the outages to the log, the DNS checks when due
    /// and their answers into the minutes.
    fn log_tick(&self) {
        let (path, run, ipv6, due) = {
            let st = self.st.borrow();
            let (Some(lr), Some(sess)) = (&st.log, &st.session) else { return };
            (lr.path.clone(), lr.run, lr.ipv6, sess.now_ms() >= lr.next_dns_ms)
        };
        if due {
            self.dns_checks(run, ipv6);
        }
        let lines = {
            let st = self.st.borrow();
            let Some(sess) = &st.session else { return };
            let now = sess.now_ms();
            let mut t = sess.trace.lock().unwrap();
            // Times are the run's start plus the session's monotonic clock, which may not count
            // a sleep or hibernate: when the wall clock is ahead by more than a few seconds,
            // what comes after is dated by it (minutes already kept keep theirs; the hours
            // asleep show as a gap). A clock set back is not followed until the next run.
            let wall = (self.svc.clock)();
            if wall > t.unix(now) + CLOCK_STEP_MS {
                t.reanchor(now, wall);
            }
            // This run's answers (a check of an earlier run that comes late does nothing), in
            // the minute they came back: one that began late in a minute already written must
            // not make a second record of it.
            for (r, which, c) in std::mem::take(&mut *self.dns_slot.lock().unwrap()) {
                if r == run {
                    t.record_dns(which, now, &c);
                }
            }
            self.log_lines(&mut t, now, false, None)
        };
        self.writer.write(path, lines);
    }

    /// The two DNS checks, each on a worker (inline in the tests); one still running is not
    /// doubled.
    fn dns_checks(&self, run: u64, ipv6: bool) {
        {
            let mut st = self.st.borrow_mut();
            let Some(now) = st.session.as_ref().map(|s| s.now_ms()) else { return };
            let Some(lr) = st.log.as_mut() else { return };
            // Every 30 s; a poll that comes late does not make a burst of checks.
            lr.next_dns_ms += crate::isplog::DNS_EVERY_MS;
            if lr.next_dns_ms <= now {
                lr.next_dns_ms = now + crate::isplog::DNS_EVERY_MS;
            }
        }
        for which in [Which::System, Which::Public] {
            let busy = self.dns_busy[which as usize].clone();
            if busy.swap(true, Ordering::SeqCst) {
                continue;
            }
            let (dns, slot, done) = (self.svc.dns.clone(), self.dns_slot.clone(), busy.clone());
            let work = move || {
                let c = dns.check(which, ipv6);
                slot.lock().unwrap().push((run, which, c));
                done.store(false, Ordering::SeqCst);
            };
            if self.svc.manual {
                work();
            } else if std::thread::Builder::new().name("dns-check".into()).stack_size(256 * 1024).spawn(work).is_err() {
                busy.store(false, Ordering::SeqCst);
            }
        }
    }

    /// The log file's troubles: told once per spell, a garbled file once; the status line says
    /// it while it lasts.
    fn disk_tick(&self) {
        let (problem, spell, broken) = {
            let mut s = self.writer.status.lock().unwrap();
            (s.problem.clone(), s.spell, std::mem::take(&mut s.broken))
        };
        for p in broken {
            let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            self.toast(&format!("The ISP log {name} was damaged: it is kept as {name}.broken, and a new one is begun."), ToastKind::Error, None);
        }
        let tell = problem.clone().filter(|_| spell > self.st.borrow().log_spell_told);
        {
            let mut st = self.st.borrow_mut();
            st.log_spell_told = st.log_spell_told.max(spell);
            st.log_problem = problem;
        }
        if let Some(p) = tell {
            self.toast(&p, ToastKind::Error, None);
        }
    }


    /// At exit (and in tests): let the log's thread write what it was handed (3 s at most).
    pub fn finish_log(&self) {
        self.writer.sync(Duration::from_secs(3));
    }

    /// The ISP report (SPEC §9.6): everything up to now goes to the log first (the minute being
    /// filled too, an open outage as still on), then the log's thread reads the log, adds it up
    /// and writes the report: never the window's thread.
    fn isp_report(&self, out: PathBuf, csv: bool) {
        let (host, ipv6, lines, log_path) = {
            let st = self.st.borrow();
            let Some((host, ip)) = st.current.clone() else { return };
            let log_path = self.svc.logs.join(logfile::file_name(&host, ip.is_ipv6()));
            let mut lines = Vec::new();
            if let (Some(_), Some(sess)) = (&st.log, &st.session) {
                let now = sess.now_ms();
                let mut t = sess.trace.lock().unwrap();
                lines = self.log_lines(&mut t, now, true, Some("still out when this report was made"));
            }
            (host, ip.is_ipv6(), lines, log_path)
        };
        self.writer.write(log_path.clone(), lines);
        let seq = {
            let mut st = self.st.borrow_mut();
            st.report_seq += 1;
            st.report_pending = true;
            st.report_seq
        };
        let known = self.resolver.known.lock().unwrap().clone();
        let names = self.st.borrow().prefs.names;
        let (local, clock, slot) = (self.svc.local.clone(), self.svc.clock.clone(), self.report_slot.clone());
        let fmt = (self.svc.csv_format)();
        let dropped = self.writer.status.lock().unwrap().dropped;
        self.writer.run(move |disk| {
            let (lines, left_out) = disk.read_all(&log_path);
            let now = clock();
            let data = crate::ispreport::aggregate(lines.iter().map(String::as_str), now, &*local);
            let ctx = crate::ispreport::Ctx { target: &host, ipv6, known: &known, names, local: &*local, now, left_out, dropped };
            let body = if csv { crate::ispreport::csv(&data, &ctx, &fmt) } else { crate::host::clipboard_text(&crate::ispreport::text(&data, &ctx)) };
            let r = write_atomic(&out, body.as_bytes()).map(|_| out.clone()).map_err(|e| e.to_string());
            *slot.lock().unwrap() = Some((seq, "ISP report", r));
        });
        self.run_timer();
        self.report_tick();
    }

    /// A report or an ISP report written (or not): said, when it is the newest one asked for.
    fn report_tick(&self) {
        let done = self.report_slot.lock().unwrap().take();
        let Some((seq, what, r)) = done else { return };
        if seq != self.st.borrow().report_seq {
            return;
        }
        self.st.borrow_mut().report_pending = false;
        match r {
            Ok(p) => {
                let file = p.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
                self.toast(&format!("Saved {file}"), ToastKind::Ok, Some(p));
            }
            Err(e) => self.toast(&format!("Could not save the {what}: {e}"), ToastKind::Error, None),
        }
    }

    // ---------- the tray ----------

    /// What the tray icon shows: red for an outage now, amber while the system resolver fails.
    fn tray_look(&self) -> (tray::State, String) {
        let st = self.st.borrow();
        let host = st.current.as_ref().map(|c| c.0.clone()).unwrap_or_default();
        let (state, words) = match st.session.as_ref().map(|s| s.trace.lock().unwrap()) {
            Some(t) => {
                let known = self.resolver.known.lock().unwrap();
                match &t.log {
                    Some(l) if l.open.is_some() => (tray::State::Outage, log_words(&t, l, &known, &*self.svc.local).0),
                    Some(l) if l.dns[0].failing() => (tray::State::Dns, log_words(&t, l, &known, &*self.svc.local).0),
                    Some(l) => (tray::State::Logging, log_words(&t, l, &known, &*self.svc.local).0),
                    None => (tray::State::Logging, String::new()),
                }
            }
            None => (tray::State::Logging, String::new()),
        };
        let tip: String = resolve::clean_name(&format!("VibeTrace: logging {host} · {words}")).chars().take(120).collect();
        (state, tip)
    }

    /// Minimised while logging: the window goes to the tray (the trace and the log go on). The
    /// icon follows the log.
    fn tray_tick(&self) {
        let Some(ui) = self.ui() else { return };
        let (logging, in_tray) = {
            let st = self.st.borrow();
            (st.log.is_some(), st.in_tray)
        };
        let going = logging && !in_tray && ui.window().is_minimized();
        if !going && !in_tray {
            return;
        }
        let look = self.tray_look();
        if self.st.borrow().tray_shown.as_ref() == Some(&look) {
            return;
        }
        let w = self.me.borrow().clone();
        let shown = self.svc.tray.show(
            look.0,
            &look.1,
            Rc::new(move |e| {
                if let Some(a) = w.upgrade() {
                    a.on_tray(e);
                }
            }),
        );
        // Hidden only once the icon is there: a window hidden with no icon (no notification
        // area) could never be brought back. It stays minimised then.
        if going && shown {
            self.st.borrow_mut().in_tray = true;
            let _ = ui.hide();
        }
        if shown {
            self.st.borrow_mut().tray_shown = Some(look);
        }
    }

    /// A click on the tray icon or its menu.
    pub fn on_tray(&self, ev: tray::Event) {
        match ev {
            tray::Event::Open => self.restore(),
            tray::Event::Quit => self.quit(),
            tray::Event::Menu => {
                let entries = vec![(1, "Open VibeTrace".to_string()), (0, String::new()), (2, "Stop the log".to_string()), (0, String::new()), (3, "Quit".to_string())];
                match self.svc.tray.menu(&entries) {
                    Some(1) => self.restore(),
                    Some(2) => {
                        self.stop();
                        self.restore();
                    }
                    Some(3) => self.quit(),
                    _ => {}
                }
            }
        }
    }

    pub fn in_tray(&self) -> bool {
        self.st.borrow().in_tray
    }

    /// Back from the tray: the window shows again and the icon goes.
    fn restore(&self) {
        let was = std::mem::replace(&mut self.st.borrow_mut().in_tray, false);
        if !was {
            return;
        }
        self.st.borrow_mut().tray_shown = None;
        self.svc.tray.hide();
        if let Some(ui) = self.ui() {
            let _ = ui.show();
            ui.window().set_minimized(false);
        }
        self.rebuild();
    }

    /// Quit from the tray, or Windows ending the session (whatever is on screen): the log's
    /// last minute written, the icon gone, the event loop left.
    pub fn quit(&self) {
        self.st.borrow_mut().in_tray = false;
        self.svc.tray.hide();
        self.stop();
        // Windows ending the session may end the process as soon as this returns: the log's
        // last minute is on disk first.
        self.finish_log();
        (self.svc.quit)();
    }

    // ---------- path MTU ----------

    /// The path MTU button: a probe of the running trace's path, or stopped again.
    fn toggle_mtu(&self) {
        let running = self.st.borrow().mtu.as_ref().is_some_and(|m| m.run.running());
        if running {
            if let Some(m) = self.st.borrow_mut().mtu.as_mut() {
                m.run.stop();
                m.told = true;
            }
            self.toast("Path MTU stopped; what it found so far stays in the table.", ToastKind::Info, None);
            self.rebuild();
            return;
        }
        let made = {
            let st = self.st.borrow();
            let Some(sess) = st.session.as_ref().filter(|s| !s.stopped()) else { return };
            let t = sess.trace.lock().unwrap();
            let Some(r) = t.reference() else { return };
            let ipv6 = t.target.is_ipv6();
            let plan = Plan {
                ipv6,
                reference: r,
                dest: t.dest_hop() == Some(r),
                answers: t.hops[..=r].iter().map(Hop::answers).collect(),
                addrs: t.hops[..=r].iter().map(|h| h.responders.list.iter().map(|x| x.addr).collect()).collect(),
                link: None,
                cached: None,
                // Each hop's normal loss as the outage rule sees it: its newest outcomes,
                // outages left out (NET2-2), never the trace's lifetime with them in.
                loss: (0..=r).map(|k| mtu_loss(&t, k)).collect(),
            };
            let net = self.svc.net.clone();
            if self.svc.manual { MtuRun::manual(net, t.target, plan) } else { MtuRun::spawn(net, t.target, plan) }
        };
        match made {
            Ok(run) => self.st.borrow_mut().mtu = Some(MtuState { run, told: false }),
            Err(e) => self.toast(&e, ToastKind::Error, None),
        }
        self.run_timer();
        self.rebuild();
    }

    /// Tests: send `n` probes of a manual path MTU run now.
    pub fn mtu_steps(&self, n: u32) {
        if let Some(m) = &self.st.borrow().mtu {
            m.run.steps(n);
        }
    }

    /// A probe that finished says its answer once.
    fn mtu_tick(&self) {
        let said = {
            let mut st = self.st.borrow_mut();
            let host = st.current.as_ref().map(|c| c.0.clone()).unwrap_or_default();
            match st.mtu.as_mut() {
                Some(m) if !m.told && !m.run.running() => {
                    m.told = true;
                    let s = m.run.state.lock().unwrap();
                    Some((s.summary(&host), s.error.is_some()))
                }
                _ => None,
            }
        };
        if let Some((text, bad)) = said {
            self.toast(&text, if bad { ToastKind::Error } else { ToastKind::Ok }, None);
        }
    }

    // ---------- About's install check ----------

    /// "Check this install": one at a time, on a worker (it reads the files and may go online);
    /// the window looks for the answer every CHECK_POLL_MS meanwhile and goes on. Closing About
    /// leaves it running: the answer lands in the rows, which About shows when it opens again.
    fn check_install(&self) {
        let Some(ui) = self.ui() else { return };
        let seq = {
            let mut st = self.st.borrow_mut();
            if st.check_rx.is_some() {
                return;
            }
            st.check_seq += 1;
            st.check_seq
        };
        let (tx, rx) = channel();
        self.st.borrow_mut().check_rx = Some(rx);
        ui.set_checking(true);
        let (inspect, fetch, release) = (self.svc.inspect.clone(), self.svc.fetch.clone(), self.svc.release.clone());
        // VibeTrace has no portable mode: it is always installed, so the uninstaller is checked too.
        let installed = true;
        std::thread::spawn(move || {
            let local = inspect(&installed);
            // The exe updated or replaced under this one while it ran: nothing to compare (FED3).
            let rows = if local.replaced {
                crate::check::replaced_rows(&release, &local)
            } else {
                let fetched = fetch_within(fetch, crate::check::list_path(release.app), release.wait);
                crate::check::rows(&release, &local, fetched)
            };
            let _ = tx.send((seq, rows));
        });
        let w = self.me.borrow().clone();
        self.check_timer.start(TimerMode::Repeated, Duration::from_millis(CHECK_POLL_MS), move || {
            if let Some(a) = w.upgrade() {
                a.poll_check();
            }
        });
    }

    /// The check's answer, once it is there: the rows, and the button back.
    fn poll_check(&self) {
        let got = {
            let st = self.st.borrow();
            let Some(rx) = st.check_rx.as_ref() else { return };
            match rx.try_recv() {
                Ok((seq, rows)) => Some((seq == st.check_seq).then_some(rows)),
                Err(TryRecvError::Empty) => None,
                Err(TryRecvError::Disconnected) => Some(Some(Rows::stopped())),
            }
        };
        let Some(rows) = got else { return };
        self.check_timer.stop();
        self.st.borrow_mut().check_rx = None;
        if let Some(rows) = rows {
            self.show_rows(&rows);
        }
        if let Some(ui) = self.ui() {
            ui.set_checking(false);
            ui.set_checked(true);
        }
    }

    fn show_rows(&self, rows: &Rows) {
        let dot = |d: Dot| match d {
            Dot::Idle => CheckDot::Idle,
            Dot::Ok => CheckDot::Ok,
            Dot::Warn => CheckDot::Warn,
            Dot::Danger => CheckDot::Danger,
        };
        let all: Vec<CheckRow> = rows.all().iter().map(|(name, r)| CheckRow { name: s(name), text: s(&r.text), dot: dot(r.dot) }).collect();
        self.check_rows.set_vec(all);
    }

    // ---------- toasts ----------

    /// A toast; `main` shows one for files dropped on the exe (launch.rs).
    pub fn toast(&self, text: &str, kind: ToastKind, reveal: Option<PathBuf>) {
        let id = {
            let mut st = self.st.borrow_mut();
            st.toast_seq += 1;
            let id = st.toast_seq;
            if let Some(p) = reveal.clone() {
                st.toast_paths.insert(id, p);
            }
            id
        };
        // At most three on screen: the oldest goes.
        while self.toasts.row_count() >= 3 {
            let old = self.toasts.row_data(0).map(|t| t.id).unwrap_or(0);
            self.drop_toast(old);
        }
        self.toasts.push(ToastItem { id, text: s(text), kind, action: if reveal.is_some() { s("Show") } else { s("") } });
        self.arm_toast(id, if kind == ToastKind::Error { 10_000 } else { 5_000 });
    }

    /// A toast's timer, `ms` from now. Only its newest timer counts, and while About is open it
    /// waits: the toast is in sight but out of reach there (`dialogs_closed` gives it its full
    /// time again).
    fn arm_toast(&self, id: i32, ms: u64) {
        let generation = {
            let mut st = self.st.borrow_mut();
            let t = st.toast_time.entry(id).or_insert((0, ms));
            t.0 += 1;
            t.0
        };
        let w = self.me.borrow().clone();
        Timer::single_shot(Duration::from_millis(ms), move || {
            let Some(a) = w.upgrade() else { return };
            let current = a.st.borrow().toast_time.get(&id).is_some_and(|t| t.0 == generation);
            if current && !a.ui().is_some_and(|ui| ui.get_about_open()) {
                a.drop_toast(id);
            }
        });
    }

    /// About closed: every toast gets its full time again.
    fn dialogs_closed(&self) {
        let all: Vec<(i32, u64)> = self.st.borrow().toast_time.iter().map(|(id, t)| (*id, t.1)).collect();
        for (id, ms) in all {
            self.arm_toast(id, ms);
        }
    }

    fn drop_toast(&self, id: i32) {
        if let Some(i) = self.toasts.iter().position(|t| t.id == id) {
            self.toasts.remove(i);
        }
        self.st.borrow_mut().toast_time.remove(&id);
        self.st.borrow_mut().toast_paths.remove(&id);
    }

    fn toast_action(&self, id: i32) {
        let p = self.st.borrow().toast_paths.get(&id).cloned();
        if let Some(p) = p {
            (self.svc.reveal)(&p);
        }
        self.drop_toast(id);
    }

    // ---------- drawing ----------

    /// Everything on screen from the current state (cheap: 30 rows at most).
    pub fn rebuild(&self) {
        let Some(ui) = self.ui() else { return };
        self.feed_resolver();
        let frame = self.frame();
        {
            let mut st = self.st.borrow_mut();
            if let Some(sel) = st.selected
                && sel >= frame.path.hops.len()
            {
                st.selected = None; // the path got shorter
            }
            st.path = frame.path.clone();
        }
        sync(&self.rows, frame.rows);
        sync(&self.responders, frame.responders);
        sync(&self.events, frame.events);
        ui.set_summary(frame.summary);
        ui.set_detail(frame.detail);
        ui.set_responders_more(s(frame.responders_more));
        ui.set_events_title(s(frame.events_title));
        ui.set_table_note(s(frame.table_note));
        ui.set_status_left(s(frame.status));
        ui.set_status_warn(frame.status_warn);
        ui.set_status_right(s(frame.status_right));
        ui.set_running(frame.running);
        ui.set_has_trace(frame.has_trace);
        ui.set_logging(frame.logging);
        ui.set_mtu_running(frame.mtu_running);
        ui.set_can_mtu(frame.can_mtu);
        ui.set_show_mtu(frame.show_mtu);
        ui.set_window_title(s(frame.title));
        if frame.scroll_to >= 0 {
            ui.set_scroll_to(frame.scroll_to);
            ui.set_scroll_seq(frame.scroll_seq);
        }
    }

    /// New responders to the name and AS lookups (as switched on). No lock is held while the
    /// resolver works: in the tests it works inline.
    fn feed_resolver(&self) {
        let (names, asn, fresh) = {
            let st = self.st.borrow();
            let Some(sess) = &st.session else { return };
            let fresh = std::mem::take(&mut sess.trace.lock().unwrap().new_addrs);
            (st.prefs.names, st.prefs.asn, fresh)
        };
        for a in fresh {
            self.resolver.want(a, names, asn);
        }
    }

    fn frame(&self) -> Frame {
        let st = self.st.borrow();
        let mut f = Frame { scroll_to: -1, ..Frame::default() };
        f.running = st.resolving.is_some() || st.session.as_ref().is_some_and(|s| !s.stopped());
        f.has_trace = st.session.is_some();
        f.logging = st.log.is_some() || st.log_wanted;
        f.title = "VibeTrace".into();
        // The path MTU probe of this trace.
        let mtu = st.mtu.as_ref().map(|m| {
            let running = m.run.running(); // (it locks the state: not while a copy is being made)
            (m.run.state.lock().unwrap().clone(), running)
        });
        f.mtu_running = mtu.as_ref().is_some_and(|m| m.1);
        f.show_mtu = mtu.is_some();
        let opts_line = |p: &Prefs| format!("ICMP {} bytes every {}", p.size, view::interval(p.interval_ms));
        if let Some((host, _)) = &st.resolving {
            f.summary = SummaryInfo { started: true, dest_name: s(host), dest_addr: s("resolving…"), latency: s("—"), loss: s("—"), jitter: s("—"), hops: s("—"), elapsed: s("0:00"), ..Default::default() };
            f.table_note = format!("Resolving {host}…");
            f.status = format!("Resolving {host}…");
            f.title = format!("{host} · VibeTrace");
            return f;
        }
        let Some(sess) = &st.session else {
            f.status = match &st.note {
                Some((n, _)) => n.clone(),
                None => format!("Ready · {}", opts_line(&st.prefs)),
            };
            f.status_warn = st.note.as_ref().is_some_and(|n| n.1);
            return f;
        };
        let names = st.prefs.names;
        let now_ms = st.stopped_ms.unwrap_or_else(|| sess.now_ms());
        let guard = sess.trace.lock().unwrap();
        let t = &*guard;
        let known = self.resolver.known.lock().unwrap();
        let path = view::path(t, &known, names);
        let elapsed = now_ms.saturating_sub(t.origin_ms);

        // ---- rows ----
        let right = t.hops.iter().filter_map(|h| h.history.iter().last().map(|s| s.tick)).max().unwrap_or(0);
        let scale = spark_scale(t, path.hops.len(), right);
        f.can_mtu = f.running && !f.mtu_running && st.resolving.is_none() && t.reference().is_some() && t.fatal.is_none();
        let mtu_cell = |i: usize| match &mtu {
            Some((m, _)) if i <= m.plan.reference => m.cell(i),
            _ => (String::new(), 0, String::new()),
        };
        for (i, h) in path.hops.iter().enumerate() {
            let (bars, ticks) = sparkline(&t.hops[i], right, scale);
            f.rows.push(hop_row(i, h, &path, st.selected == Some(i), bars, ticks, mtu_cell(i)));
        }
        if path.silent_tail && !path.hops.is_empty() {
            f.rows.push(HopRow { index: -1, tail: true, silent: true, addr: s(format!("no reply beyond hop {}", path.hops.len())), ..Default::default() });
        }
        f.table_note = if !path.hops.is_empty() {
            String::new()
        } else if t.round() >= view::DEST_PATIENCE {
            "No hop answers: ICMP may be blocked by a firewall on this computer or its network.".into()
        } else if t.fatal.is_some() {
            String::new()
        } else if !f.running {
            "Stopped before the first answers.".into()
        } else {
            "Waiting for the first answers…".into()
        };
        if let Some(sel) = st.selected {
            f.scroll_to = sel as i32;
            f.scroll_seq = st.scroll_seq;
        }

        // ---- the answer first ----
        f.summary = summary(t, &path, elapsed);

        // ---- the detail: the selected hop, else the destination (or the last that answers) ----
        let focus = st.selected.filter(|i| *i < path.hops.len()).or(path.dest).or(path.reference);
        if let Some(i) = focus {
            let (w, h) = self.chart.get();
            f.detail = detail(t, &path, i, elapsed, w, h);
            let cell = mtu_cell(i).0;
            if !cell.is_empty() && cell != "…" && cell != "?" {
                f.detail.mtu = s(format!("· MTU {cell}"));
            }
            let hv = &path.hops[i];
            let total: u32 = hv.responders.iter().map(|r| r.replies).sum::<u32>() + hv.other_replies;
            for r in hv.responders.iter().take(4) {
                let (num, name) = known.as_text(r.addr);
                let failed = names && known.host_failed(r.addr);
                f.responders.push(ResponderRow {
                    addr: s(r.addr.to_string()),
                    host: s(if failed { resolve::NAME_FAILED } else if names { known.host(r.addr).unwrap_or("") } else { "" }),
                    as_text: s(if name.is_empty() { num } else { format!("{num} {name}") }),
                    share: s(view::loss_text(r.replies as f64 / total.max(1) as f64)),
                    primary: Some(r.addr) == hv.addr,
                });
            }
            if hv.responders.len() > 4 {
                f.responders_more = format!("+{} more", hv.responders.len() - 4);
            }
            let whole_path = st.selected.is_none() || Some(i) == path.dest || Some(i) == path.reference;
            f.events_title = if whole_path { "EVENTS ON THE PATH".into() } else { format!("EVENTS AT HOP {}", i + 1) };
            // (session ms, row): the trace's events, and while logging its outages and DNS
            // failures (the path's), newest first.
            let mut rows: Vec<(u64, EventRow)> = Vec::new();
            // While logging, an outage is the path's event: the hops' bursts inside it are its
            // own losses, said once by it (each hop's own list still has them). Spans in time
            // order (outages are found in order), looked up by a binary search: a flapping line
            // has a thousand outages and two thousand events, five times a second.
            let spans: Vec<(u64, u64)> = t.log.as_ref().map(|l| l.outages.iter().map(|o| (o.start_ms, o.end_ms.unwrap_or(u64::MAX))).collect()).unwrap_or_default();
            // (A hop before the reference loses its first probe up to an interval earlier.)
            let in_outage = |at: u64| {
                let a = at + t.opts.interval_ms as u64;
                let n = spans.partition_point(|s| s.0 <= a);
                n > 0 && at <= spans[n - 1].1
            };
            for e in t.events.iter() {
                if e.hop >= path.hops.len() || (!whole_path && e.hop != i) {
                    continue;
                }
                let hop = &path.hops[e.hop];
                let counts = Some(e.hop) == path.reference || hop.class == LossClass::Real;
                // Bursts at a rate-limiting router are not the path's: only its own list shows them.
                if matches!(e.kind, EventKind::LossBurst { .. }) && whole_path && (!counts || in_outage(e.at_ms + t.origin_ms)) {
                    continue;
                }
                let text = view::event_text(&e.kind, t.target.is_ipv6());
                rows.push((
                    e.at_ms + t.origin_ms,
                    EventRow {
                        time: s(t.started.time_after(e.at_ms + t.origin_ms)),
                        text: s(if whole_path { format!("hop {} · {text}", e.hop + 1) } else { text }),
                        danger: matches!(e.kind, EventKind::Unreachable { .. }) || (matches!(e.kind, EventKind::LossBurst { .. }) && counts),
                    },
                ));
            }
            if let (true, Some(log)) = (whole_path, &t.log) {
                // The newest hundred (the report has them all).
                for o in log.outages.iter().rev().take(100) {
                    let place = outage_place(&outage_rec(t, o, &known, None));
                    let text = match (o.end_ms, o.stopped) {
                        (Some(e), _) => format!("Outage {} {place}", crate::ispreport::dur(e - o.start_ms)),
                        (None, false) => format!("Outage now {place}"),
                        (None, true) => format!("Outage {place}, still out when the log stopped"),
                    };
                    rows.push((o.start_ms, EventRow { time: s(t.started.time_after(o.start_ms)), text: s(text), danger: true }));
                }
                let public = crate::dnscheck::public_name(t.target.is_ipv6());
                for (which, who) in [(0, "the system resolver"), (1, public)] {
                    for sp in &log.dns[which].spells {
                        let text = match sp.end_ms {
                            Some(e) => format!("DNS: {who} failed for {} ({})", crate::ispreport::dur(e - sp.start_ms), sp.why),
                            None => format!("DNS: {who} failing ({})", sp.why),
                        };
                        rows.push((sp.start_ms, EventRow { time: s(t.started.time_after(sp.start_ms)), text: s(text), danger: which == 0 }));
                    }
                }
            }
            rows.sort_by_key(|a| std::cmp::Reverse(a.0));
            f.events.extend(rows.into_iter().map(|r| r.1));
        } else {
            f.events_title = "EVENTS".into();
        }

        // ---- the status line ----
        let who = if t.name == t.target.to_string() { t.name.clone() } else { format!("{} ({})", t.name, t.target) };
        let unreachable = path.hops.iter().any(|h| h.unreachable.is_some());
        let hops = match (path.dest, path.hops.len()) {
            (Some(d), _) => count(d + 1, "hop", "hops"),
            (None, 0) => "no hops yet".into(),
            (None, n) if unreachable => format!("{}, unreachable", count(n, "hop", "hops")),
            (None, n) => format!("{n}+ hops"),
        };
        let line = format!("{} bytes every {}", t.opts.size, view::interval(t.opts.interval_ms));
        let mtu_now = mtu.as_ref().filter(|m| m.1).and_then(|(m, _)| m.current().map(|(k, size)| format!(" · path MTU: hop {}, {size} bytes ({} probe{})…", k + 1, m.probes, if m.probes == 1 { "" } else { "s" })));
        f.status = if let Some((n, warn)) = &st.note {
            f.status_warn = *warn;
            n.clone()
        } else if let (true, Some(lr), Some(log)) = (f.running, &st.log, &t.log) {
            let (words, warn) = log_words(t, log, &known, &*self.svc.local);
            let since = (self.svc.local)(lr.since_unix);
            let disk = if st.log_problem.is_some() { " · the log is kept in memory (its file cannot be written now)" } else { "" };
            f.status_warn = warn || st.log_problem.is_some();
            format!("Logging {who} since {:02}:{:02} · {words}{disk}{} · round {} · ICMP {line}", since.hour, since.minute, mtu_now.unwrap_or_default(), t.round())
        } else if f.running {
            format!("Tracing {who} · {hops}{} · round {} · ICMP {line}", mtu_now.unwrap_or_default(), t.round())
        } else {
            format!("Stopped · {who} · {hops} · {} · ICMP {line}", count(t.round() as usize, "round", "rounds"))
        };
        f.status_right = if t.target.is_ipv6() { "IPv6".into() } else { "IPv4".into() };
        f.title = if st.log.is_some() { format!("{} · logging · VibeTrace", t.name) } else { format!("{} · VibeTrace", t.name) };
        drop(known);
        drop(guard);
        f.path = path;
        f
    }
}

#[derive(Default)]
struct Frame {
    path: PathView,
    rows: Vec<HopRow>,
    summary: SummaryInfo,
    detail: DetailInfo,
    responders: Vec<ResponderRow>,
    responders_more: String,
    events: Vec<EventRow>,
    events_title: String,
    table_note: String,
    status: String,
    status_warn: bool,
    status_right: String,
    running: bool,
    has_trace: bool,
    logging: bool,
    mtu_running: bool,
    can_mtu: bool,
    show_mtu: bool,
    title: String,
    scroll_to: i32,
    scroll_seq: i32,
}

/// Where an outage broke, in a few words: "at the ISP's edge (hop 2)".
fn outage_place(r: &OutageRec) -> String {
    let phrase = crate::isplog::Zone::phrase(&r.zone);
    match (r.zone.as_str(), r.hop) {
        ("computer", _) | (_, None) => phrase.to_string(),
        (_, Some(h)) => format!("{phrase} (hop {h})"),
    }
}

/// The log in a few words for the status line and the tray ("2 outages · DNS ok"), and whether
/// it is a warning (an outage now, the system resolver failing).
fn log_words(t: &Trace, log: &crate::isplog::LogState, known: &resolve::Known, local: &dyn Fn(u64) -> WallClock) -> (String, bool) {
    let outages = match (log.open.and_then(|id| log.outage(id)), log.outages.len()) {
        (Some(o), _) => format!("outage now {}, since {}", outage_place(&outage_rec(t, o, known, None)), local(o.id).time_after(0)),
        (None, 0) => "no outages".into(),
        (None, 1) => "1 outage".into(),
        (None, n) => format!("{n} outages"),
    };
    let public = crate::dnscheck::public_name(t.target.is_ipv6());
    let (sys, publ) = (&log.dns[0], &log.dns[1]);
    let dns = match (sys.last.is_some(), sys.failing(), publ.failing()) {
        (false, _, _) if publ.last.is_none() => "DNS checking…".to_string(),
        (_, true, true) => "DNS failing (both resolvers)".to_string(),
        (_, true, false) => "DNS failing (the system resolver)".to_string(),
        (_, false, true) => format!("DNS ok ({public} does not answer)"),
        _ => "DNS ok".to_string(),
    };
    (format!("{outages} · {dns}"), log.open.is_some() || sys.failing())
}

/// Hop `k`'s sent and answered for the path MTU's normal loss: its ring with what was an
/// outage left out (`isplog::normal_counts`; this log's outages too, while logging).
pub fn mtu_loss(t: &Trace, k: usize) -> (u32, u32) {
    let none = std::collections::VecDeque::new();
    let outages = t.log.as_ref().map_or(&none, |l| &l.outages);
    let Some(ring) = t.recent.get(k) else { return (0, 0) };
    let (sent, lost) = crate::isplog::normal_counts(ring, ring.len(), outages);
    (sent, sent - lost)
}

/// An outage as it is written and shown: where it broke, in words, from what is known of the
/// path now.
pub fn outage_rec(t: &Trace, o: &Outage, known: &resolve::Known, note: Option<String>) -> OutageRec {
    let looks: Vec<HopLook> = t
        .hops
        .iter()
        .take(o.ttl as usize)
        .enumerate()
        .map(|(i, h)| {
            let addr = h.responders.primary();
            let asn = addr.and_then(|a| known.names.get(&a)).and_then(|x| x.asn);
            // Its normal loss: the outage's own losses are not the router rate-limiting.
            let (p, r) = (o.probes.get(i).copied().unwrap_or(0), o.replies.get(i).copied().unwrap_or(0));
            let sent = h.stats.sent.saturating_sub(p);
            let lost = h.stats.lost_count().saturating_sub(p.saturating_sub(r));
            let loss = if sent == 0 { 0.0 } else { lost as f64 / sent as f64 };
            HopLook { addr, answers: h.answers(), loss, asn, as_name: asn.and_then(|a| known.as_names.get(&a).cloned()).unwrap_or_default() }
        })
        .collect();
    let local = o.local.map(|s| crate::icmp::words(s, t.target.is_ipv6()));
    let l = crate::isplog::locate(&looks, o, local);
    OutageRec {
        id: o.id,
        // Its id is its start in UTC, as dated when it began (the clock may be followed since).
        start: o.id,
        end: o.end_ms.map(|e| t.unix(e)),
        ttl: o.ttl,
        dest: o.dest,
        hop: l.hop.map(|h| h as u8 + 1),
        addr: l.addr,
        zone: l.zone.code().into(),
        words: l.words,
        note: {
            // Said together: it may have begun before the log and outlasted it.
            let parts: Vec<String> = [o.before_log.then(|| "already out when the log began".to_string()), note.or_else(|| o.stopped.then(|| "still out when the log stopped".to_string()))]
                .into_iter()
                .flatten()
                .collect();
            (!parts.is_empty()).then(|| parts.join("; "))
        },
    }
}

/// Bring a model in line with `rows`, touching only the rows that changed.
fn sync<T: Clone + PartialEq + 'static>(model: &VecModel<T>, rows: Vec<T>) {
    let n = rows.len();
    for (i, r) in rows.into_iter().enumerate() {
        if i < model.row_count() {
            if model.row_data(i).as_ref() != Some(&r) {
                model.set_row_data(i, r);
            }
        } else {
            model.push(r);
        }
    }
    while model.row_count() > n {
        model.remove(model.row_count() - 1);
    }
}

fn hop_row(i: usize, h: &HopView, p: &PathView, selected: bool, bars: String, ticks: String, mtu: (String, i32, String)) -> HopRow {
    let silent = h.silent();
    let addr = h.addr.map(|a| a.to_string()).unwrap_or_else(|| "no reply".into());
    let loss_kind = match h.class {
        LossClass::None => 0,
        LossClass::Real => 1,
        LossClass::Limited => 2,
        LossClass::Silent => 3,
    };
    let loss_tip = view::loss_tip(p, i);
    let host = if h.host_failed { resolve::NAME_FAILED.to_string() } else { h.host.clone() };
    let mut a11y = vec![if host.is_empty() { addr.clone() } else { format!("{host} {addr}") }];
    if h.is_dest {
        a11y.push("destination".into());
    }
    if !h.as_num.is_empty() {
        a11y.push(format!("{} {}", h.as_num, h.as_name).trim().to_string());
    }
    if h.sent > 0 {
        a11y.push(format!("loss {}", view::loss_cell(h.loss)));
        if h.class == LossClass::Limited {
            a11y.push("rate limited".into());
        }
        a11y.push(format!("sent {}", h.sent));
    }
    if let Some(a) = h.avg {
        a11y.push(format!("average {} ms", view::ms(Some(a))));
    }
    if !mtu.0.is_empty() && mtu.0 != "…" {
        a11y.push(format!("MTU {}", mtu.0));
    }
    HopRow {
        index: i as i32,
        ttl: s(h.ttl.to_string()),
        host: s(&host),
        host_failed: h.host_failed,
        addr: s(addr),
        others: s(if h.others > 0 { format!("+{}", h.others) } else { String::new() }),
        as_num: s(&h.as_num),
        as_name: s(&h.as_name),
        loss: s(if h.sent == 0 { String::new() } else { view::loss_cell(h.loss) }),
        loss_kind,
        loss_tip: s(loss_tip),
        sent: s(if h.sent == 0 { String::new() } else { h.sent.to_string() }),
        last: s(view::ms(h.last)),
        avg: s(view::ms(h.avg)),
        avg_tip: s(if h.slow { view::SLOW_TIP } else { "" }),
        best: s(view::ms(h.best)),
        worst: s(view::ms(h.worst)),
        stdev: s(view::ms(h.stdev)),
        jitter: s(view::ms(h.jitter)),
        bars: s(bars),
        ticks: s(ticks),
        mtu: s(&mtu.0),
        mtu_kind: mtu.1,
        mtu_tip: s(&mtu.2),
        dest: h.is_dest,
        silent,
        tail: false,
        selected,
        a11y: s(a11y.join(", ")),
    }
}

/// The shared sparkline scale (µs): the largest of the rows' 95th percentiles over what the
/// sparklines show, so one spike does not flatten every row. At least 1 ms.
fn spark_scale(t: &Trace, shown: usize, right: u32) -> f64 {
    let left = right.saturating_sub(BARS as u32 - 1); // the shown ticks (fewer at the start)
    let mut scale: f64 = 1000.0;
    for h in t.hops.iter().take(shown) {
        let mut v: Vec<u32> = h.history.iter().filter(|s| s.tick >= left).filter_map(|s| s.rtt_us).collect();
        if v.is_empty() {
            continue;
        }
        v.sort_unstable();
        let p95 = v[((v.len() - 1) as f64 * 0.95).round() as usize];
        scale = scale.max(p95 as f64);
    }
    scale
}

/// One row's sparkline as path commands in a 150 x 26 pixel box: a 2 px bar per probe on a
/// 3 px pitch, newest at the right, rising from y 21 up to 16 px (at least 1 px for any reply,
/// clipped at the scale); a lost probe is a 2 x 4 px tick hanging from y 5.
pub fn sparkline(h: &Hop, right: u32, scale_us: f64) -> (String, String) {
    let left = right as i64 - (BARS as i64 - 1);
    let (mut bars, mut ticks) = (String::new(), String::new());
    // A hop that never answered would be a solid row of marks: it reads "no reply" instead.
    let silent = h.stats.received == 0;
    for smp in h.history.iter().filter(|s| s.tick as i64 >= left && s.tick <= right) {
        let x = (smp.tick as i64 - left) * 3;
        match smp.rtt_us {
            Some(us) => {
                let px = ((us as f64 / scale_us) * 16.0).round().clamp(1.0, 16.0) as u32;
                bars.push_str(&format!("M{x} {}H{}V21H{x}Z", 21 - px, x + 2));
            }
            None if !silent => ticks.push_str(&format!("M{x} 5H{}V9H{x}Z", x + 2)),
            None => {}
        }
    }
    (bars, ticks)
}

/// The chart's top: the smallest of 1, 2, 3, 4, 5, 6, 8 (times a power of ten) at or above
/// `v` ms, at least 1 ms. Fine enough not to waste the plot, round enough to read.
pub fn nice_ceil(v: f64) -> f64 {
    let v = v.max(1.0);
    let mag = 10f64.powf(v.log10().floor());
    for m in [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0] {
        if m * mag >= v - 1e-9 {
            return m * mag;
        }
    }
    10.0 * mag
}

fn scale_label(ms: f64) -> String {
    if ms < 1.0 { format!("{ms:.1} ms") } else { format!("{ms:.0} ms") }
}

/// The summary strip: the destination's numbers (the answer first).
fn summary(t: &Trace, p: &PathView, elapsed: u64) -> SummaryInfo {
    let named = t.name != t.target.to_string();
    let mut s_ = SummaryInfo {
        started: true,
        dest_name: s(&t.name),
        dest_addr: s(if named { t.target.to_string() } else { String::new() }),
        latency: s("—"),
        loss: s("—"),
        jitter: s("—"),
        hops: s("—"),
        elapsed: s(view::elapsed(elapsed)),
        ..Default::default()
    };
    if let Some(d) = p.dest.and_then(|d| p.hops.get(d)) {
        // The answer gets a decimal more than the table's columns (one under 100 ms).
        let fine = |v: Option<f64>| v.map(|v| view::ms_text(v).trim_end_matches(" ms").to_string()).unwrap_or_default();
        if let Some(avg) = d.avg {
            s_.latency = s(view::ms_text(avg));
            s_.latency_sub = s(format!("best {} · worst {}", fine(d.best), fine(d.worst)));
        }
        s_.jitter = s(d.jitter.map(view::ms_text).unwrap_or("—".into()));
        s_.loss = s(view::loss_cell(d.loss));
        s_.loss_sub = s(format!("of {}", d.sent));
        s_.loss_state = if d.loss > 0.0 { 2 } else { 1 };
        s_.hops = s(d.ttl.to_string());
    } else if let Some(u) = p.hops.iter().find(|h| h.unreachable.is_some()) {
        s_.latency_sub = s("unreachable");
        s_.hops = s(u.ttl.to_string());
        s_.hops_sub = s("ends");
    } else if p.dest_silent {
        s_.latency_sub = s("does not answer");
        s_.hops = s(format!("{}+", p.hops.len()));
    }
    s_
}

/// The detail panel for hop `i`: who, the verdict, and the chart in the plot's own pixels.
fn detail(t: &Trace, p: &PathView, i: usize, elapsed: u64, w: f32, h: f32) -> DetailInfo {
    let hv = &p.hops[i];
    let mut d = DetailInfo {
        shown: true,
        title: s(if hv.is_dest { format!("Hop {} · destination", hv.ttl) } else { format!("Hop {}", hv.ttl) }),
        host: s(if hv.host_failed { resolve::NAME_FAILED } else { &hv.host }),
        addr: s(hv.addr.map(|a| a.to_string()).unwrap_or_else(|| "no reply".into())),
        as_text: s(if hv.as_name.is_empty() { hv.as_num.clone() } else { format!("{} {}", hv.as_num, hv.as_name) }),
        verdict: s(view::verdict(p, i)),
        loss_real: hv.class == LossClass::Real,
        ..Default::default()
    };
    let (w, h) = (w.floor() as i64, h.floor() as i64);
    if w < 20 || h < 24 {
        return d;
    }
    // The span: the trace so far in whole minutes, from one up to ten.
    let span = (elapsed.div_ceil(60_000) * 60_000).clamp(60_000, CHART_SPAN_MAX_MS);
    d.x_left = s(format!("−{} min", span / 60_000));
    let (top, base) = (6i64, h - 1);
    let mid = (top + base) / 2;
    d.y_top_at = top as f32;
    d.y_mid_at = mid as f32;
    let rect = |x0: i64, y0: i64, x1: i64, y1: i64| format!("M{x0} {y0}H{x1}V{y1}H{x0}Z");
    let mut grid = rect(0, top, w, top + 1);
    grid.push_str(&rect(0, mid, w, mid + 1));
    grid.push_str(&rect(0, base, w, base + 1));
    d.grid = s(grid);
    let hop = &t.hops[i];
    // The span ends now at the right edge; early in a trace its left part is still empty.
    let from = elapsed as i64 - span as i64;
    let samples: Vec<_> = hop.history.iter().filter(|s| s.at_ms as i64 >= from).copied().collect();
    if hv.silent() {
        d.empty = s(if hv.sent > 0 { "No reply from this hop" } else { "No probes yet" });
        // Its losses are not drawn: a hop that never answers would be a solid band of marks.
        return d;
    }
    let mut v: Vec<u32> = samples.iter().filter_map(|s| s.rtt_us).collect();
    if v.is_empty() {
        d.empty = s("No replies in this span");
        return d;
    }
    v.sort_unstable();
    let p98 = v[((v.len() - 1) as f64 * 0.98).round() as usize] as f64 / 1000.0;
    let ymax = nice_ceil(p98 * 1.05);
    d.y_top = s(scale_label(ymax));
    d.y_mid = s(scale_label(ymax / 2.0));
    let y = |ms: f64| -> i64 { base - ((ms / ymax).min(1.0) * (base - top) as f64).round() as i64 };
    // Columns: as many as there are probes in the span (each at least 2 px wide), each a slice
    // of it: min..max as a band, the mean as a 2 px mark, a loss as a mark above the top line.
    let probes = (span / t.opts.interval_ms.max(1) as u64).max(1) as i64;
    let cw = (w / probes).max(2);
    let cols = (w / cw).min(probes).max(1) as usize;
    let per = span as f64 / cols as f64;
    let x0 = w - cols as i64 * cw; // the columns end flush with the right edge (now)
    let bw = if cw > 3 { cw - 1 } else { cw };
    let mut buckets: Vec<(u32, u32, f64, u32, bool)> = vec![(u32::MAX, 0, 0.0, 0, false); cols];
    for smp in &samples {
        let c = (((smp.at_ms as i64 - from) as f64) / per).floor().max(0.0) as usize;
        let b = &mut buckets[c.min(cols - 1)];
        match smp.rtt_us {
            Some(us) => {
                b.0 = b.0.min(us);
                b.1 = b.1.max(us);
                b.2 += us as f64;
                b.3 += 1;
            }
            None => b.4 = true,
        }
    }
    let (mut range, mut avg, mut loss) = (String::new(), String::new(), String::new());
    for (c, b) in buckets.iter().enumerate() {
        let x = x0 + c as i64 * cw;
        if b.3 > 0 {
            let (lo, hi) = (y(b.0 as f64 / 1000.0), y(b.1 as f64 / 1000.0));
            range.push_str(&rect(x, hi, x + bw, (lo + 1).max(hi + 1)));
            let m = y(b.2 / b.3 as f64 / 1000.0);
            avg.push_str(&rect(x, (m - 1).max(top), x + bw, (m + 1).max(top + 2)));
        }
        if b.4 {
            loss.push_str(&rect(x, 0, x + bw, 4));
        }
    }
    d.range = s(range);
    d.avg = s(avg);
    d.loss = s(loss);
    d
}

/// "1 hop", "2 hops" (copy-ux F14: no "1 hops").
fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 { format!("1 {one}") } else { format!("{n} {many}") }
}
