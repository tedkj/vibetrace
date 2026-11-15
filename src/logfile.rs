//! The ISP log on disk (SPEC §9.2): one JSON-lines file per target and family in
//! `%LOCALAPPDATA%\com.tedkj.vibetrace\logs`, a ring across runs (7 days, 16 MiB), written by the
//! log's own thread, never the window's.
//!
//! The state-file rules (VIBEWARE.md): the file is read before the first write and before every
//! rewrite; one whose first line is not a VibeTrace `run` record is garbled, kept aside as
//! `<name>.broken` and never written over; a torn last line (a crash mid-write) is skipped and
//! the next append starts on a new line; a file that cannot be read or written right now gets
//! nothing: the records wait in memory (at most a day of minutes) and are tried again at every
//! write. An append that fails half way is cut back to where it began, so no record is written
//! twice; when even the cut-back fails, the file is read again before the next write and a
//! record may be in it twice (said in the status). While one instance writes, another cannot
//! open the file to write: nothing is written over another instance's lines.

use crate::isplog::{LOG_VERSION, Record};
use crate::prefs::{broken_path, write_atomic};
use std::collections::{HashMap, VecDeque};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Records are kept while at most this much older than the newest.
pub const KEEP_MS: u64 = 7 * 24 * 3600 * 1000;
/// Past this size the file is rewritten with the newest records in `KEEP_BYTES`.
pub const CAP_BYTES: u64 = 16 * 1024 * 1024;
pub const KEEP_BYTES: u64 = 12 * 1024 * 1024;
/// The most of a log file ever read: the ring keeps it under CAP_BYTES, and the last write
/// before a rewrite can pass it by a little. A larger file is not one VibeTrace wrote (replaced,
/// or grown by another program): it counts as damaged and is never read whole
/// (IN-VibeTrace-3).
pub const READ_MAX: u64 = CAP_BYTES + 4 * 1024 * 1024;

/// A log file, at most READ_MAX bytes: larger is InvalidData (damaged).
fn read_log(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut b = Vec::new();
    std::fs::File::open(path)?.take(READ_MAX + 1).read_to_end(&mut b)?;
    if b.len() as u64 > READ_MAX {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "larger than an ISP log grows"));
    }
    Ok(b)
}
/// The log opened to write at the end we know: read and write, created when missing. Not an
/// append handle: on Windows that one lacks FILE_WRITE_DATA, so a failed append could never be
/// cut back (`set_len` is refused). Others may read it meanwhile, never write (RVB3): another
/// instance logging the same target cannot open it to write between this handle's length check
/// and the end of its write or cut-back; its minutes wait in memory until its next write.
fn open_log(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).share_mode(1 /* FILE_SHARE_READ */).open(path)
}

/// A file that can be cut back to a length (the tests hand in one that fails half way).
trait CutBack: std::io::Write + std::io::Seek {
    fn cut_back(&self, len: u64) -> std::io::Result<()>;
}

impl CutBack for std::fs::File {
    fn cut_back(&self, len: u64) -> std::io::Result<()> {
        self.set_len(len)
    }
}

/// Write `buf` at `at` (the file's known end). One that fails part way is cut back to `at` on
/// the same handle, so the queue written again later leaves no record in the file twice. Err:
/// the write's error, and whether the cut-back worked.
fn append_at(f: &mut impl CutBack, at: u64, buf: &[u8]) -> Result<(), (std::io::Error, bool)> {
    let r = f.seek(std::io::SeekFrom::Start(at)).and_then(|_| f.write_all(buf)).and_then(|_| f.flush());
    r.map_err(|e| (e, f.cut_back(at).is_ok()))
}

/// Minutes kept in memory while the file cannot be written (a day).
pub const QUEUE_MINUTES: usize = 1440;
/// Times before this (2020-01-01) or more than a year ahead are not believed (a broken clock or
/// a hostile file): such records are skipped.
pub const EARLIEST: u64 = 1_577_836_800_000;
const AHEAD_MS: u64 = 365 * 24 * 3600 * 1000;
/// The ring judges "newest" among records at most a day ahead of now: one far in the future
/// (a hostile line) must not make it drop everything else. The clock set back by more than a
/// day leaves none such; then the newest of all counts.
const SANE_MS: u64 = 24 * 3600 * 1000;
/// A rewrite keeps a little less than `KEEP_MS`, so the next one is an hour away, not a minute.
const KEEP_TRIM_MS: u64 = KEEP_MS - 3600 * 1000;
/// Lines of any kind waiting in memory at most (outages of a flapping line pile up too).
pub const QUEUE_LINES: usize = 2 * QUEUE_MINUTES;

/// "<host> IPv4.jsonl": characters outside `a-z 0-9 . -` become `-`, at most 100.
pub fn file_name(host: &str, ipv6: bool) -> String {
    let h: String = host.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' }).take(100).collect();
    let h = h.trim_matches('.');
    let h = if h.is_empty() { "target" } else { h };
    format!("{h} {}.jsonl", if ipv6 { "IPv6" } else { "IPv4" })
}

/// One line as a record of this version, whatever its time.
pub fn parse_record(line: &str) -> Option<Record> {
    let r: Record = serde_json::from_str(line.trim_end_matches('\r')).ok()?;
    if let Record::Run(run) = &r
        && run.v != LOG_VERSION
    {
        return None;
    }
    if let Record::Outage(o) = &r
        && o.end.is_some_and(|e| e < o.start)
    {
        return None;
    }
    Some(r)
}

/// One line as a record, if it is one and its time is believable at `now`.
pub fn parse_line(line: &str, now: u64) -> Option<Record> {
    let r = parse_record(line)?;
    let at = r.at();
    (at >= EARLIEST && r.age_at() <= now.saturating_add(AHEAD_MS)).then_some(r)
}

/// What a read of the file found.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Scan {
    pub len: u64,
    pub ends_nl: bool,
    pub oldest: Option<u64>,
    pub newest: Option<u64>,
    /// Lines that are not records (a torn line, damage).
    pub skipped: u32,
    pub records: u32,
}

impl Scan {
    fn see(&mut self, at: u64) {
        self.oldest = Some(self.oldest.map_or(at, |o| o.min(at)));
        self.newest = Some(self.newest.map_or(at, |n| n.max(at)));
    }
}

/// Read a log file's bytes. Err: garbled (empty files are fine; anything else must begin with
/// a VibeTrace `run` record: judged by what the line is, never by its time, so a clock set
/// back does not make a log "damaged"). The span (oldest, newest) is of the minutes and
/// outages, not the run records (an old run kept at the front would make it a week forever).
// Err says "garbled" and nothing more: there is no detail to carry.
#[allow(clippy::result_unit_err)]
pub fn scan(bytes: &[u8], now: u64) -> Result<Scan, ()> {
    let mut s = Scan { len: bytes.len() as u64, ends_nl: bytes.last().is_none_or(|b| *b == b'\n'), ..Scan::default() };
    let mut first = true;
    for line in bytes.split(|b| *b == b'\n') {
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let text = std::str::from_utf8(line).ok();
        if first {
            if !matches!(text.and_then(parse_record), Some(Record::Run(_))) {
                return Err(());
            }
            first = false;
        }
        match text.and_then(|l| parse_line(l, now)) {
            Some(r) => {
                s.records += 1;
                if !matches!(r, Record::Run(_)) && r.age_at() <= now.saturating_add(SANE_MS) {
                    s.see(r.age_at());
                }
            }
            None => s.skipped += 1,
        }
    }
    Ok(s)
}

/// The ring: the newest minutes and outages at most `KEEP_TRIM_MS` older than the newest
/// (an outage by its end) and within `budget` bytes, whole lines, in file order; the run
/// records among them, and the latest one before them at the front (every file begins with
/// one). Lines that are not records go.
pub fn ring(bytes: &[u8], now: u64, budget: u64) -> Vec<u8> {
    let lines: Vec<(&[u8], Record)> = bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.iter().all(|b| b.is_ascii_whitespace()))
        .filter_map(|l| Some((l, std::str::from_utf8(l).ok().and_then(|s| parse_line(s, now))?)))
        .collect();
    let times = || lines.iter().filter(|(_, r)| !matches!(r, Record::Run(_))).map(|(_, r)| r.age_at());
    let Some(newest) = times().filter(|t| *t <= now.saturating_add(SANE_MS)).max().or_else(|| times().max()) else { return Vec::new() };
    let mut keep: Vec<usize> = Vec::new();
    let mut used = 0u64;
    for (i, (l, r)) in lines.iter().enumerate().rev() {
        if matches!(r, Record::Run(_)) {
            continue; // placed below
        }
        if r.age_at() + KEEP_TRIM_MS < newest {
            continue; // old (a line written later may still be new: an outage's end)
        }
        if used + l.len() as u64 + 1 > budget {
            break;
        }
        used += l.len() as u64 + 1;
        keep.push(i);
    }
    keep.reverse();
    if let Some(&first) = keep.first() {
        let runs = (first..lines.len()).filter(|i| matches!(lines[*i].1, Record::Run(_)));
        let lead = (0..first).rev().find(|i| matches!(lines[*i].1, Record::Run(_)));
        keep.extend(lead.into_iter().chain(runs));
        keep.sort_unstable();
    }
    let mut out = Vec::with_capacity(used as usize + 256);
    for i in keep {
        out.extend_from_slice(lines[i].0.strip_suffix(b"\r").unwrap_or(lines[i].0));
        out.push(b'\n');
    }
    out
}

/// How the log's file stands, for the window (shared with the writer).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Status {
    /// What is wrong right now, in words (None: written fine).
    pub problem: Option<String>,
    /// Counts the spells of problems (the window tells each once).
    pub spell: u64,
    /// Files found garbled and kept aside, not told yet.
    pub broken: Vec<PathBuf>,
    /// Minutes that went because the file could not be written for over a day.
    pub dropped: u32,
}

#[derive(Default)]
struct FileState {
    queue: VecDeque<String>,
    /// The newest `run` line sent for this file (a new file must begin with one).
    run_line: Option<String>,
    known: Option<Scan>,
}

/// The files and what waits for them. Lives on the writer's thread (or the caller's, inline).
pub struct Disk {
    files: HashMap<PathBuf, FileState>,
    status: Arc<Mutex<Status>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Disk {
    fn problem(&self, why: Option<String>) {
        let mut s = lock(&self.status);
        if why.is_some() && s.problem.is_none() {
            s.spell += 1;
        }
        s.problem = why;
    }

    /// Queue `lines` for `path` and write what waits.
    pub fn write(&mut self, path: &Path, lines: Vec<String>) {
        let st = self.files.entry(path.to_path_buf()).or_default();
        for l in lines {
            if l.starts_with("{\"kind\":\"run\"") {
                st.run_line = Some(l.clone());
            }
            st.queue.push_back(l);
        }
        // A day of minutes at most: older ones go (counted).
        let minutes = st.queue.iter().filter(|l| l.starts_with("{\"kind\":\"min\"")).count();
        if minutes > QUEUE_MINUTES {
            let mut extra = minutes - QUEUE_MINUTES;
            let before = st.queue.len();
            st.queue.retain(|l| {
                if extra > 0 && l.starts_with("{\"kind\":\"min\"") {
                    extra -= 1;
                    false
                } else {
                    true
                }
            });
            lock(&self.status).dropped += (before - st.queue.len()) as u32;
        }
        // And all of it: the oldest lines that are not runs go first (outages counted too).
        while st.queue.len() > QUEUE_LINES {
            match st.queue.iter().position(|l| !l.starts_with("{\"kind\":\"run\"")) {
                Some(i) => {
                    st.queue.remove(i);
                    lock(&self.status).dropped += 1;
                }
                None => break,
            }
        }
        self.flush(path);
    }

    /// The lines not written yet for `path` (a report adds them to what the file holds).
    pub fn pending(&self, path: &Path) -> Vec<String> {
        self.files.get(path).map(|s| s.queue.iter().cloned().collect()).unwrap_or_default()
    }

    /// Read the file whole: is it ours? Kept aside when garbled. None: nothing may be written.
    fn check(&mut self, path: &Path) -> Option<Scan> {
        let now = (self.clock)();
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let read = match read_log(path) {
            Ok(bytes) => scan(&bytes, now),
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => Err(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Scan { ends_nl: true, ..Scan::default() }),
            Err(e) => {
                self.problem(Some(format!("The ISP log ({name}) cannot be read right now ({e}): its minutes are kept in memory until it can.")));
                return None;
            }
        };
        match read {
            Ok(s) => Some(s),
            // Garbled, or larger than any log of ours: kept aside (an older copy replaced), never
            // written over.
            Err(()) => match std::fs::rename(path, broken_path(path)) {
                Ok(()) => {
                    lock(&self.status).broken.push(path.to_path_buf());
                    Some(Scan { ends_nl: true, ..Scan::default() })
                }
                Err(e) => {
                    self.problem(Some(format!("The ISP log ({name}) is damaged and cannot be kept aside ({e}): nothing is written to it.")));
                    None
                }
            },
        }
    }

    /// Does the file still begin the way we left it (ours, the length we wrote)? Cheap: its
    /// length and first line.
    fn unchanged(path: &Path, known: &Scan, now: u64) -> bool {
        let Ok(mut f) = std::fs::File::open(path) else { return known.len == 0 && !path.exists() };
        if f.metadata().map(|m| m.len()).ok() != Some(known.len) {
            return false;
        }
        if known.len == 0 {
            return true;
        }
        let mut head = vec![0u8; 4096];
        let n = f.read(&mut head).unwrap_or(0);
        let first = head[..n].split(|b| *b == b'\n').next().unwrap_or(&[]);
        std::str::from_utf8(first).ok().and_then(|l| parse_line(l, now)).is_some_and(|r| matches!(r, Record::Run(_)))
    }

    /// Write what waits for `path`: check the file (whole the first time, or when it changed
    /// behind our back), append, and keep the ring.
    pub fn flush(&mut self, path: &Path) {
        let now = (self.clock)();
        let fresh = match self.files.get(path) {
            None => return,
            Some(st) if st.queue.is_empty() => return,
            Some(st) => st.known.as_ref().is_none_or(|k| !Self::unchanged(path, k, now)),
        };
        if fresh {
            let scan = self.check(path);
            let st = self.files.get_mut(path).expect("present");
            st.known = scan;
            if st.known.is_none() {
                return;
            }
        }
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let (buf, known) = {
            let st = self.files.get_mut(path).expect("present");
            let known = st.known.clone().expect("checked");
            // A new file begins with the run it belongs to (none known yet: it waits).
            if known.len == 0 && !st.queue.front().is_some_and(|l| l.starts_with("{\"kind\":\"run\"")) {
                match st.run_line.clone() {
                    Some(r) => st.queue.push_front(r),
                    None => return,
                }
            }
            let mut buf = String::new();
            if known.len > 0 && !known.ends_nl {
                buf.push('\n'); // after a torn line
            }
            for l in &st.queue {
                buf.push_str(l);
                buf.push('\n');
            }
            (buf, known)
        };
        if let Some(dir) = path.parent()
            && let Err(e) = std::fs::create_dir_all(dir)
        {
            self.problem(Some(format!("The ISP log's folder cannot be made ({e}): its minutes are kept in memory until it can.")));
            return;
        }
        let mut f = match open_log(path) {
            Ok(f) => f,
            Err(e) => {
                self.files.get_mut(path).expect("present").known = None; // read it again next time
                self.problem(Some(format!("The ISP log ({name}) cannot be written right now ({e}): its minutes are kept in memory until it can.")));
                return;
            }
        };
        // The length we know, on this very handle: anything else changed it behind our back
        // (read again at the next write; nothing is written over). No other handle can write
        // until this one closes, so the length holds until the write or cut-back is done.
        if f.metadata().map(|m| m.len()).ok() != Some(known.len) {
            self.files.get_mut(path).expect("present").known = None;
            return;
        }
        if let Err((e, cut_back)) = append_at(&mut f, known.len, buf.as_bytes()) {
            self.files.get_mut(path).expect("present").known = None; // read it again next time
            self.problem(Some(if cut_back {
                format!("The ISP log ({name}) cannot be written right now ({e}): its minutes are kept in memory until it can.")
            } else {
                format!("The ISP log ({name}) cannot be written right now ({e}), and the part that did get written could not be taken back out: VibeTrace reads the file again before its next write, and a minute may be in it twice.")
            }));
            return;
        }
        // Closed before the ring's rewrite: it renames a new file over this one, which an open
        // handle that does not share delete would refuse.
        drop(f);
        let full = {
            let st = self.files.get_mut(path).expect("present");
            let mut k = known;
            k.len += buf.len() as u64;
            k.ends_nl = true;
            for l in &st.queue {
                if let Some(r) = parse_line(l, now) {
                    k.see(r.at());
                    k.records += 1;
                }
            }
            st.queue.clear();
            let full = k.len > CAP_BYTES || matches!((k.oldest, k.newest), (Some(o), Some(n)) if n.saturating_sub(o) > KEEP_MS);
            st.known = Some(k);
            full
        };
        self.problem(None);
        if full {
            self.rewrite(path);
        }
    }

    /// The ring: read the file again and write back the newest records (whole or not at all).
    fn rewrite(&mut self, path: &Path) {
        let now = (self.clock)();
        let Ok(bytes) = read_log(path) else {
            if let Some(st) = self.files.get_mut(path) {
                st.known = None;
            }
            return;
        };
        if scan(&bytes, now).is_err() {
            if let Some(st) = self.files.get_mut(path) {
                st.known = None; // checked (and kept aside) at the next write
            }
            return;
        }
        let kept = ring(&bytes, now, KEEP_BYTES);
        let ok = write_atomic(path, &kept).is_ok();
        if let Some(st) = self.files.get_mut(path) {
            st.known = if ok { scan(&kept, now).ok() } else { None };
        }
    }

    /// Everything the log holds for `path`, as lines: the file (when it is ours and can be read)
    /// and what waits. The error says why the file was left out.
    pub fn read_all(&mut self, path: &Path) -> (Vec<String>, Option<String>) {
        self.flush(path);
        let now = (self.clock)();
        let mut out = Vec::new();
        let mut why = None;
        match read_log(path) {
            Ok(bytes) => {
                if scan(&bytes, now).is_ok() {
                    out.extend(String::from_utf8_lossy(&bytes).lines().map(str::to_string));
                } else {
                    why = Some("the log file is damaged".to_string());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => why = Some("the log file is damaged (larger than VibeTrace ever writes it)".to_string()),
            Err(e) => why = Some(format!("the log file cannot be read right now ({e})")),
        }
        out.extend(self.pending(path));
        (out, why)
    }
}

enum Msg {
    Write(PathBuf, Vec<String>),
    Job(Box<dyn FnOnce(&mut Disk) + Send>),
    Sync(Sender<()>),
}

/// The log's writer: a thread of its own (inline in the window tests).
pub struct LogWriter {
    tx: Option<Sender<Msg>>,
    inline: Option<Mutex<Disk>>,
    pub status: Arc<Mutex<Status>>,
}

impl LogWriter {
    pub fn new(inline: bool, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> LogWriter {
        let status = Arc::new(Mutex::new(Status::default()));
        let disk = Disk { files: HashMap::new(), status: status.clone(), clock };
        if inline {
            return LogWriter { tx: None, inline: Some(Mutex::new(disk)), status };
        }
        let (tx, rx) = channel::<Msg>();
        let mut disk = disk;
        let _ = std::thread::Builder::new().name("isp-log".into()).stack_size(512 * 1024).spawn(move || {
            while let Ok(m) = rx.recv() {
                match m {
                    Msg::Write(p, lines) => disk.write(&p, lines),
                    Msg::Job(f) => f(&mut disk),
                    Msg::Sync(done) => {
                        let _ = done.send(());
                    }
                }
            }
        });
        LogWriter { tx: Some(tx), inline: None, status }
    }

    pub fn write(&self, path: PathBuf, lines: Vec<String>) {
        if lines.is_empty() {
            return;
        }
        match (&self.tx, &self.inline) {
            (Some(tx), _) => {
                let _ = tx.send(Msg::Write(path, lines));
            }
            (None, Some(d)) => lock(d).write(&path, lines),
            _ => {}
        }
    }

    /// Work on the writer's own thread (a report reads the file there, between writes).
    pub fn run(&self, f: impl FnOnce(&mut Disk) + Send + 'static) {
        match (&self.tx, &self.inline) {
            (Some(tx), _) => {
                let _ = tx.send(Msg::Job(Box::new(f)));
            }
            (None, Some(d)) => f(&mut lock(d)),
            _ => {}
        }
    }

    /// Wait (at most `limit`) until everything sent so far is done: exit, and tests.
    pub fn sync(&self, limit: Duration) {
        if let Some(tx) = &self.tx {
            let (done, wait) = channel();
            if tx.send(Msg::Sync(done)).is_ok() {
                let _ = wait.recv_timeout(limit);
            }
        }
    }
}
