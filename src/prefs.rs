//! A small JSON file the app remembers things in (theme, window choices, recent entries).
//! Missing or garbled means defaults, but a garbled file is never written over: the first save
//! keeps it aside as `prefs.json.broken` (replacing an older copy; VibeBackup BA-3), and the
//! window says so (a file that turns garbled while the window is open too: `take_garbled`). A
//! file that is there but cannot be read right now is never overwritten. The window's changes
//! are kept as changes, not as a merged value: every write reads the file afresh and puts the
//! unwritten changes onto what it read, so another instance's prefs stay, even when this window
//! started on defaults because the file could not be read then (R2-TRACE-1, R2-SCAN-1). Writes
//! happen off the UI thread, whole or not at all.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// One change of this window's to the prefs (set a field, remember an entry), applied onto the
/// newest prefs right before each write.
pub type Change<T> = Arc<dyn Fn(&mut T) + Send + Sync>;

pub struct Store<T> {
    path: PathBuf,
    /// This window's changes that are not in the file yet, oldest first.
    changes: Arc<Mutex<Vec<Change<T>>>>,
    /// This window's prefs as last loaded or written: what the changes go onto when the file is
    /// missing or garbled.
    own: Arc<Mutex<T>>,
    write: Arc<Mutex<()>>,
    /// `load` found the file garbled.
    broken: Arc<AtomicBool>,
    /// The garbled file `load` found (told at start); cleared once a good file is written.
    noted: Arc<AtomicBool>,
    /// A garbled file was kept aside and the good one not written yet.
    aside: Arc<AtomicBool>,
    /// A garbled file was kept aside and replaced that nobody has told the user about yet.
    garbled_new: Arc<AtomicBool>,
}

impl<T> Clone for Store<T> {
    fn clone(&self) -> Self {
        Store {
            path: self.path.clone(),
            changes: self.changes.clone(),
            own: self.own.clone(),
            write: self.write.clone(),
            broken: self.broken.clone(),
            noted: self.noted.clone(),
            aside: self.aside.clone(),
            garbled_new: self.garbled_new.clone(),
        }
    }
}

/// A lock that a panic elsewhere does not turn into a second one (the test rigs flush in Drop).
fn lock<X>(m: &Mutex<X>) -> MutexGuard<'_, X> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Where a garbled file is kept: `prefs.json.broken`.
pub fn broken_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".broken");
    path.with_file_name(name)
}

/// Defaults when the file is missing or garbled; an error when it is there but unreadable now.
pub fn read<T: DeserializeOwned + Default>(path: &Path) -> std::io::Result<T> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(serde_json::from_str(&t).unwrap_or_default()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.kind() == std::io::ErrorKind::InvalidData => Ok(T::default()),
        Err(e) => Err(e),
    }
}

/// Whole or not at all: a crash or a power cut mid-write leaves the old file. The temp file sits
/// beside the target and is this process's own (named by its id, and made create-new), so
/// neither a second instance writing at the same moment nor a file of the user's that happens to
/// have its name is ever written into or removed: a name already taken moves on to the next.
/// It is on the disk (`sync_all`, FlushFileBuffers) before it takes the name, so a power cut
/// right after cannot leave the name on zeros (FS10), and it is removed on every error. std's
/// rename replaces with POSIX semantics on NTFS: a reader holding the file open (another
/// instance, a scanner) does not block it, where MoveFileExW is refused. The new file takes the
/// folder's attributes and ACL, as before.
pub fn write_atomic(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let pid = std::process::id();
    let mut n = 0;
    let (tmp, mut file) = loop {
        let tmp = path.with_extension(if n == 0 { format!("{pid}.tmp") } else { format!("{pid}-{n}.tmp") });
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(f) => break (tmp, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && n < 20 => n += 1,
            Err(e) => return Err(e),
        }
    };
    let r = file.write_all(body).and_then(|_| file.sync_all());
    drop(file);
    let r = r.and_then(|_| std::fs::rename(&tmp, path));
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

impl<T: Serialize + DeserializeOwned + Default + Clone + PartialEq + Send + 'static> Store<T> {
    pub fn new(path: PathBuf) -> Store<T> {
        Store {
            path,
            changes: Default::default(),
            own: Default::default(),
            write: Default::default(),
            broken: Default::default(),
            noted: Default::default(),
            aside: Default::default(),
            garbled_new: Default::default(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The prefs, defaults when missing, garbled or unreadable now. Reads only; a garbled file
    /// is noted (`broken`) and kept aside by the first write.
    pub fn load(&self) -> T {
        let v = match std::fs::read(&self.path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|_| {
                self.broken.store(true, Ordering::Relaxed);
                self.noted.store(true, Ordering::SeqCst);
                T::default()
            }),
            Err(_) => T::default(),
        };
        *lock(&self.own) = v.clone();
        v
    }

    /// `load` found the file garbled (the window tells the user).
    pub fn broken(&self) -> bool {
        self.broken.load(Ordering::Relaxed)
    }

    /// Whether a garbled file was kept aside and replaced since this was last asked (not the one
    /// `load` found at start, which the window tells by `broken`): the window says so once.
    pub fn take_garbled(&self) -> bool {
        self.garbled_new.swap(false, Ordering::SeqCst)
    }

    /// One change of this window's: kept until it is in the file, and written now (`flush`). Call
    /// it off the UI thread (it reads the file).
    pub fn change(&self, f: Change<T>) {
        lock(&self.changes).push(f);
        self.flush();
    }

    /// Write the unwritten changes: read the file afresh, put every change onto it in order,
    /// write the result, and only then forget the changes. While the file cannot be read nothing
    /// is written and the changes wait for the next write (one still waiting at exit is lost:
    /// never this window's defaults over a file it could not read). A garbled file is kept aside
    /// first (never written over), and a garbled or missing one is replaced by this window's
    /// own prefs with the changes.
    pub fn flush(&self) {
        let _w = lock(&self.write);
        let n = lock(&self.changes).len();
        if n == 0 {
            return;
        }
        let base = match std::fs::read(&self.path) {
            Ok(b) => match serde_json::from_slice::<T>(&b) {
                Ok(v) => Some(v),
                // Garbled: kept aside (replacing an older copy), never written over.
                Err(_) if std::fs::rename(&self.path, broken_path(&self.path)).is_ok() => {
                    self.aside.store(true, Ordering::SeqCst);
                    Some(lock(&self.own).clone())
                }
                Err(_) => None,
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(lock(&self.own).clone()),
            Err(_) => None,
        };
        let Some(mut v) = base else { return };
        let todo: Vec<Change<T>> = lock(&self.changes)[..n].to_vec();
        for f in &todo {
            f(&mut v);
        }
        let ok = serde_json::to_vec_pretty(&v).map(|b| write_atomic(&self.path, &b).is_ok()).unwrap_or(false);
        if ok {
            lock(&self.changes).drain(..n);
            *lock(&self.own) = v;
            // Kept aside and replaced: now it is true to say so (unless it is the one told at start).
            if self.aside.swap(false, Ordering::SeqCst) && !self.noted.load(Ordering::SeqCst) {
                self.garbled_new.store(true, Ordering::SeqCst);
            }
            self.noted.store(false, Ordering::SeqCst);
        }
    }
}
