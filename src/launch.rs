//! Files dropped on the exe or its shortcut. Windows starts the app with their paths as its
//! arguments, but VibeTrace takes a host there, and a file is never one. A dropped file is told
//! apart by its shape alone (`dropped_file`): nothing asks the disk or a share about it (a
//! `\\server\...` path asked about would make Windows contact that server). Only dropped files:
//! the window, no target, and a toast saying they were left alone. A dropped file beside
//! anything else: exit 2. No dropped file: the command line as before (`target_arg`).

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

/// The longest name a toast shows; a longer one keeps its start and end around an ellipsis.
const LONGEST: usize = 60;

/// What the arguments hold of files dropped on the exe.
#[derive(Debug, PartialEq)]
pub enum Dropped {
    /// No dropped file: the command line as before (`target_arg`).
    No,
    /// Only dropped files (one or more): the window with no target, and this toast.
    Files(String),
    /// Dropped files and something else: exit 2.
    Mixed,
}

/// The arguments after the exe's own name.
pub fn dropped(args: &[OsString]) -> Dropped {
    let files = args.iter().filter(|a| dropped_file(a)).count();
    if files == 0 {
        Dropped::No
    } else if files < args.len() {
        Dropped::Mixed
    } else {
        Dropped::Files(left_alone(args))
    }
}

/// A dropped file's shape: an absolute path with a drive (`C:\...` or `C:/...`, any letter) or a
/// UNC or device path (`\\...`), once the spaces and `"` before it are trimmed (lossy: a name
/// that is not Unicode keeps its other characters). By the text alone, never by asking the disk
/// or the network. No host, address or URL has this shape: a name holds no `\`, and an IPv6
/// address has no `\` or `/` after a colon (`[::1]`, `fe80::1%12`, `c::1`); a drive alone (`C:`)
/// or drive-relative (`C:x`) is not one either.
pub fn dropped_file(a: &OsStr) -> bool {
    let lossy = a.to_string_lossy();
    let t = lossy.trim_start_matches(|c: char| c.is_whitespace() || c == '"');
    let b = t.as_bytes();
    t.starts_with(r"\\") || (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && matches!(b[2], b'\\' | b'/'))
}

/// The name a toast shows for a path (lossy). A Windows name never holds a `"`, so one is left
/// over from the command line's quoting (`"C:\Photos\"` ends in `\"`, an escaped quote): the
/// path is the text before it. Anything else, a `'` or a space included, belongs to the name. A
/// path with no name of its own shows its last folder (`C:\a\b\..` shows `a`) or its drive or
/// share (`C:\`), and a long name is cut in the middle.
fn shown(a: &OsStr) -> String {
    let lossy = a.to_string_lossy();
    let path = lossy.trim_start_matches('"').split('"').next().unwrap_or_default();
    let mut kept: Vec<Component> = Vec::new();
    for c in Path::new(path).components() {
        match (c, kept.last()) {
            (Component::ParentDir, Some(Component::Normal(_))) => {
                kept.pop();
            }
            (Component::ParentDir, Some(Component::RootDir)) => {}
            (c, _) => kept.push(c),
        }
    }
    let name = match kept.last() {
        Some(Component::Normal(n)) => n.to_string_lossy().into_owned(),
        Some(_) => kept.iter().collect::<PathBuf>().to_string_lossy().into_owned(),
        None => ".".to_string(),
    };
    let n = name.chars().count();
    if n <= LONGEST {
        return name;
    }
    let head: String = name.chars().take(LONGEST / 2).collect();
    let tail: String = name.chars().skip(n - (LONGEST - LONGEST / 2 - 1)).collect();
    format!("{head}\u{2026}{tail}")
}

/// The toast for dropped files: the first one's name (not its folder), and how many more.
fn left_alone(args: &[OsString]) -> String {
    let name = shown(&args[0]);
    let more = match args.len() - 1 {
        0 => String::new(),
        n => format!(" and {n} more"),
    };
    format!("VibeTrace doesn't open files, so it left {name}{more} alone.")
}
