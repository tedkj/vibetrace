//! About's "Check this install": the rules, with no I/O, so every case is tested. The I/O lives
//! elsewhere and is handed in: what Windows says of the files' signatures and their SHA-256
//! (`trust`, offline), and the signed release list from the website (`net`, online, only when
//! the button is pressed). Here: the list's minisign signature checked first, then the list
//! parsed, then the files and the version compared, and each of the three rows (Signature,
//! Files, Version) put in words.
//!
//! What it can prove: the signature row is Windows' own check (a changed exe can't pass it
//! without the signing key). The files and version rows are the app checking itself: they catch
//! damage (a broken update, a quarantined or swapped file) and a release list that was swapped
//! or tampered with, but a changed copy could fake this window, which the note under the rows
//! says.

use std::collections::BTreeMap;

/// The website (About's link) and the release lists' home.
pub const SITE: &str = "https://getvibeware.com";
/// The release lists' host: the fetcher talks to this one only, over HTTPS on 443.
pub const HOST: &str = "getvibeware.com";
/// The release list's signing key: the updater's (VibeFTP `app/src/updater.rs`). Ted holds the
/// secret half.
pub const RELEASE_KEY: &str = "RWRtiPHhr0TNUFN/XkthdjPMyH1O9YUG07Ge9MyAFamDUBzJ2agHr7EA";
/// Who signs the exe: the Certum certificate's name, as Windows shows it (the exe's Properties, Digital Signatures).
/// A valid signature by anyone else is a danger.
pub const PUBLISHER: &str = "Open Source Developer Ted Kenneth Johansen";
/// Who issues that certificate: the issuer's common name on the shipped files. A signature that
/// names PUBLISHER but chains to another issuer is a danger too (review X15SIG-3).
pub const ISSUER: &str = "Certum Code Signing 2021 CA";
/// The exe's name in the release list (the installer's name for it, whatever the copy is called).
pub const EXE: &str = "VibeTrace.exe";
/// The uninstaller beside an installed exe.
pub const UNINSTALLER: &str = "uninstall.exe";
/// The most a release list (or its signature) may be.
pub const LIST_CAP: usize = 256 * 1024;
/// The longest the whole fetch may take, the list and its signature together (review RAB-3).
/// WinHTTP's own timeouts bound each step; a peer or proxy that trickles bytes could still
/// stretch the steps out, so the check's worker waits this long and no longer, and the fetcher's
/// read loop stops at it too (`fetch_budget`).
pub const FETCH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// A row's state dot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dot {
    Idle,
    Ok,
    Warn,
    Danger,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub dot: Dot,
    pub text: String,
}

fn row(dot: Dot, text: impl Into<String>) -> Row {
    Row { dot, text: text.into() }
}

/// The three rows, in the order About shows them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rows {
    pub signature: Row,
    pub files: Row,
    pub version: Row,
}

impl Rows {
    /// Before the first check.
    pub fn idle() -> Rows {
        Rows {
            signature: row(Dot::Idle, "Not checked yet."),
            files: row(Dot::Idle, "Not checked yet. Compares each file with the published release."),
            version: row(Dot::Idle, "Not checked yet."),
        }
    }

    /// The check's worker ended without an answer (it should not happen; said, not hidden).
    pub fn stopped() -> Rows {
        let r = row(Dot::Warn, "The check stopped before it finished. Try again.");
        Rows { signature: r.clone(), files: r.clone(), version: r }
    }

    pub fn all(&self) -> [(&'static str, &Row); 3] {
        [("Signature", &self.signature), ("Files", &self.files), ("Version", &self.version)]
    }
}

/// What Windows said of one file's signature (`trust::signature`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sig {
    /// Valid, by this signer.
    Signed(Signer),
    NotSigned,
    /// Signed, but the signature does not hold (why, in words).
    Broken(String),
    Missing,
    /// Windows could not answer (why, in words).
    Unknown(String),
}

/// Who signed a file, from its leaf certificate (`trust::signature`). The publisher pin compares
/// `exact` and `issuer`, the names exactly as the certificate holds them; `name` is for showing
/// only, cleaned, so a look-alike (a no-break space, a doubled space, an invisible mark) never
/// passes as PUBLISHER (review X15SIG-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signer {
    /// The certificate's display name, cleaned for showing.
    pub name: String,
    /// The subject's common name, exactly ("" when it has none).
    pub exact: String,
    /// The issuer's common name, exactly ("" when it has none).
    pub issuer: String,
}

impl From<&str> for Signer {
    /// A signer whose certificate holds exactly `name` and was issued by ISSUER (the tests'
    /// stand-ins; Windows' answers are read by `trust::signature`).
    fn from(name: &str) -> Signer {
        Signer { name: name.into(), exact: name.into(), issuer: ISSUER.into() }
    }
}

/// One file's SHA-256 (`trust::sha256_file`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hash {
    /// Lower-case hex.
    Sha256(String),
    Missing,
    Unreadable(String),
}

/// One file of this copy, by its name in the release list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    pub name: String,
    pub sig: Sig,
    pub hash: Hash,
}

/// This copy as read on the PC: the exe first, then the uninstaller when installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Local {
    pub files: Vec<File>,
    pub portable: bool,
    /// The exe at its path is another file than the one this process started from: it was
    /// updated or replaced while this window was open (the installer renames the running exe
    /// aside, FED3; a hand swap does the same). Its files are then not this version's to compare.
    pub replaced: bool,
}

/// The fetcher's answer (the exe's `net::fetch_release_list`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched {
    /// The list and its `.minisig`, as served (at most LIST_CAP bytes each).
    Got { list: Vec<u8>, sig: Vec<u8> },
    /// No answer from the site (no network, the name not found, a timeout).
    Offline,
    /// The whole fetch took longer than FETCH_DEADLINE.
    TimedOut,
    /// The site answered 404 for the list or its signature.
    NotPublished,
    /// Anything else, in words ("HTTP 500", "the site's certificate didn't check out").
    Failed(String),
}

/// What this build checks against: the app's name in the list, its own version, the list's
/// signing key, the expected code signer, and how long the check waits for the list.
/// `Release::this()` in the app; the tests use their fixture key and app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub app: &'static str,
    pub version: &'static str,
    pub key: &'static str,
    pub publisher: &'static str,
    /// The fetch's deadline: FETCH_DEADLINE (a test's own, shorter one in the window tests).
    pub wait: std::time::Duration,
}

impl Release {
    pub fn this() -> Release {
        Release { app: "VibeTrace", version: crate::VERSION, key: RELEASE_KEY, publisher: PUBLISHER, wait: FETCH_DEADLINE }
    }
}

/// The release list's path on HOST: `/releases/<app in lower case>.json`.
pub fn list_path(app: &str) -> String {
    format!("/releases/{}.json", app.to_ascii_lowercase())
}

/// The only paths the fetcher takes: `/releases/<a-z0-9>.json`. It asks HOST for that one and
/// for the same with `.minisig` after it; a `.minisig` path itself is refused.
pub fn valid_list_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/releases/") else { return false };
    rest.strip_suffix(".json").is_some_and(|s| !s.is_empty() && s.len() <= 40 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
}

/// An HTTP status as the fetcher takes it: 200 goes on; 404 and 410 say the list isn't
/// published; a redirect is refused (they are off in WinHTTP too, review RAB-1); anything else
/// fails with its number.
pub fn http_status(status: u32) -> Result<(), Fetched> {
    match status {
        200 => Ok(()),
        404 | 410 => Err(Fetched::NotPublished),
        300..=399 => Err(Fetched::Failed("the site sent it elsewhere".into())),
        other => Err(Fetched::Failed(format!("HTTP {other}"))),
    }
}

/// Before each request and each piece the fetcher reads: a file of more than LIST_CAP bytes is
/// refused (`len`, what it holds of the file so far), and so is a fetch past FETCH_DEADLINE
/// (`elapsed`, since it began).
pub fn fetch_budget(len: usize, elapsed: std::time::Duration) -> Result<(), Fetched> {
    if len > LIST_CAP {
        return Err(Fetched::Failed("the release list is too big".into()));
    }
    if elapsed >= FETCH_DEADLINE {
        return Err(Fetched::TimedOut);
    }
    Ok(())
}

/// How much the fetcher asks `WinHttpReadData` for: what has come in (`ready`), at most what its
/// buffer holds (`room`), so network bytes never write past it (review RRAB-2).
pub fn read_size(ready: u32, room: usize) -> u32 {
    ready.min(u32::try_from(room).unwrap_or(u32::MAX))
}

// ---------- the release list ----------

/// A verified, parsed release list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List {
    pub latest: String,
    /// version -> file name -> SHA-256 (lower-case hex).
    pub releases: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListError {
    /// The signature is missing, malformed, by another key or does not match the bytes.
    BadSignature,
    /// Signed, but not a list this app can read (why).
    Unreadable(String),
    /// Signed, readable, and for another app (its name, cleaned).
    OtherApp(String),
}

#[derive(serde::Deserialize)]
struct RawList {
    app: String,
    latest: String,
    releases: BTreeMap<String, BTreeMap<String, String>>,
}

/// The list's bytes, believed only when `sig` (a minisign signature file, prehashed) checks out
/// against `key`; then parsed, and `app` must match. Nothing of the bytes is read before the
/// signature holds.
pub fn verify_list(key: &str, list: &[u8], sig: &[u8], app: &str) -> Result<List, ListError> {
    use minisign_verify::{PublicKey, Signature};
    let pk = PublicKey::from_base64(key).map_err(|_| ListError::BadSignature)?;
    let sig = std::str::from_utf8(sig).ok().and_then(|s| Signature::decode(s).ok()).ok_or(ListError::BadSignature)?;
    pk.verify(list, &sig, false).map_err(|_| ListError::BadSignature)?;
    parse_list(list, app)
}

/// A list's contents, once its signature held (installer\release-list.ps1's output is tested
/// with it too): this app's, a version for latest and each release, a SHA-256 for each file.
pub fn parse_list(list: &[u8], app: &str) -> Result<List, ListError> {
    let raw: RawList = serde_json::from_slice(list).map_err(|_| ListError::Unreadable("it isn't valid JSON".into()))?;
    if raw.app != app {
        return Err(ListError::OtherApp(crate::text::clean_max(&raw.app, 40)));
    }
    if version(&raw.latest).is_none() {
        return Err(ListError::Unreadable("its latest version isn't a version number".into()));
    }
    let mut releases = BTreeMap::new();
    for (v, files) in raw.releases {
        if version(&v).is_none() {
            return Err(ListError::Unreadable("a release in it isn't a version number".into()));
        }
        let mut out = BTreeMap::new();
        for (name, hex) in files {
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ListError::Unreadable("a file's hash in it isn't a SHA-256".into()));
            }
            out.insert(name, hex.to_ascii_lowercase());
        }
        releases.insert(v, out);
    }
    Ok(List { latest: raw.latest, releases })
}

/// A version as numbers (`1.2.3`, an optional `-pre` part of dot-separated letters and digits,
/// none of them empty). None for anything else, so a version shown from the list is only ever
/// digits, dots and plain pre-release words.
pub fn version(v: &str) -> Option<([u64; 3], Option<&str>)> {
    if v.len() > 32 {
        return None;
    }
    let (main, pre) = match v.split_once('-') {
        Some((m, p)) if p.split('.').all(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric())) => (m, Some(p)),
        Some(_) => return None,
        None => (v, None),
    };
    let mut n = [0u64; 3];
    let parts: Vec<&str> = main.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        n[i] = p.parse().ok()?;
    }
    Some((n, pre))
}

/// How `a` compares with `b` as versions: the three numbers, then a pre-release before its
/// release, two pre-releases part by part (review RAB-6): digits by their value and before
/// words, words by their text, and the one that runs out first before the other (`beta.9` <
/// `beta.10` < `beta.10.1` < `rc`). installer\release-list.ps1 orders them the same way. None
/// when either isn't a version.
pub fn compare(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    use std::cmp::Ordering;
    let (an, ap) = version(a)?;
    let (bn, bp) = version(b)?;
    // Digits by value without parsing (any length): leading zeros off, then the longer is
    // larger, then the text.
    let part = |x: &str, y: &str| {
        let num = |s: &str| s.bytes().all(|c| c.is_ascii_digit());
        match (num(x), num(y)) {
            (true, true) => {
                let (x, y) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
                x.len().cmp(&y.len()).then(x.cmp(y))
            }
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => x.cmp(y),
        }
    };
    Some(an.cmp(&bn).then(match (ap, bp) {
        (None, None) => Ordering::Equal,
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (Some(x), Some(y)) => {
            let (mut xs, mut ys) = (x.split('.'), y.split('.'));
            loop {
                match (xs.next(), ys.next()) {
                    (None, None) => break Ordering::Equal,
                    (None, Some(_)) => break Ordering::Less,
                    (Some(_), None) => break Ordering::Greater,
                    (Some(p), Some(q)) => match part(p, q) {
                        Ordering::Equal => {}
                        other => break other,
                    },
                }
            }
        }
    }))
}

// ---------- the rows ----------

/// A file's name in a sentence: the uninstaller by what it is, the exe by its name.
fn called(name: &str) -> String {
    if name == UNINSTALLER { "the uninstaller".into() } else { name.to_string() }
}

/// The same at the start of a sentence.
fn called_first(name: &str) -> String {
    let c = called(name);
    let mut ch = c.chars();
    match ch.next() {
        Some(f) => f.to_uppercase().chain(ch).collect(),
        None => c,
    }
}

/// "A", "A and B".
fn and(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [a] => a.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The three rows for this copy, its files and what the fetcher brought.
pub fn rows(release: &Release, local: &Local, fetched: Fetched) -> Rows {
    let signature = signature_row(release.publisher, &local.files);
    let (files, version) = match fetched {
        Fetched::Offline => (
            row(Dot::Idle, "Couldn't reach the release list, so the files weren't compared. The signature check still ran."),
            row(Dot::Idle, "Not known while offline."),
        ),
        Fetched::TimedOut => (
            row(Dot::Idle, "The release list took too long to answer, so the files weren't compared. The signature check still ran."),
            row(Dot::Idle, "Not known: the release list took too long to answer."),
        ),
        Fetched::NotPublished => (row(Dot::Idle, "The release list isn't published yet, so the files weren't compared."), row(Dot::Idle, "Not known until the release list is published.")),
        Fetched::Failed(why) => (
            row(Dot::Idle, format!("The release list couldn't be fetched ({}), so the files weren't compared.", crate::text::clean_max(&why, 80))),
            row(Dot::Idle, "Not known: the release list couldn't be fetched."),
        ),
        Fetched::Got { list, sig } => match verify_list(release.key, &list, &sig, release.app) {
            Err(ListError::BadSignature) => (row(Dot::Danger, "The release list didn't pass its signature check, so it was ignored."), row(Dot::Idle, "Not known: the release list was ignored.")),
            Err(ListError::OtherApp(other)) => (row(Dot::Danger, format!("The release list is for another app ({other}), so it was ignored.")), row(Dot::Idle, "Not known: the release list was ignored.")),
            Err(ListError::Unreadable(why)) => (row(Dot::Warn, format!("The release list couldn't be read ({why}), so the files weren't compared.")), row(Dot::Idle, "Not known: the release list couldn't be read.")),
            Ok(list) => (files_row(release.version, local, &list), version_row(release.version, &list)),
        },
    };
    Rows { signature, files, version }
}

/// The rows when the exe was updated or replaced under the running one (`Local::replaced`): the
/// files on disk are another copy's, so comparing them with this one's entry would call a
/// healthy install damaged (FED3). Said as a replacement, never as a newer version: the same
/// version installed again, an older one, or a portable copy swapped by hand are replacements too
/// (RVD6). Windows' signature check of the files still runs; nothing is fetched or compared.
pub fn replaced_rows(release: &Release, local: &Local) -> Rows {
    Rows {
        signature: signature_row(release.publisher, &local.files),
        files: row(Dot::Idle, format!("{0} was updated or replaced while this window was open. Restart {0} to check the files now in place.", release.app)),
        version: row(Dot::Idle, format!("Not known until {} restarts.", release.app)),
    }
}

/// The Signature row: Windows' answer for every file, the worst first.
pub fn signature_row(publisher: &str, files: &[File]) -> Row {
    // A loose copy (review AF2-3): no uninstaller beside the exe, so the exe alone is judged,
    // as in a portable copy.
    let files: Vec<&File> = files.iter().filter(|f| !(f.name == UNINSTALLER && f.sig == Sig::Missing)).collect();
    if let Some((f, why)) = files.iter().find_map(|f| if let Sig::Broken(w) = &f.sig { Some((f, w)) } else { None }) {
        return row(Dot::Danger, format!("{}'s signature is broken: {why}.", called_first(&f.name)));
    }
    if !publisher.is_empty()
        && let Some(s) = files.iter().find_map(|f| if let Sig::Signed(s) = &f.sig { (s.exact != publisher || s.issuer != ISSUER).then_some(s) } else { None })
    {
        let why = if s.exact != publisher && s.name == publisher {
            format!("Signed by a name that only looks like {publisher}, so this isn't the published app.")
        } else if s.exact != publisher {
            format!("Signed by {}, not by {publisher}, so this isn't the published app.", s.name)
        } else {
            format!("Signed by {}, but the certificate isn't from {ISSUER}, so this isn't the published app.", s.name)
        };
        return row(Dot::Danger, why);
    }
    if let Some((f, why)) = files.iter().find_map(|f| if let Sig::Unknown(w) = &f.sig { Some((f, w)) } else { None }) {
        return row(Dot::Warn, format!("Windows couldn't check {}'s signature: {why}.", called(&f.name)));
    }
    if let Some(f) = files.iter().find(|f| f.sig == Sig::Missing) {
        return row(Dot::Warn, format!("{} is missing, so its signature wasn't checked.", called_first(&f.name)));
    }
    let signers: Vec<&String> = files.iter().filter_map(|f| if let Sig::Signed(s) = &f.sig { Some(&s.name) } else { None }).collect();
    let unsigned: Vec<String> = files.iter().filter(|f| f.sig == Sig::NotSigned).map(|f| called(&f.name)).collect();
    if signers.is_empty() {
        return row(Dot::Warn, "Not signed yet, so Windows can't vouch for this copy.");
    }
    if !unsigned.is_empty() {
        return row(Dot::Warn, format!("Only part of this install is signed: {} isn't.", and(&unsigned)));
    }
    if signers.iter().any(|n| *n != signers[0]) {
        let mut names: Vec<String> = signers.iter().map(|n| n.to_string()).collect();
        names.dedup();
        return row(Dot::Warn, format!("Signed by {}: its files have different publishers.", and(&names)));
    }
    // No "just now": a kept answer is shown again when About reopens (review RAB-7).
    row(Dot::Ok, format!("Signed by {}. Windows checked the signature.", signers[0]))
}

/// The Files row: each file's SHA-256 against the running version's entry in the list.
pub fn files_row(running: &str, local: &Local, list: &List) -> Row {
    let Some(entry) = list.releases.get(running) else {
        return row(Dot::Warn, format!("Version {running} isn't in the release list (a build that wasn't published, say), so the files weren't compared."));
    };
    let fix = if local.portable { "Get a fresh copy from the website; your settings stay." } else { "Reinstall it from the website; your settings stay." };
    let mut differ = Vec::new();
    let mut missing = Vec::new();
    let mut unreadable = Vec::new();
    let mut unlisted = Vec::new();
    for f in &local.files {
        match (&f.hash, entry.get(&f.name)) {
            (Hash::Missing, _) => missing.push(f.name.clone()),
            (Hash::Unreadable(why), _) => unreadable.push((f.name.clone(), why.clone())),
            (Hash::Sha256(_), None) => unlisted.push(called(&f.name)),
            (Hash::Sha256(h), Some(want)) if !h.eq_ignore_ascii_case(want) => differ.push(f.name.clone()),
            _ => {}
        }
    }
    // A loose copy (review AF2-2): an installed exe copied out without its uninstaller. When the
    // uninstaller is all that's missing, the exe alone is compared, and a match is fine; an exe
    // that doesn't match is a danger as before.
    let loose = differ.is_empty() && missing == [UNINSTALLER];
    if loose {
        missing.clear();
    }
    if !differ.is_empty() || !missing.is_empty() {
        let differ_part = match differ.as_slice() {
            [] => None,
            [one] => Some(format!("{} doesn't match release {running}", called_first(one))),
            many => Some(format!("Neither {} matches release {running}", and(&many.iter().map(|n| called(n)).collect::<Vec<_>>()).replacen(" and ", " nor ", 1))),
        };
        let missing_part = (!missing.is_empty()).then(|| {
            let names: Vec<String> = missing.iter().map(|n| called(n)).collect();
            format!("{} {} missing", and(&names), if names.len() == 1 { "is" } else { "are" })
        });
        let said = match (differ_part, missing_part) {
            (Some(d), Some(m)) => format!("{d}, and {m}."),
            (Some(d), None) => format!("{d}."),
            (None, Some(m)) => {
                let mut c = m.chars();
                let first: String = c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default();
                format!("{first}.")
            }
            (None, None) => unreachable!("one of them is set"),
        };
        return row(Dot::Danger, format!("{said} {fix}"));
    }
    if let Some((name, why)) = unreadable.first() {
        return row(Dot::Warn, format!("{} couldn't be read to compare it ({}).", called_first(name), crate::text::clean_max(why, 80)));
    }
    if !unlisted.is_empty() {
        return row(Dot::Warn, format!("The release list has nothing for {} in {running}, so it wasn't compared.", and(&unlisted)));
    }
    match local.files.as_slice() {
        [one] => row(Dot::Ok, format!("{} matches release {running}.", one.name)),
        [exe, _] if loose => row(Dot::Ok, format!("{} matches release {running}. No uninstaller beside it, so only the exe was compared.", exe.name)),
        [exe, _] => row(Dot::Ok, format!("Both files match release {running} ({} and the uninstaller).", exe.name)),
        _ => row(Dot::Ok, format!("Every file matches release {running}.")),
    }
}

/// The Version row: the running version against the list's latest.
pub fn version_row(running: &str, list: &List) -> Row {
    use std::cmp::Ordering;
    match compare(&list.latest, running) {
        Some(Ordering::Equal) => row(Dot::Ok, format!("{running} is the latest.")),
        Some(Ordering::Greater) => row(Dot::Warn, format!("{} is out. Get it from getvibeware.com.", list.latest)),
        Some(Ordering::Less) => row(Dot::Idle, format!("{running} is newer than the latest release ({}).", list.latest)),
        None => row(Dot::Idle, format!("{running} can't be compared with the release list's latest.")),
    }
}
