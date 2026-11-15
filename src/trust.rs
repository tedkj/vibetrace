//! The install check's offline half: what Windows says of a file's signature, and a file's
//! SHA-256. Both block (they read the whole file): call them from the check's worker only.
//!
//! The signature is `WinVerifyTrust` with the generic Authenticode policy, no UI, no revocation
//! check and URL retrieval from the cache only, so it never goes online; the signer's name is
//! read from the verified chain (VibeBoot's `autostart/signer.rs`, cut down: the app's own files
//! carry their signature, so no catalog lookup). The hash is BCrypt's SHA-256, no crate.
//! The flags are set in `offline_verify`, which a unit test reads; tests/pe.rs pins by this file's
//! tokens that they are set there only and that `signature` hands its result straight to the
//! call, and the state's close and the leaf (review RAB-1, RRAB-2): a test that dropped the cache-only
//! flag could go online, so it is never run that way.

use crate::check::{File, Hash, Local, Sig, Signer};
use std::path::Path;

/// This copy's files: the exe at `exe` (`own_exe`) and, when installed, `uninstall.exe` beside
/// it; and whether the exe there is still the one this process started from (FED3). `started` is
/// that file's identity as the process started (`exe_identity`, taken in `Services::system` and
/// handed to every check), an input so a test can swap the file under it (review RVD7). The
/// identity is read again after the files are hashed: an install that lands while they are read
/// is a replacement too, never damaged files.
pub fn inspect_from(started: Option<(u32, u64)>, exe: &Path, installed: bool) -> Local {
    let mut files = vec![(crate::check::EXE, exe.to_path_buf())];
    if installed && let Some(dir) = exe.parent() {
        files.push((crate::check::UNINSTALLER, dir.join(crate::check::UNINSTALLER)));
    }
    let before = identity(exe);
    let files = files.into_iter().map(|(name, path)| File { name: name.into(), sig: signature(&path), hash: sha256_file(&path) }).collect();
    let after = identity(exe);
    Local { files, portable: !installed, replaced: replaced(started, before, after) }
}

/// The exe's path as Windows started it: the app has no portable mode, so no
/// `portable::final_path`. Windows keeps the name a process was started by even when its file
/// is renamed, so after an update this names the new exe, not the running one.
pub fn own_exe() -> std::path::PathBuf {
    std::env::current_exe().unwrap_or_default()
}

/// A file's identity: its volume's serial number and its file index. It stays with the file
/// through a rename; a new file under the name has another. None when it cannot be read.
pub fn identity(path: &Path) -> Option<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
    let f = std::fs::File::open(path).ok()?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: an open file's handle and a structure of the size the call writes.
    let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) } != 0;
    ok.then(|| (info.dwVolumeSerialNumber, (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow)))
}

/// The exe's identity now, read twice (`steady_identity`). `controller::Services::system` takes it
/// at start, before an install could replace the exe, and hands that value to every check
/// (`inspect_from`).
pub fn exe_identity() -> Option<(u32, u64)> {
    let exe = own_exe();
    steady_identity(identity(&exe), identity(&exe))
}

/// Two reads of one file's identity, kept only when they agree (review RVD2, "Not covered"): a
/// file system that makes up a file index on every open (a network redirector, say) gives the
/// running exe no identity to go by, so it is unknown, and an unknown start never says
/// "replaced" (`replaced`), which such a file system would otherwise say on every check, after a
/// restart too.
pub fn steady_identity(first: Option<(u32, u64)>, second: Option<(u32, u64)>) -> Option<(u32, u64)> {
    if first == second { first } else { None }
}

/// The exe at its path is another file than the one this process started from: it was updated
/// or replaced while the app ran (the installer renames the running exe to `.exe.old` and puts
/// the new one in its place). `before` and `after`: the identity read before and after the files
/// are hashed, so an install that lands meanwhile counts too (RVD7). With the start identity known,
/// any two known identities that differ: replaced. Unknown: not replaced (the check then compares
/// as before, and a missing exe is said by the Files row); an unknown start identity too, since
/// the reads after it are only worth what that file system's identities are worth.
pub fn replaced(started: Option<(u32, u64)>, before: Option<(u32, u64)>, after: Option<(u32, u64)>) -> bool {
    if started.is_none() {
        return false;
    }
    let known: Vec<(u32, u64)> = [started, before, after].into_iter().flatten().collect();
    known.windows(2).any(|w| w[0] != w[1])
}

/// A file's SHA-256, read in 64 KiB pieces.
pub fn sha256_file(path: &Path) -> Hash {
    use std::io::Read;
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Hash::Missing,
        Err(e) => return Hash::Unreadable(crate::text::clean_max(&e.to_string(), 80)),
    };
    let mut h = match Sha256::new() {
        Some(h) => h,
        None => return Hash::Unreadable("Windows' SHA-256 isn't available".into()),
    };
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if !h.update(&buf[..n]) {
                    return Hash::Unreadable("Windows' SHA-256 failed".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Hash::Unreadable(crate::text::clean_max(&e.to_string(), 80)),
        }
    }
    match h.finish() {
        Some(d) => Hash::Sha256(d.iter().map(|b| format!("{b:02x}")).collect()),
        None => Hash::Unreadable("Windows' SHA-256 failed".into()),
    }
}

/// BCrypt's SHA-256 on its pseudo-handle (no provider to open or close).
struct Sha256(windows_sys::Win32::Security::Cryptography::BCRYPT_HASH_HANDLE);

impl Sha256 {
    fn new() -> Option<Sha256> {
        use windows_sys::Win32::Security::Cryptography::{BCRYPT_SHA256_ALG_HANDLE, BCryptCreateHash};
        let mut h = std::ptr::null_mut();
        // SAFETY: an out pointer for the handle; BCrypt allocates the hash object itself.
        let s = unsafe { BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &mut h, std::ptr::null_mut(), 0, std::ptr::null(), 0, 0) };
        (s >= 0 && !h.is_null()).then_some(Sha256(h))
    }

    fn update(&mut self, data: &[u8]) -> bool {
        use windows_sys::Win32::Security::Cryptography::BCryptHashData;
        // SAFETY: a live hash handle and a buffer of the length given (at most 64 KiB here).
        unsafe { BCryptHashData(self.0, data.as_ptr(), data.len() as u32, 0) >= 0 }
    }

    fn finish(self) -> Option<[u8; 32]> {
        use windows_sys::Win32::Security::Cryptography::BCryptFinishHash;
        let mut out = [0u8; 32];
        // SAFETY: a live hash handle and a 32-byte buffer, SHA-256's size.
        let ok = unsafe { BCryptFinishHash(self.0, out.as_mut_ptr(), 32, 0) } >= 0;
        ok.then_some(out)
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        // SAFETY: the handle made in `new`, destroyed once.
        unsafe { windows_sys::Win32::Security::Cryptography::BCryptDestroyHash(self.0) };
    }
}

// WinVerifyTrust's answers (HRESULTs as u32), as VibeBoot reads them.
const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
const TRUST_E_SUBJECT_FORM_UNKNOWN: u32 = 0x800B_0003;
const TRUST_E_PROVIDER_UNKNOWN: u32 = 0x800B_0001;
const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
const CERT_E_EXPIRED: u32 = 0x800B_0101;
const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
const CERT_E_CHAINING: u32 = 0x800B_010A;
const CERT_E_REVOKED: u32 = 0x800B_010C;
const CERT_E_UNTRUSTEDTESTROOT: u32 = 0x800B_010D;
const CRYPT_E_FILE_ERROR: u32 = 0x8009_2003;
const CRYPT_E_REVOKED: u32 = 0x8009_2010;

/// A WinVerifyTrust answer as a `Sig`. Pure, so every code is tested.
pub fn classify(code: u32, signer: Option<Signer>) -> Sig {
    match code {
        0 => Sig::Signed(signer.unwrap_or_else(|| Signer { name: "an unnamed publisher".into(), exact: String::new(), issuer: String::new() })),
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => Sig::NotSigned,
        TRUST_E_BAD_DIGEST => Sig::Broken("the file was changed after it was signed".into()),
        TRUST_E_EXPLICIT_DISTRUST => Sig::Broken("the certificate is blocked on this PC".into()),
        CERT_E_REVOKED | CRYPT_E_REVOKED => Sig::Broken("the certificate was revoked".into()),
        CERT_E_EXPIRED => Sig::Broken("the certificate expired and the signature has no timestamp".into()),
        CERT_E_UNTRUSTEDROOT | CERT_E_UNTRUSTEDTESTROOT | CERT_E_CHAINING => Sig::Broken(format!("Windows doesn't trust the certificate{}", signer.map(|s| format!(" ({})", s.name)).unwrap_or_default())),
        CRYPT_E_FILE_ERROR => Sig::Unknown("Windows couldn't read the file".into()),
        other => Sig::Broken(format!("Windows refused it (0x{other:08X})")),
    }
}

/// What Windows says of `path`'s own signature, offline.
pub fn signature(path: &Path) -> Sig {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::WinTrust::*;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Sig::Missing,
        Err(e) => return Sig::Unknown(crate::text::clean_max(&e.to_string(), 80)),
    };
    let wide = crate::host::wide_path(path);
    let mut info = WINTRUST_FILE_INFO { cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32, pcwszFilePath: wide.as_ptr(), hFile: file.as_raw_handle(), pgKnownSubject: std::ptr::null_mut() };
    let mut data = offline_verify(&mut info);
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` points at `info`, which points at `wide` and the open file; all outlive both
    // calls, and the state the first call opens is closed by the second.
    let (code, signer) = unsafe {
        let code = WinVerifyTrust(std::ptr::null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast()) as u32;
        let signer = signer_name(data.hWVTStateData);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(std::ptr::null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast());
        (code, signer)
    };
    classify(code, signer)
}

/// The verify's settings for `info`'s file, all made before WinVerifyTrust sees them (review
/// RRAB-2): no UI, no revocation check, URLs from the cache only, so it never goes online. Pure,
/// so a unit test reads them; tests/pe.rs pins that `signature` hands this straight to the call.
fn offline_verify(info: &mut windows_sys::Win32::Security::WinTrust::WINTRUST_FILE_INFO) -> windows_sys::Win32::Security::WinTrust::WINTRUST_DATA {
    use windows_sys::Win32::Security::WinTrust::*;
    let mut data = WINTRUST_DATA { dwUnionChoice: WTD_CHOICE_FILE, ..Default::default() };
    data.Anonymous.pFile = info;
    data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data
}

/// Who signed, from a verified trust state (the first signer's leaf certificate): its display
/// name cleaned for showing, and its subject's and issuer's common names exactly as the
/// certificate holds them, for the publisher pin (review X15SIG-3). No display name: None.
unsafe fn signer_name(state: windows_sys::Win32::Foundation::HANDLE) -> Option<Signer> {
    use windows_sys::Win32::Security::Cryptography::{CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW, szOID_COMMON_NAME};
    use windows_sys::Win32::Security::WinTrust::{WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData};
    // SAFETY: pointers from WinVerifyTrust's own state, checked for null at each step.
    unsafe {
        if state.is_null() {
            return None;
        }
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
            return None;
        }
        let cert = (*(*sgnr).pasCertChain).pCert;
        if cert.is_null() {
            return None;
        }
        // One name of `cert` as UTF-16 without its NUL; empty when there is none, or when it
        // doesn't fit (a cut name could match a pin it doesn't hold).
        let read = |kind: u32, flags: u32, para: *const core::ffi::c_void| -> Vec<u16> {
            let mut buf = [0u16; 512];
            // `cert` is the chain's own context, valid while the state is open (the SAFETY above);
            // the buffer's length is passed with it.
            let n = CertGetNameStringW(cert, kind, flags, para, buf.as_mut_ptr(), buf.len() as u32) as usize;
            if n <= 1 || n >= buf.len() { Vec::new() } else { buf[..n - 1].to_vec() }
        };
        let name = crate::text::clean_wide(&read(CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null()), 120);
        if name.is_empty() {
            return None;
        }
        let cn = szOID_COMMON_NAME as *const core::ffi::c_void;
        let exact = String::from_utf16_lossy(&read(CERT_NAME_ATTR_TYPE, 0, cn));
        let issuer = String::from_utf16_lossy(&read(CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG, cn));
        Some(Signer { name, exact, issuer })
    }
}
