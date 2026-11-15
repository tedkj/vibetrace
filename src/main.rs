// VibeTrace: one process, no browser engine, the software renderer.
#![windows_subsystem = "windows"]

use slint::ComponentHandle;

/// The real release-list fetcher (WinHTTP), the exe's alone: it is in no test build, not the
/// lib's, not the integration tests', not this exe's own unit tests', so no test can go online
/// (review RAB-2; tests/pe.rs checks this line).
#[cfg(not(test))]
mod net;

/// The window's Win32 handle, for `host::fit_to_work_area`.
fn hwnd_of(w: &slint::winit_030::winit::window::Window) -> Option<isize> {
    use slint::winit_030::winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match w.window_handle().ok()?.as_raw() {
        RawWindowHandle::Win32(h) => Some(h.hwnd.get()),
        _ => None,
    }
}

fn main() -> Result<(), slint::PlatformError> {
    // DLL hardening, first of all (VibeLink LINK-1): every DLL loaded from here on comes from
    // System32, never from the exe's own folder (the per-user install folder, which the user's
    // own programs can write). The static imports are covered by the link flag
    // /DEPENDENTLOADFLAG:0x800 (build.rs).
    // SAFETY: a process-wide setting with a valid flag; nothing has been loaded by name yet.
    unsafe {
        use windows_sys::Win32::System::LibraryLoader::{LOAD_LIBRARY_SEARCH_SYSTEM32, SetDefaultDllDirectories};
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    // No Windows "No Disk" box: a file call on an empty card reader or drive gets its error back
    // instead of a modal box (review fix-popup, RX1). tests/pe.rs checks this block comes next.
    // SAFETY: a process-wide setting with a valid flag, the bits already set kept.
    unsafe {
        use windows_sys::Win32::System::Diagnostics::Debug::{GetErrorMode, SEM_FAILCRITICALERRORS, SetErrorMode};
        SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS);
    }
    // The command line is `VibeTrace.exe [<host>]` (target_arg, read with args_os): anything else
    // ends the process before any window or file (exit code 2). Files dropped on the exe are
    // never a host (launch.rs, told by their shape): only those open the window with a toast,
    // and one beside anything else is exit 2 too.
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let (target, left_alone) = match vibetrace::launch::dropped(args.get(1..).unwrap_or_default()) {
        vibetrace::launch::Dropped::No => match vibetrace::target_arg(args.into_iter()) {
            Ok(target) => (target, None),
            Err(_) => std::process::exit(2),
        },
        vibetrace::launch::Dropped::Files(note) => (None, Some(note)),
        vibetrace::launch::Dropped::Mixed => std::process::exit(2),
    };
    #[allow(unused_mut)]
    let mut paths = vibetrace::host::paths();
    // Live checks and measurements only: the app's folders in a place of the developer's choosing,
    // so nothing touches the real profile. Never in a shipped build.
    #[cfg(feature = "dev-hooks")]
    if let Some(home) = std::env::var_os("VIBETRACE_DEV_HOME").map(std::path::PathBuf::from) {
        paths = vibetrace::host::Paths { config: home.join("config"), local_data: home.join("local") };
    }
    // The probe hands back the value it was asked about, and `main` goes on with that one only: the
    // old binding is gone (`dev_probe`, review RRF-2).
    #[cfg(feature = "dev-hooks")]
    let paths = dev_probe(paths);
    let prefs = vibetrace::prefs::Store::new(paths.config.join("prefs.json"));
    let ui = vibetrace::window(prefs.clone())?;
    // The one place that names the real release-list fetcher (tests/pe.rs checks it): every test
    // hands the controller a fake, so no test goes online. This exe's unit-test build has no
    // `net` and never runs `main`: it gets a stand-in that fetches nothing.
    #[cfg(not(test))]
    let fetch = std::sync::Arc::new(net::fetch_release_list);
    #[cfg(test)]
    let fetch = std::sync::Arc::new(|_: &str| vibetrace::check::Fetched::Failed("a test build has no fetcher".into()));
    let app = vibetrace::controller::App::attach(&ui, prefs.clone(), vibetrace::controller::Services::system(paths.local_data.join("logs"), fetch));
    // `VibeTrace.exe <host>` traces it at once.
    if let Some(target) = target {
        ui.set_target(target.as_str().into());
        app.start(&target);
    }
    if let Some(note) = left_alone {
        app.toast(&note, vibetrace::ToastKind::Info, None);
    }
    // The loop runs on while the window hides in the tray (an ISP log); closing the window
    // (or Quit in the tray) ends it.
    ui.window().on_close_requested(|| {
        let _ = slint::quit_event_loop();
        slint::CloseRequestResponse::HideWindow
    });
    // The window opens at its preferred size; on a small or highly scaled screen that runs past
    // the taskbar, so the first window event once it is on screen fits it into the monitor's work
    // area (X15A11Y-3), once.
    let fitted = std::cell::Cell::new(false);
    {
        use slint::winit_030::{EventResult, WinitWindowAccessor};
        use vibetrace::host;
        ui.window().on_winit_window_event(move |window, _| {
            if !fitted.get() && window.with_winit_window(hwnd_of).flatten().and_then(host::fit_to_work_area).is_some() {
                fitted.set(true);
            }
            EventResult::Propagate
        });
    }
    ui.show()?;
    let ran = slint::run_event_loop_until_quit();
    app.stop(); // the log's last minute goes to its thread
    app.finish_log(); // and is on disk before the process goes
    app.finish_prefs(); // a change from the last moments, still on its way to disk
    ran
}

/// Live checks only (review RRE-5, RRF-2): with VIBETRACE_DEV_PROBE set, `main` writes the
/// app's data folders, one a line on stdout, and ends (exit 0) right after the dev home, before
/// any of them is used and before any window. Else it hands back the value it was given,
/// unchanged, and `main` goes on with it (`let paths = dev_probe(paths);`), so the folders the
/// probe names are the ones `main` uses. tests/pe.rs asks this before it starts the exe for real
/// (`run_exe`): every folder must be inside the scratch dev home it gave, so an override that is
/// gone, compiled out or too late fails there, by what the exe does.
#[cfg(feature = "dev-hooks")]
fn dev_probe(paths: vibetrace::host::Paths) -> vibetrace::host::Paths {
    use std::io::Write;
    if std::env::var_os("VIBETRACE_DEV_PROBE").is_some() {
        let mut out = std::io::stdout().lock();
        for f in [&paths.config, &paths.local_data] {
            let _ = writeln!(out, "{}", f.display());
        }
        let _ = out.flush();
        std::process::exit(0);
    }
    paths
}
