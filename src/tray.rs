//! The tray icon while an ISP log runs minimised (SPEC §9.5): VibeBackup's pattern, copied.
//! Shell_NotifyIconW on a small hidden window of the UI thread (winit's message pump
//! dispatches its messages along with the app's own). Its colour follows the log; left click
//! brings the window back, right click a native menu. No balloons.
//!
//! The window is a hidden tool window, not a message-only one: a context menu only closes on an
//! outside click when its owner can be the foreground window, and only top-level windows hear
//! "TaskbarCreated" (Explorer restarted: add the icon again). Neither works on HWND_MESSAGE.
//!
//! Windows ending the session is heard by `SessionEnd`, a hidden window of its own that lives as
//! long as the app, whatever is on screen: winit does not pass WM_ENDSESSION on, and the tray's
//! window exists only while the app sits in the tray (R-5).

use std::cell::RefCell;
use std::collections::HashMap;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::UI::Shell::{NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NIN_SELECT, NOTIFYICON_VERSION_4, NOTIFYICONDATAW, Shell_NotifyIconW};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

/// How the log stands, as the icon's colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// Logging, all well: the mark's own signal blue.
    Logging,
    /// The DNS checks fail: amber.
    Dns,
    /// An outage now: red.
    Outage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Left click (or Enter on the icon): the window comes back.
    Open,
    /// Right click: the menu.
    Menu,
    /// The tray's window is asked to close (WM_CLOSE): leave cleanly.
    Quit,
}

const CALLBACK: u32 = WM_APP + 1;
const NIN_KEYSELECT: u32 = NIN_SELECT | 1;

/// Each tray window's handler, by its hwnd.
type Handlers = HashMap<usize, std::rc::Rc<dyn Fn(Event)>>;

thread_local! {
    static HANDLERS: RefCell<Handlers> = RefCell::new(HashMap::new());
    static TASKBAR_CREATED: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static READD: RefCell<HashMap<usize, Box<dyn Fn()>>> = RefCell::new(HashMap::new());
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == CALLBACK {
        let ev = match (lp & 0xffff) as u32 {
            NIN_SELECT | NIN_KEYSELECT | WM_LBUTTONUP => Some(Event::Open),
            WM_CONTEXTMENU | WM_RBUTTONUP => Some(Event::Menu),
            _ => None,
        };
        if let Some(ev) = ev {
            // Called back after this message, not inside it: the handler may run a modal menu.
            let key = hwnd as usize;
            slint::Timer::single_shot(std::time::Duration::ZERO, move || {
                // The handler is called with the map let go: it may drop this very tray (the
                // window comes back), whose Drop takes the map again.
                if let Some(f) = handler(key) {
                    f(ev);
                }
            });
        }
        return 0;
    }
    if msg == WM_CLOSE {
        if let Some(f) = handler(hwnd as usize) {
            f(Event::Quit);
        }
        return 0;
    }
    if msg != 0 && msg == TASKBAR_CREATED.with(|t| t.get()) {
        let key = hwnd as usize;
        READD.with(|r| {
            if let Some(f) = r.borrow().get(&key) {
                f();
            }
        });
        return 0;
    }
    unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
}

thread_local! {
    static ON_END: RefCell<HashMap<usize, std::rc::Rc<dyn Fn()>>> = RefCell::new(HashMap::new());
}

unsafe extern "system" fn session_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        // Yes, the session may end (the log is written when it does).
        WM_QUERYENDSESSION => 1,
        WM_ENDSESSION => {
            // Windows may end the process as soon as this returns: the handler writes first.
            if wp != 0
                && let Some(f) = ON_END.with(|m| m.borrow().get(&(hwnd as usize)).cloned())
            {
                f();
            }
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wp, lp) },
    }
}

/// A hidden top-level window that hears Windows ending the session (logging off, shutting
/// down, a restart for updates) for as long as it lives, whatever is on screen. Top-level, not
/// message-only: Windows sends WM_QUERYENDSESSION / WM_ENDSESSION to top-level windows only.
/// Never shown.
pub struct SessionEnd {
    hwnd: HWND,
}

impl SessionEnd {
    /// `handler` runs inside WM_ENDSESSION (the session really ends), on the UI thread.
    pub fn new(handler: impl Fn() + 'static) -> Option<SessionEnd> {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        let class = crate::host::wide("VibeTraceSession");
        unsafe {
            let inst = GetModuleHandleW(std::ptr::null());
            let wc = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                lpfnWndProc: Some(session_proc),
                hInstance: inst,
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            RegisterClassExW(&wc); // fails harmlessly when already registered
            let hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, class.as_ptr(), class.as_ptr(), WS_POPUP, 0, 0, 0, 0, std::ptr::null_mut(), std::ptr::null_mut(), inst, std::ptr::null());
            if hwnd.is_null() {
                return None;
            }
            ON_END.with(|m| m.borrow_mut().insert(hwnd as usize, std::rc::Rc::new(handler)));
            Some(SessionEnd { hwnd })
        }
    }

    /// Its window (tests send it the messages).
    pub fn hwnd(&self) -> HWND {
        self.hwnd
    }
}

impl Drop for SessionEnd {
    fn drop(&mut self) {
        ON_END.with(|m| m.borrow_mut().remove(&(self.hwnd as usize)));
        unsafe { DestroyWindow(self.hwnd) };
    }
}

/// The handler of the tray window `key`, out of the map (never called while it is borrowed).
fn handler(key: usize) -> Option<std::rc::Rc<dyn Fn(Event)>> {
    HANDLERS.with(|h| h.borrow().get(&key).cloned())
}

pub struct Tray {
    hwnd: HWND,
    icons: RefCell<HashMap<State, HICON>>,
    state: std::cell::Cell<State>,
    tip: RefCell<String>,
    size: i32,
}

fn copy_into(dst: &mut [u16], s: &str) {
    let w: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
    dst[..w.len()].copy_from_slice(&w);
    dst[w.len()] = 0;
}

impl Tray {
    /// Add the icon. `handler` hears clicks (on the UI thread).
    pub fn new(state: State, tip: &str, handler: impl Fn(Event) + 'static) -> Option<std::rc::Rc<Tray>> {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        let class = crate::host::wide("VibeTraceTray");
        unsafe {
            let inst = GetModuleHandleW(std::ptr::null());
            let wc = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                lpfnWndProc: Some(wndproc),
                hInstance: inst,
                lpszClassName: class.as_ptr(),
                ..std::mem::zeroed()
            };
            RegisterClassExW(&wc); // fails harmlessly when already registered
            let hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, class.as_ptr(), class.as_ptr(), WS_POPUP, 0, 0, 0, 0, std::ptr::null_mut(), std::ptr::null_mut(), inst, std::ptr::null());
            if hwnd.is_null() {
                return None;
            }
            TASKBAR_CREATED.with(|t| t.set(RegisterWindowMessageW(crate::host::wide("TaskbarCreated").as_ptr())));
            let size = GetSystemMetrics(SM_CXSMICON).clamp(16, 64);
            let tray = std::rc::Rc::new(Tray { hwnd, icons: RefCell::new(HashMap::new()), state: std::cell::Cell::new(state), tip: RefCell::new(tip.to_string()), size });
            HANDLERS.with(|h| h.borrow_mut().insert(hwnd as usize, std::rc::Rc::new(handler)));
            let weak = std::rc::Rc::downgrade(&tray);
            READD.with(|r| {
                r.borrow_mut().insert(
                    hwnd as usize,
                    Box::new(move || {
                        if let Some(t) = weak.upgrade() {
                            t.add();
                        }
                    }),
                )
            });
            tray.add();
            Some(tray)
        }
    }

    fn data(&self) -> NOTIFYICONDATAW {
        let mut d: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
        d.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        d.hWnd = self.hwnd;
        d.uID = 1;
        d
    }

    fn icon(&self, s: State) -> HICON {
        *self.icons.borrow_mut().entry(s).or_insert_with(|| make_icon(s, self.size))
    }

    fn add(&self) {
        let mut d = self.data();
        d.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        d.uCallbackMessage = CALLBACK;
        d.hIcon = self.icon(self.state.get());
        copy_into(&mut d.szTip, &self.tip.borrow());
        unsafe {
            Shell_NotifyIconW(NIM_ADD, &d);
            d.Anonymous.uVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIconW(NIM_SETVERSION, &d);
        }
    }

    /// Colour and tooltip. One HICON per state, made once (a new one per update leaks GDI
    /// handles: NasBackup crashed of that). If the shell lost the icon, it is added again.
    pub fn set(&self, s: State, tip: &str) {
        if self.state.get() == s && *self.tip.borrow() == tip {
            return;
        }
        self.state.set(s);
        *self.tip.borrow_mut() = tip.to_string();
        let mut d = self.data();
        d.uFlags = NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        d.hIcon = self.icon(s);
        copy_into(&mut d.szTip, tip);
        if unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) } == 0 {
            self.add();
        }
    }

    /// A native menu at the pointer; the chosen entry's id, or None. Entries: (id, label);
    /// id 0 is a separator; the first entry is the default (bold).
    pub fn menu(&self, entries: &[(u32, String)]) -> Option<u32> {
        unsafe {
            let m = CreatePopupMenu();
            for (id, label) in entries {
                if *id == 0 {
                    AppendMenuW(m, MF_SEPARATOR, 0, std::ptr::null());
                    continue;
                }
                let w = crate::host::wide(label);
                AppendMenuW(m, MF_STRING, *id as usize, w.as_ptr());
            }
            if let Some((id, ..)) = entries.first() {
                SetMenuDefaultItem(m, *id, 0);
            }
            let mut p = POINT { x: 0, y: 0 };
            GetCursorPos(&mut p);
            SetForegroundWindow(self.hwnd);
            let id = TrackPopupMenu(m, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, p.x, p.y, 0, self.hwnd, std::ptr::null());
            PostMessageW(self.hwnd, WM_NULL, 0, 0); // (the documented way to let the menu go)
            DestroyMenu(m);
            if id > 0 { Some(id as u32) } else { None }
        }
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        let d = self.data();
        unsafe {
            Shell_NotifyIconW(NIM_DELETE, &d);
            DestroyWindow(self.hwnd);
            for (_, h) in self.icons.borrow_mut().drain() {
                DestroyIcon(h);
            }
        }
        HANDLERS.with(|h| h.borrow_mut().remove(&(self.hwnd as usize)));
        READD.with(|r| r.borrow_mut().remove(&(self.hwnd as usize)));
    }
}

/// The tray as the window's controller uses it: an icon while the window is hidden in it.
/// Behind a trait so the window tests run without touching the real notification area.
pub trait TrayHost {
    /// Show the icon (or update it): its state, tooltip, and who hears its clicks. False when
    /// there is no icon (no notification area): the window must not hide then.
    fn show(&self, state: State, tip: &str, on: std::rc::Rc<dyn Fn(Event)>) -> bool;
    /// Take the icon away.
    fn hide(&self);
    /// The native menu at the pointer: the chosen entry's id.
    fn menu(&self, entries: &[(u32, String)]) -> Option<u32>;
    /// From now on, Windows ending the session calls `f` (before the process may go), whatever
    /// is on screen.
    fn on_session_end(&self, f: std::rc::Rc<dyn Fn()>);
}

/// The real one: a `Tray` while shown, and the session's end heard by a `SessionEnd`.
#[derive(Default)]
pub struct SystemTray {
    tray: RefCell<Option<std::rc::Rc<Tray>>>,
    session: RefCell<Option<SessionEnd>>,
}

impl TrayHost for SystemTray {
    fn show(&self, state: State, tip: &str, on: std::rc::Rc<dyn Fn(Event)>) -> bool {
        let mut t = self.tray.borrow_mut();
        match t.as_ref() {
            Some(tray) => tray.set(state, tip),
            None => *t = Tray::new(state, tip, move |e| on(e)),
        }
        t.is_some()
    }

    fn hide(&self) {
        // Destroyed after the click (or menu) that asked for it has returned: never inside the
        // tray window's own message.
        if let Some(t) = self.tray.borrow_mut().take() {
            slint::Timer::single_shot(std::time::Duration::ZERO, move || drop(t));
        }
    }

    fn menu(&self, entries: &[(u32, String)]) -> Option<u32> {
        let t = self.tray.borrow().clone();
        t.and_then(|t| t.menu(entries))
    }

    fn on_session_end(&self, f: std::rc::Rc<dyn Fn()>) {
        *self.session.borrow_mut() = SessionEnd::new(move || f());
    }
}

// ---------- the icon's drawing ----------

/// The graphite tile, as in the exe icon.
const GRAPHITE: [u8; 3] = [0x16, 0x19, 0x1d];

/// The mark's colour per state (the dark theme's status colours: they read on light and dark
/// taskbars alike). Logging is the mark's own signal blue.
fn colour(s: State) -> [u8; 3] {
    match s {
        State::Logging => [0x7d, 0x95, 0xff],
        State::Dns => [0xe2, 0xa2, 0x4a],
        State::Outage => [0xe0, 0x56, 0x4e],
    }
}

// The app's mark (Stairs, assets/icon.svg) on the 24 grid, as regions: the full-bleed tile with
// its cut corner, the small block (3..7, 17.8..21.8) and the stairs: a 2.4 stroke along
// 7,19.8 H9.2 V13.8 H15.2 V7.8 H21, mitered (square outer corners), butt ends.
fn in_tile(x: f32, y: f32) -> bool {
    (0.0..=24.0).contains(&x) && (0.0..=24.0).contains(&y) && x - y <= 18.0
}

fn in_mark(x: f32, y: f32) -> bool {
    let r = |x0: f32, x1: f32, y0: f32, y1: f32| (x0..=x1).contains(&x) && (y0..=y1).contains(&y);
    r(3.0, 7.0, 17.8, 21.8)
        || r(7.0, 10.4, 18.6, 21.0)
        || r(8.0, 10.4, 12.6, 21.0)
        || r(8.0, 16.4, 12.6, 15.0)
        || r(14.0, 16.4, 6.6, 15.0)
        || r(14.0, 21.0, 6.6, 9.0)
}

/// BGRA pixels (top-down) of the state's icon at `n` px: 8x8 supersampled. The mark in the
/// state's colour on the graphite tile.
pub fn pixels(s: State, n: i32) -> Vec<u8> {
    let ink = colour(s);
    const SS: i32 = 8;
    let mut out = vec![0u8; (n * n * 4) as usize];
    for py in 0..n {
        for px in 0..n {
            let (mut cov, mut sym) = (0u32, 0u32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = (px as f32 + (sx as f32 + 0.5) / SS as f32) * 24.0 / n as f32;
                    let y = (py as f32 + (sy as f32 + 0.5) / SS as f32) * 24.0 / n as f32;
                    if in_tile(x, y) {
                        cov += 1;
                        if in_mark(x, y) {
                            sym += 1;
                        }
                    }
                }
            }
            let i = ((py * n + px) * 4) as usize;
            let f = if cov == 0 { 0.0 } else { sym as f32 / cov as f32 };
            for c in 0..3 {
                let v = GRAPHITE[c] as f32 * (1.0 - f) + ink[c] as f32 * f;
                out[i + 2 - c] = v.round() as u8; // BGR
            }
            out[i + 3] = (cov * 255 / (SS * SS) as u32) as u8;
        }
    }
    out
}

fn make_icon(s: State, n: i32) -> HICON {
    use windows_sys::Win32::Graphics::Gdi::{BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS, DeleteObject};
    unsafe {
        let mut bi: BITMAPINFO = std::mem::zeroed();
        bi.bmiHeader = BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: n,
            biHeight: -n,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..std::mem::zeroed()
        };
        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let color = CreateDIBSection(std::ptr::null_mut(), &bi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
        if color.is_null() || bits.is_null() {
            return std::ptr::null_mut();
        }
        let px = pixels(s, n);
        std::ptr::copy_nonoverlapping(px.as_ptr(), bits as *mut u8, px.len());
        let mask = CreateBitmap(n, n, 1, 1, std::ptr::null());
        let info = ICONINFO { fIcon: 1, xHotspot: 0, yHotspot: 0, hbmMask: mask, hbmColor: color };
        let h = CreateIconIndirect(&info);
        DeleteObject(color);
        DeleteObject(mask);
        h
    }
}
