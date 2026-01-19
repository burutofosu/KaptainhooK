//! KaptainhooK システムトレイアプリケーション
//!
//! バックグラウンドで実行し、以下に素早くアクセス:
//! - 設定を開く
//! - 状態表示
//! - 保護の有効/無効
//! - 終了

#![windows_subsystem = "windows"]
#![allow(unsafe_op_in_unsafe_fn)]

use kh_composition::cli::CliRuntime;
use kh_composition::paths;
use kh_composition::system;
use kh_composition::ui_common::i18n;
use std::error::Error;
use std::ffi::OsStr;
use std::process::Command;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[cfg(windows)]
use kh_log_utils::write_lifecycle_line;
#[cfg(windows)]
use windows::core::{GUID, PCWSTR, PWSTR};
#[cfg(windows)]
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, HWND, LPARAM, LRESULT, LUID, POINT,
    WPARAM,
};
#[cfg(windows)]
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, LookupPrivilegeValueW,
    LUID_AND_ATTRIBUTES, SecurityImpersonation, TokenElevation, TokenLinkedToken, TokenPrimary,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_LINKED_TOKEN, TOKEN_PRIVILEGES,
    TOKEN_QUERY,
};
#[cfg(windows)]
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(windows)]
use windows::Win32::System::Threading::{
    CreateProcessWithTokenW, GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW, LOGON_WITH_PROFILE,
};
#[cfg(windows)]
#[cfg(windows)]
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, NOTIFYICONDATAW, NIF_GUID, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD,
    NIM_DELETE, NIM_SETVERSION, NOTIFYICON_VERSION_4,
};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, ChangeWindowMessageFilterEx, CreateIcon, CreatePopupMenu, CreateWindowExW,
    DefWindowProcW, DestroyIcon, DispatchMessageW, GetCursorPos, GetMessageW, GetShellWindow,
    GetWindowThreadProcessId, LoadIconW, LoadImageW, PostQuitMessage, RegisterClassW,
    RegisterWindowMessageW, SetForegroundWindow, TrackPopupMenu, TranslateMessage,
    CHANGEFILTERSTRUCT, CW_USEDEFAULT, HMENU, HICON, IDI_APPLICATION, IMAGE_ICON, LR_DEFAULTSIZE,
    LR_LOADFROMFILE, MF_SEPARATOR, MF_STRING, MSG, MSGFLT_ALLOW, TPM_RIGHTBUTTON, WM_APP,
    WM_COMMAND, WM_CONTEXTMENU, WM_CREATE, WM_DESTROY, WM_LBUTTONDBLCLK, WM_LBUTTONUP,
    WM_RBUTTONDBLCLK, WM_RBUTTONUP, WM_USER, WNDCLASSW,
};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug)]
struct SimpleError(String);

impl std::fmt::Display for SimpleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for SimpleError {}

fn err(msg: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(SimpleError(msg.into()))
}

const TRAY_ICON_ID: u32 = 1;
const WM_TRAYICON: u32 = WM_APP + 1;
const TRAY_GUID: GUID = GUID::from_u128(0x86a7d2d2_f7d8_4e50_8d59_6d2b1b2b3c7a);
const ID_SETTINGS: usize = 1001;
const ID_STATUS: usize = 1002;
const ID_RESTART: usize = 1003;
const ID_EXIT: usize = 1004;
const NIN_SELECT: u32 = WM_USER + 0;
const NIN_KEYSELECT: u32 = WM_USER + 1;

#[cfg(windows)]
struct MenuHandle(HMENU);

#[cfg(windows)]
unsafe impl Send for MenuHandle {}

#[cfg(windows)]
unsafe impl Sync for MenuHandle {}

#[cfg(windows)]
static TRAY_MENU: OnceLock<MenuHandle> = OnceLock::new();
#[cfg(windows)]
static TRAY_TOOLTIP: OnceLock<String> = OnceLock::new();
#[cfg(windows)]
static TASKBAR_CREATED_MSG: OnceLock<u32> = OnceLock::new();

#[cfg(windows)]
fn main() -> Result<()> {
    log_tray("kh-tray start");
    if is_elevated() {
        log_tray("elevated detected, attempting non-elevated relaunch");
        if relaunch_non_elevated() {
            log_tray("relaunch succeeded; exiting elevated instance");
            return Ok(());
        }
        log_tray("relaunch failed; continuing elevated");
    }

    // 設定を読み込み言語を適用
    let runtime = CliRuntime::new();
    let config = runtime.load_config_or_default();
    i18n::set_language(config.language);
    let t = i18n::t();
    let _ = TRAY_TOOLTIP.set(t.tray_tooltip().to_string());

    let taskbar_created = unsafe {
        RegisterWindowMessageW(PCWSTR(to_wide("TaskbarCreated").as_ptr()))
    };
    let _ = TASKBAR_CREATED_MSG.set(taskbar_created);

    let hwnd = unsafe { create_message_window()? };
    let menu = unsafe { create_tray_menu(t)? };
    let _ = TRAY_MENU.set(MenuHandle(menu));

    unsafe {
        let (icon, destroy_icon) = icon_for_tray();
        add_tray_icon(hwnd, icon, t.tray_tooltip())?;
        message_loop();
        remove_tray_icon(hwnd);
        if destroy_icon {
            let _ = DestroyIcon(icon);
        }
    }

    Ok(())
}

#[cfg(not(windows))]
fn main() {
    let t = i18n::t();
    eprintln!("{}", t.tray_unavailable());
    std::process::exit(1);
}

#[cfg(windows)]
unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CREATE => LRESULT(0),
        WM_COMMAND => {
            let id = (wparam.0 & 0xffff) as usize;
            log_tray(&format!("WM_COMMAND id={}", id));
            match id {
                ID_SETTINGS => open_settings(),
                ID_STATUS => show_service_status(),
                ID_RESTART => restart_service(),
                ID_EXIT => PostQuitMessage(0),
                _ => {}
            }
            LRESULT(0)
        }
        WM_TRAYICON => {
            let event_raw = lparam.0 as u32;
            let event = event_raw & 0xFFFF;
            log_tray(&format!(
                "WM_TRAYICON event_raw={} event={}",
                event_raw, event
            ));
            match event {
                WM_RBUTTONUP
                | WM_RBUTTONDBLCLK
                | WM_LBUTTONUP
                | WM_LBUTTONDBLCLK
                | WM_CONTEXTMENU
                | NIN_SELECT
                | NIN_KEYSELECT => {
                    log_tray("WM_TRAYICON -> show_tray_menu");
                    show_tray_menu(hwnd);
                }
                _ => {}
            }
            LRESULT(0)
        }
        msg if TASKBAR_CREATED_MSG.get().is_some_and(|id| *id == msg) => {
            log_tray("TaskbarCreated received; re-adding tray icon");
            if let Some(tooltip) = TRAY_TOOLTIP.get() {
                let (icon, destroy_icon) = icon_for_tray();
                if add_tray_icon(hwnd, icon, tooltip).is_err() {
                    log_tray("TaskbarCreated: add_tray_icon failed");
                }
                if destroy_icon {
                    let _ = DestroyIcon(icon);
                }
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            remove_tray_icon(hwnd);
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(windows)]
unsafe fn create_message_window() -> Result<HWND> {
    let class_name = to_wide("KaptainhooKTrayWindow");
    let hinstance = GetModuleHandleW(None).map_err(|e| err(e.to_string()))?;

    let wc = WNDCLASSW {
        lpfnWndProc: Some(wnd_proc),
        hInstance: hinstance.into(),
        lpszClassName: PCWSTR(class_name.as_ptr()),
        ..Default::default()
    };

    let atom = RegisterClassW(&wc);
    if atom == 0 {
        return Err(err("RegisterClassW failed"));
    }

    let hwnd = CreateWindowExW(
        Default::default(),
        PCWSTR(class_name.as_ptr()),
        PCWSTR(class_name.as_ptr()),
        Default::default(),
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        None,
        None,
        Some(hinstance.into()),
        None,
    )?;

    allow_tray_messages(hwnd);

    Ok(hwnd)
}

#[cfg(windows)]
unsafe fn allow_tray_messages(hwnd: HWND) {
    let mut cfs = CHANGEFILTERSTRUCT {
        cbSize: std::mem::size_of::<CHANGEFILTERSTRUCT>() as u32,
        ExtStatus: windows::Win32::UI::WindowsAndMessaging::MSGFLTINFO_STATUS(0),
    };
    if ChangeWindowMessageFilterEx(hwnd, WM_TRAYICON, MSGFLT_ALLOW, Some(&mut cfs)).is_err() {
        log_last_error("ChangeWindowMessageFilterEx WM_TRAYICON failed");
    }
    if ChangeWindowMessageFilterEx(hwnd, WM_COMMAND, MSGFLT_ALLOW, Some(&mut cfs)).is_err() {
        log_last_error("ChangeWindowMessageFilterEx WM_COMMAND failed");
    }
    if ChangeWindowMessageFilterEx(hwnd, WM_CONTEXTMENU, MSGFLT_ALLOW, Some(&mut cfs)).is_err() {
        log_last_error("ChangeWindowMessageFilterEx WM_CONTEXTMENU failed");
    }
}

#[cfg(windows)]
fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let _guard = HandleGuard(token);

        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
        .is_ok();

        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(windows)]
fn relaunch_non_elevated() -> bool {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let exe_str = exe_path.to_string_lossy().to_string();
    let mut cmdline = to_wide(&format!("\"{}\"", exe_str));
    let exe_w = to_wide(&exe_str);

    unsafe {
        enable_privilege("SeIncreaseQuotaPrivilege");
        enable_privilege("SeImpersonatePrivilege");
        enable_privilege("SeAssignPrimaryTokenPrivilege");

        if relaunch_with_linked_token(&exe_w, &mut cmdline) {
            return true;
        }

        let shell = GetShellWindow();
        if shell.0 == std::ptr::null_mut() {
            log_tray("relaunch: GetShellWindow returned null");
            return false;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(shell, Some(&mut pid));
        if pid == 0 {
            log_tray("relaunch: GetWindowThreadProcessId returned 0");
            return false;
        }

        let Ok(process) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            log_tray("relaunch: OpenProcess failed");
            return false;
        };
        let _proc_guard = HandleGuard(process);

        let token_access = TOKEN_DUPLICATE | TOKEN_QUERY;
        let primary_access = TOKEN_DUPLICATE
            | TOKEN_ASSIGN_PRIMARY
            | TOKEN_QUERY
            | TOKEN_ADJUST_DEFAULT
            | TOKEN_ADJUST_SESSIONID;
        let mut token = HANDLE::default();
        if OpenProcessToken(process, token_access, &mut token).is_err()
        {
            log_last_error("relaunch: OpenProcessToken failed");
            return false;
        }
        let _token_guard = HandleGuard(token);

        let mut dup = HANDLE::default();
        if DuplicateTokenEx(token, primary_access, None, SecurityImpersonation, TokenPrimary, &mut dup)
            .is_err()
        {
            log_last_error("relaunch: DuplicateTokenEx failed");
            return false;
        }
        let _dup_guard = HandleGuard(dup);

        log_tray("relaunch: attempting with shell token");
        if try_create_process_with_token(dup, &exe_w, &mut cmdline, "shell") {
            return true;
        }
    }

    false
}

#[cfg(windows)]
unsafe fn relaunch_with_linked_token(exe_w: &[u16], cmdline: &mut [u16]) -> bool {
    let mut token = HANDLE::default();
    let token_access = TOKEN_DUPLICATE | TOKEN_QUERY;
    let primary_access = TOKEN_DUPLICATE
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_QUERY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID;
    if OpenProcessToken(GetCurrentProcess(), token_access, &mut token).is_err() {
        log_last_error("relaunch: OpenProcessToken(current) failed");
        return false;
    }
    let _token_guard = HandleGuard(token);

    let mut linked = TOKEN_LINKED_TOKEN::default();
    let mut ret_len = 0u32;
    if GetTokenInformation(
        token,
        TokenLinkedToken,
        Some(&mut linked as *mut _ as *mut _),
        std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
        &mut ret_len,
    )
    .is_err()
    {
        log_last_error("relaunch: GetTokenInformation(TokenLinkedToken) failed");
        return false;
    }
    let _linked_guard = HandleGuard(linked.LinkedToken);

    log_tray("relaunch: attempting with linked token");
    if try_create_process_with_token(linked.LinkedToken, exe_w, cmdline, "linked-direct") {
        return true;
    }

    let mut primary = HANDLE::default();
    if DuplicateTokenEx(
        linked.LinkedToken,
        primary_access,
        None,
        SecurityImpersonation,
        TokenPrimary,
        &mut primary,
    )
        .is_err()
    {
        log_last_error("relaunch: DuplicateTokenEx(linked) failed");
        return false;
    }
    let _primary_guard = HandleGuard(primary);

    log_tray("relaunch: attempting with linked token (duplicated)");
    try_create_process_with_token(primary, exe_w, cmdline, "linked-dup")
}

#[cfg(windows)]
unsafe fn try_create_process_with_token(
    token: HANDLE,
    exe_w: &[u16],
    cmdline: &mut [u16],
    context: &str,
) -> bool {
    let mut si = STARTUPINFOW::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();

    if CreateProcessWithTokenW(
        token,
        LOGON_WITH_PROFILE,
        PCWSTR(exe_w.as_ptr()),
        Some(PWSTR(cmdline.as_mut_ptr())),
        Default::default(),
        None,
        None,
        &si,
        &mut pi,
    )
    .is_ok()
    {
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
        return true;
    }
    log_last_error(&format!("relaunch {}: CreateProcessWithTokenW failed", context));
    false
}

#[cfg(windows)]
fn log_tray(msg: &str) {
    write_lifecycle_line("TRAY", msg);
}

#[cfg(windows)]
struct HandleGuard(HANDLE);

#[cfg(windows)]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
unsafe fn enable_privilege(name: &str) {
    let mut token = HANDLE::default();
    if OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &mut token,
    )
    .is_err()
    {
        log_last_error("enable_privilege: OpenProcessToken failed");
        return;
    }
    let _token_guard = HandleGuard(token);

    let name_w = to_wide(name);
    let mut luid = LUID::default();
    if LookupPrivilegeValueW(None, PCWSTR(name_w.as_ptr()), &mut luid).is_err() {
        log_last_error("enable_privilege: LookupPrivilegeValueW failed");
        return;
    }

    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    let _ = AdjustTokenPrivileges(token, false, Some(&mut tp), 0, None, None);
    let err = GetLastError();
    if err == ERROR_NOT_ALL_ASSIGNED {
        log_tray("enable_privilege: not all privileges assigned");
        return;
    }
    log_tray(&format!("enable_privilege ok: {}", name));
}

#[cfg(windows)]
fn log_last_error(prefix: &str) {
    let err = unsafe { GetLastError().0 };
    log_tray(&format!("{} (GetLastError={})", prefix, err));
}

#[cfg(windows)]
unsafe fn create_tray_menu(t: &dyn i18n::Translations) -> Result<HMENU> {
    let menu = CreatePopupMenu()?;
    if menu.0.is_null() {
        return Err(err("CreatePopupMenu failed"));
    }

    let settings = to_wide(t.tray_settings());
    let status = to_wide(t.tray_status());
    let restart = to_wide(t.tray_restart());
    let exit = to_wide(t.tray_exit());

    let _ = AppendMenuW(menu, MF_STRING, ID_SETTINGS, PCWSTR(settings.as_ptr()));
    let _ = AppendMenuW(menu, MF_STRING, ID_STATUS, PCWSTR(status.as_ptr()));
    let _ = AppendMenuW(menu, MF_STRING, ID_RESTART, PCWSTR(restart.as_ptr()));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, ID_EXIT, PCWSTR(exit.as_ptr()));

    Ok(menu)
}

#[cfg(windows)]
unsafe fn add_tray_icon(hwnd: HWND, icon: HICON, tooltip: &str) -> Result<()> {
    let mut nid = notify_icon_data(hwnd, icon, tooltip);
    let _ = Shell_NotifyIconW(NIM_DELETE, &mut nid);
    let ok = Shell_NotifyIconW(NIM_ADD, &mut nid).as_bool();
    if !ok {
        log_last_error("Shell_NotifyIconW NIM_ADD failed");
        return Err(err("Shell_NotifyIconW NIM_ADD failed"));
    }
    log_tray("Shell_NotifyIconW NIM_ADD ok");
    nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
    let _ = Shell_NotifyIconW(NIM_SETVERSION, &mut nid);
    log_tray("Shell_NotifyIconW NIM_SETVERSION");
    Ok(())
}

#[cfg(windows)]
unsafe fn remove_tray_icon(hwnd: HWND) {
    let mut nid = NOTIFYICONDATAW::default();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    nid.uFlags = NIF_GUID;
    nid.guidItem = TRAY_GUID;
    let _ = Shell_NotifyIconW(NIM_DELETE, &mut nid);
}

#[cfg(windows)]
unsafe fn show_tray_menu(hwnd: HWND) {
    if let Some(menu) = TRAY_MENU.get() {
        log_tray("show_tray_menu");
        let mut pt = POINT::default();
        let _ = GetCursorPos(&mut pt);
        let _ = SetForegroundWindow(hwnd);
        let ok = TrackPopupMenu(menu.0, TPM_RIGHTBUTTON, pt.x, pt.y, Some(0), hwnd, None).as_bool();
        if !ok {
            log_last_error("TrackPopupMenu failed");
        }
    }
}

#[cfg(windows)]
unsafe fn message_loop() {
    let mut msg = MSG::default();
    while GetMessageW(&mut msg, None, 0, 0).as_bool() {
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

#[cfg(windows)]
fn notify_icon_data(hwnd: HWND, icon: HICON, tooltip: &str) -> NOTIFYICONDATAW {
    let mut nid = NOTIFYICONDATAW::default();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ICON_ID;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_GUID;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = icon;
    nid.guidItem = TRAY_GUID;
    let tip = to_wide(tooltip);
    let max = nid.szTip.len().saturating_sub(1);
    for (i, ch) in tip.iter().take(max).enumerate() {
        nid.szTip[i] = *ch;
    }
    nid
}

#[cfg(windows)]
fn icon_for_tray() -> (HICON, bool) {
    unsafe {
        if let Some(icon) = load_icon_from_assets() {
            return (icon, true);
        }
        let icon = create_default_icon();
        if !icon.0.is_null() {
            return (icon, true);
        }
        (LoadIconW(None, IDI_APPLICATION).unwrap_or_default(), false)
    }
}

#[cfg(windows)]
unsafe fn create_default_icon() -> HICON {
    // 16x16のシンプルアイコン作成（青い盾形状）
    let size: i32 = 16;
    let mut rgba = vec![0u8; (size * size * 4) as usize];

    for y in 0..size {
        for x in 0..size {
            let idx = ((y * size + x) * 4) as usize;
            let in_shield = y >= 2
                && y <= 14
                && x >= 3
                && x <= 12
                && (y <= 8 || (x - 7).abs() <= (14 - y) / 2);
            if in_shield {
                rgba[idx] = 66;
                rgba[idx + 1] = 133;
                rgba[idx + 2] = 244;
                rgba[idx + 3] = 255;
            } else {
                rgba[idx + 3] = 0;
            }
        }
    }

    let and_stride = ((size + 31) / 32) * 4;
    let and_mask = vec![0u8; (and_stride * size) as usize];
    let mut xor_mask = vec![0u8; (size * size * 4) as usize];
    for i in 0..(size * size) as usize {
        let r = rgba[i * 4];
        let g = rgba[i * 4 + 1];
        let b = rgba[i * 4 + 2];
        let a = rgba[i * 4 + 3];
        xor_mask[i * 4] = b;
        xor_mask[i * 4 + 1] = g;
        xor_mask[i * 4 + 2] = r;
        xor_mask[i * 4 + 3] = a;
    }

    CreateIcon(
        None,
        size,
        size,
        1,
        32,
        and_mask.as_ptr(),
        xor_mask.as_ptr(),
    )
    .unwrap_or_default()
}

#[cfg(windows)]
fn find_tray_icon_path() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("kh_tray_icon.ico"));
            candidates.push(dir.join("assets").join("kh_tray_icon.ico"));
            let mut current = Some(dir);
            for _ in 0..5 {
                if let Some(base) = current {
                    candidates.push(base.join("assets").join("kh_tray_icon.ico"));
                    current = base.parent();
                }
            }
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("assets").join("kh_tray_icon.ico"));
    }

    for path in candidates {
        if path.exists() {
            return Some(path);
        }
    }
    None
}

#[cfg(windows)]
unsafe fn load_icon_from_assets() -> Option<HICON> {
    let path = find_tray_icon_path()?;
    load_icon_from_path(&path)
}

#[cfg(windows)]
unsafe fn load_icon_from_path(path: &Path) -> Option<HICON> {
    let path_w = to_wide_os(path.as_os_str());
    let handle = LoadImageW(
        None,
        PCWSTR(path_w.as_ptr()),
        IMAGE_ICON,
        0,
        0,
        LR_LOADFROMFILE | LR_DEFAULTSIZE,
    )
    .ok()?;
    let icon = HICON(handle.0);
    if icon.0 == std::ptr::null_mut() {
        None
    } else {
        Some(icon)
    }
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0);
    wide
}

#[cfg(windows)]
fn to_wide_os(s: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = s.encode_wide().collect();
    wide.push(0);
    wide
}

fn open_settings() {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_default();

    let settings_exe = exe_dir.join("kh-settings.exe");

    if settings_exe.exists() {
        let _ = Command::new(&settings_exe).spawn();
    } else {
        // 相対パスで試行
        let _ = Command::new("kh-settings.exe").spawn();
    }
}

fn show_service_status() {
    let runtime = CliRuntime::new();
    let config = runtime.load_config_or_default();
    i18n::set_language(config.language);
    let t = i18n::t();

    match system::get_service_state() {
        Ok(state) => {
            let msg = match state {
                system::ServiceState::Running => t.tray_service_running(),
                system::ServiceState::Stopped => t.tray_service_stopped(),
                system::ServiceState::StartPending => t.tray_service_starting(),
                system::ServiceState::StopPending => t.tray_service_stopping(),
                system::ServiceState::NotInstalled => t.tray_service_not_installed(),
                system::ServiceState::Unknown => t.tray_service_unknown(),
            };
            show_message_box(t.tray_status_title(), msg);
        }
        Err(e) => {
            show_message_box(t.tray_status_title(), &t.tray_error_detail(&e.to_string()));
        }
    }
}

fn restart_service() {
    let runtime = CliRuntime::new();
    let config = runtime.load_config_or_default();
    i18n::set_language(config.language);
    let t = i18n::t();

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(paths::default_bin_dir);
    let mut restart_exe = exe_dir.join("kh-service-restart.exe");
    if !restart_exe.exists() {
        let fallback = paths::default_bin_dir().join("kh-service-restart.exe");
        if fallback.exists() {
            restart_exe = fallback;
        }
    }

    if restart_exe.exists() {
        match Command::new(&restart_exe).spawn() {
            Ok(_) => show_message_box(t.tray_status_title(), t.tray_restart_started()),
            Err(e) => show_message_box(t.tray_status_title(), &t.tray_error_detail(&e.to_string())),
        }
    } else {
        show_message_box(t.tray_status_title(), t.tray_restart_missing());
    }
}

#[cfg(windows)]
fn show_message_box(title: &str, message: &str) {
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};

    let title_wide: Vec<u16> = OsStr::new(title).encode_wide().chain(once(0)).collect();
    let message_wide: Vec<u16> = OsStr::new(message).encode_wide().chain(once(0)).collect();

    unsafe {
        MessageBoxW(
            None,
            windows::core::PCWSTR(message_wide.as_ptr()),
            windows::core::PCWSTR(title_wide.as_ptr()),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

#[cfg(not(windows))]
fn show_message_box(_title: &str, message: &str) {
    println!("{}", message);
}
