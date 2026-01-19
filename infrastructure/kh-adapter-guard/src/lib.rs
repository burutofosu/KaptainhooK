//! ガード向けプラットフォーム補助（セッション/プロセス/UI）。
//!
//! 配線は composition に集約し、このクレートは OS 固有補助のみを提供する。

use kh_domain::path::normalize_local_drive_absolute_path;

/// ガード判定用セッション情報
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: u32,
    pub is_interactive: bool,
    pub username: String,
    pub session_name: String,
}

/// プロセスのビット数
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessBitness {
    Bit32,
    Bit64,
}

/// 現在のセッション情報取得
pub fn get_session_info() -> SessionInfo {
    #[cfg(target_os = "windows")]
    {
        windows_session::get()
    }
    #[cfg(not(target_os = "windows"))]
    {
        SessionInfo {
            session_id: 0,
            is_interactive: true,
            username: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
            session_name: "Console".into(),
        }
    }
}

/// 現在のプロセスが管理者権限を持つか確認
pub fn is_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        windows_admin::check_admin()
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// プロセスが実行中か確認
pub fn is_process_running(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        windows_process::is_running(pid)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = pid; // 非Windows用の未使用警告抑制
        false
    }
}

/// ターゲット名をexe名のみに正規化
pub fn normalize_target_name(target: &str) -> String {
    let trimmed = target.trim().trim_matches('"');
    let name = trimmed
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(trimmed);
    name.to_ascii_lowercase()
}

/// 実行ファイルの解決（許可済み検索パスのみ）
pub fn resolve_target_path(target: &str, user_paths: &[String]) -> Option<String> {
    resolve_target_path_with_bitness(target, user_paths, None)
}

/// 実行ファイルの解決（IFEOビュー由来のビット数を優先）
pub fn resolve_target_path_with_bitness(
    target: &str,
    user_paths: &[String],
    ifeo_bitness: Option<ProcessBitness>,
) -> Option<String> {
    use std::path::Path;

    let trimmed = target.trim().trim_matches('"');
    let path = Path::new(trimmed);
    let bitness =
        ifeo_bitness.unwrap_or_else(|| get_parent_process_bitness().unwrap_or_else(current_process_bitness));

    if path.is_absolute() {
        // UNC を拒否し、ローカルの絶対パスのみ許可。
        let mut local_abs = normalize_local_absolute_path_for_launch(trimmed)?;

        if let Some(corrected) = sysnative_correct_system_dir(&local_abs, bitness) {
            local_abs = corrected;
        }

        if let Some(corrected) = wow64_correct_system_dir(&local_abs, bitness) {
            if Path::new(&corrected).is_file() {
                return Some(corrected);
            }
        }

        if Path::new(&local_abs).is_file() {
            return Some(local_abs);
        }
        return None;
    }
    if trimmed.contains('\\') || trimmed.contains('/') {
        return None;
    }
    resolve_from_search_path_with_bitness(trimmed, user_paths, bitness)
}

/// 起動用のローカル絶対パス正規化
/// - "\"\" (UNC) と "\\?\UNC\" は拒否
/// - "\\?\" の device prefix は除去（"\\?\C:\..." は許可）
/// - drive-letter + \\ の形式のみ許可（"C:\\..."）
/// - "." は無視、".." はスタックで折り畳み（root 超えは拒否）
fn normalize_local_absolute_path_for_launch(path: &str) -> Option<String> {
    normalize_local_drive_absolute_path(path)
}

#[cfg(windows)]
fn resolve_from_search_path_with_bitness(
    target: &str,
    user_paths: &[String],
    bitness: ProcessBitness,
) -> Option<String> {
    use std::path::PathBuf;

    let mut dirs: Vec<PathBuf> = Vec::new();
    dirs.extend(default_allowed_dirs(bitness));
    dirs.extend(expand_user_dirs(user_paths));

    for dir in dirs {
        let candidate = dir.join(target);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

#[cfg(not(windows))]
fn resolve_from_search_path_with_bitness(
    _target: &str,
    _user_paths: &[String],
    _bitness: ProcessBitness,
) -> Option<String> {
    None
}

#[cfg(windows)]
fn default_allowed_dirs(bitness: ProcessBitness) -> Vec<std::path::PathBuf> {
    use std::path::PathBuf;

    let mut dirs = Vec::new();

    // 環境変数 (SystemRoot/WINDIR) は起動元プロセスによって汚染され得るため、
    // Windows API から確定値を取得する。
    let win_dir = get_windows_dir().unwrap_or_else(|| PathBuf::from(r"C:\Windows"));

    match bitness {
        ProcessBitness::Bit64 => {
            let sys = win_dir.join("System32");
            push_dir(&mut dirs, sys.clone());
            push_dir(&mut dirs, sys.join("WindowsPowerShell").join("v1.0"));
            push_dir(&mut dirs, sys.join("wbem"));
            push_dir(&mut dirs, win_dir.join("Microsoft.NET").join("Framework64"));
        }
        ProcessBitness::Bit32 => {
            let sys = if win_dir.join("SysWOW64").is_dir() {
                win_dir.join("SysWOW64")
            } else {
                win_dir.join("System32")
            };
            push_dir(&mut dirs, sys.clone());
            push_dir(&mut dirs, sys.join("WindowsPowerShell").join("v1.0"));
            push_dir(&mut dirs, sys.join("wbem"));
            push_dir(&mut dirs, win_dir.join("Microsoft.NET").join("Framework"));
        }
    }

    // PowerShell 7 は Program Files 配下（環境変数ではなく KnownFolder を使用）
    use windows::Win32::UI::Shell::{FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86};
    match bitness {
        ProcessBitness::Bit64 => {
            let pf = known_folder_path(&FOLDERID_ProgramFiles)
                .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
            push_dir(&mut dirs, pf.join("PowerShell").join("7"));
        }
        ProcessBitness::Bit32 => {
            let pf86 = known_folder_path(&FOLDERID_ProgramFilesX86)
                .unwrap_or_else(|| PathBuf::from(r"C:\Program Files (x86)"));
            push_dir(&mut dirs, pf86.join("PowerShell").join("7"));
        }
    }

    dirs
}

#[cfg(windows)]
fn get_windows_dir() -> Option<std::path::PathBuf> {
    use windows::Win32::System::SystemInformation::GetWindowsDirectoryW;

    // まずは MAX_PATH 程度で試し、必要なら拡張する。
    let mut buf: Vec<u16> = vec![0; 260];
    loop {
        let len = unsafe { GetWindowsDirectoryW(Some(buf.as_mut_slice())) };
        if len == 0 {
            return None;
        }
        let len = len as usize;
        if len < buf.len() {
            let s = String::from_utf16_lossy(&buf[..len]);
            if s.trim().is_empty() {
                return None;
            }
            return Some(std::path::PathBuf::from(s));
        }
        // len は必要なサイズ（NUL含む可能性がある）なので +1 して再試行
        buf.resize(len + 1, 0);
    }
}

#[cfg(windows)]
fn expand_user_dirs(user_paths: &[String]) -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    for raw in user_paths {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }

        // search_paths は「ローカル drive-letter 絶対パス」のみ許可する（UNC は拒否）。
        // ここでフィルタしておかないと、\\server\share\tool.exe のようなネットワーク共有上の
        // 同名バイナリを guard 自身が起動し得る。
        let Some(local_abs) = normalize_local_absolute_path_for_launch(trimmed) else {
            continue;
        };

        let path = std::path::PathBuf::from(&local_abs);
        if path.is_dir() {
            dirs.push(path);
        }
    }
    dirs
}

#[cfg(windows)]
fn push_dir(dirs: &mut Vec<std::path::PathBuf>, path: std::path::PathBuf) {
    if path.is_dir() {
        dirs.push(path);
    }
}

fn current_process_bitness() -> ProcessBitness {
    if cfg!(target_pointer_width = "64") {
        ProcessBitness::Bit64
    } else {
        ProcessBitness::Bit32
    }
}

fn wow64_correct_system_dir(path: &str, parent_bitness: ProcessBitness) -> Option<String> {
    #[cfg(windows)]
    {
        use std::path::Path;

        if parent_bitness != ProcessBitness::Bit32 {
            return None;
        }

        let normalized = path.trim().replace('/', "\\");
        let parts: Vec<&str> = normalized.split('\\').filter(|p| !p.is_empty()).collect();
        if parts.len() < 4 {
            return None;
        }

        // C:\Windows\System32\... を SysWOW64 に補正
        if parts[1].eq_ignore_ascii_case("windows") && parts[2].eq_ignore_ascii_case("system32") {
            let mut replaced: Vec<&str> = Vec::with_capacity(parts.len());
            replaced.push(parts[0]); // drive:
            replaced.push(parts[1]); // Windows
            replaced.push("SysWOW64");
            replaced.extend_from_slice(&parts[3..]);

            let candidate = replaced.join("\\");
            if Path::new(&candidate).is_file() {
                return Some(candidate);
            }
        }
    }

    None
}

fn sysnative_correct_system_dir(path: &str, target_bitness: ProcessBitness) -> Option<String> {
    #[cfg(windows)]
    {
        use std::path::Path;

        if target_bitness != ProcessBitness::Bit64 {
            return None;
        }

        if let Some(replaced) = map_sysnative_to_system32(path) {
            if Path::new(&replaced).is_file() {
                return Some(replaced);
            }
        }
    }
    None
}

fn map_sysnative_to_system32(path: &str) -> Option<String> {
    let normalized = path.trim().replace('/', "\\");
    let parts: Vec<&str> = normalized.split('\\').filter(|p| !p.is_empty()).collect();
    if parts.len() < 3 {
        return None;
    }

    if parts.len() >= 3
        && parts[1].eq_ignore_ascii_case("windows")
        && parts[2].eq_ignore_ascii_case("sysnative")
    {
        let mut replaced: Vec<&str> = Vec::with_capacity(parts.len());
        replaced.push(parts[0]); // drive:
        replaced.push(parts[1]); // Windows
        replaced.push("System32");
        if parts.len() > 3 {
            replaced.extend_from_slice(&parts[3..]);
        }
        return Some(replaced.join("\\"));
    }

    None
}

#[cfg(windows)]
fn default_bin_dir() -> std::path::PathBuf {
    use windows::Win32::UI::Shell::FOLDERID_ProgramFiles;

    known_folder_path(&FOLDERID_ProgramFiles)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Program Files"))
        .join("KaptainhooK")
        .join("bin")
}

#[cfg(windows)]
fn known_folder_path(id: &windows::core::GUID) -> Option<std::path::PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    use windows::core::PWSTR;

    unsafe {
        let raw: PWSTR = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let s = pwstr_to_string(raw);
        CoTaskMemFree(Some(raw.0 as _));
        if s.is_empty() {
            None
        } else {
            Some(std::path::PathBuf::from(s))
        }
    }
}

#[cfg(windows)]
fn pwstr_to_string(pwstr: windows::core::PWSTR) -> String {
    unsafe {
        if pwstr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *pwstr.0.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(pwstr.0, len);
        String::from_utf16_lossy(slice)
    }
}

#[cfg(windows)]
pub fn run_service_restart_tool() -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::PCWSTR;

    let mut exe_path = default_bin_dir().join("kh-service-restart.exe");
    if !exe_path.exists() {
        if let Ok(current) = std::env::current_exe() {
            if let Some(dir) = current.parent() {
                let candidate = dir.join("kh-service-restart.exe");
                if candidate.exists() {
                    exe_path = candidate;
                }
            }
        }
    }
    if !exe_path.exists() {
        return Err("kh-service-restart.exe が見つかりません。再インストールしてください。".into());
    }

    let op: Vec<u16> = OsStr::new("runas")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let file: Vec<u16> = exe_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dir: Vec<u16> = exe_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""))
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(op.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR::null(),
            PCWSTR(dir.as_ptr()),
            SW_SHOWNORMAL,
        )
    };
    let code = result.0 as isize;
    if code <= 32 {
        return Err(format!("サービス再起動の起動に失敗しました (ShellExecuteW={})", code));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn run_service_restart_tool() -> Result<(), String> {
    Err("service restart not supported on this platform".into())
}

// ============================================================================
// Windows固有実装
// ============================================================================

#[cfg(target_os = "windows")]
mod windows_session {
    use super::SessionInfo;
    use windows::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTSFreeMemory,
        WTSQuerySessionInformationW, WTSUserName, WTSWinStationName,
    };
    use windows::core::PWSTR;

    pub fn get() -> SessionInfo {
        let session_id = get_session_id();
        let is_interactive = session_id != 0;
        let username = get_username(session_id).unwrap_or_else(get_env_username);
        let session_name = get_session_name(session_id).unwrap_or_else(|| "Unknown".into());

        SessionInfo {
            session_id,
            is_interactive,
            username,
            session_name,
        }
    }

    fn get_session_id() -> u32 {
        let mut session_id: u32 = 0;
        unsafe {
            let current_pid = std::process::id();
            if ProcessIdToSessionId(current_pid, &mut session_id).is_ok() {
                session_id
            } else {
                0
            }
        }
    }

    fn get_username(session_id: u32) -> Option<String> {
        unsafe {
            let mut buffer: PWSTR = PWSTR::null();
            let mut bytes_returned: u32 = 0;

            if WTSQuerySessionInformationW(
                Some(WTS_CURRENT_SERVER_HANDLE),
                session_id,
                WTSUserName,
                &mut buffer,
                &mut bytes_returned,
            )
            .is_ok()
            {
                let result = if !buffer.is_null() && bytes_returned > 0 {
                    Some(pwstr_to_string(buffer))
                } else {
                    None
                };

                if !buffer.is_null() {
                    WTSFreeMemory(buffer.as_ptr() as *mut _);
                }

                result
            } else {
                None
            }
        }
    }

    fn get_session_name(session_id: u32) -> Option<String> {
        unsafe {
            let mut buffer: PWSTR = PWSTR::null();
            let mut bytes_returned: u32 = 0;

            if WTSQuerySessionInformationW(
                Some(WTS_CURRENT_SERVER_HANDLE),
                session_id,
                WTSWinStationName,
                &mut buffer,
                &mut bytes_returned,
            )
            .is_ok()
            {
                let result = if !buffer.is_null() && bytes_returned > 0 {
                    Some(pwstr_to_string(buffer))
                } else {
                    None
                };

                if !buffer.is_null() {
                    WTSFreeMemory(buffer.as_ptr() as *mut _);
                }

                result
            } else {
                None
            }
        }
    }

    fn pwstr_to_string(pwstr: PWSTR) -> String {
        unsafe {
            let mut len = 0;
            while *pwstr.0.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(pwstr.0, len);
            String::from_utf16_lossy(slice)
        }
    }

    fn get_env_username() -> String {
        std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into())
    }
}

#[cfg(target_os = "windows")]
mod windows_admin {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub fn check_admin() -> bool {
        unsafe {
            let mut token = windows::Win32::Foundation::HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION::default();
            let mut return_length = 0u32;
            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            );

            let _ = CloseHandle(token);
            result.is_ok() && elevation.TokenIsElevated != 0
        }
    }
}

#[cfg(target_os = "windows")]
mod windows_process {
    use super::ProcessBitness;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::SystemInformation::{
        IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386,
        IMAGE_FILE_MACHINE_UNKNOWN,
    };
    use windows::Win32::System::Threading::{
        IsWow64Process2, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    pub fn is_running(pid: u32) -> bool {
        unsafe {
            match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                Ok(handle) => {
                    let _ = CloseHandle(handle);
                    true
                }
                Err(_) => false,
            }
        }
    }

    /// プロセス情報
    #[derive(Debug, Clone, Default)]
    pub struct ProcessInfo {
        pub pid: u32,
        pub name: String,
        pub path: Option<String>,
    }

    /// 指定PIDの親プロセス情報を取得
    pub fn get_parent_process_info(pid: u32) -> Option<ProcessInfo> {
        let process_info = get_process_entry(pid)?;
        get_process_info(process_info.th32ParentProcessID)
    }

    /// 指定PIDの祖父プロセス情報を取得
    pub fn get_grandparent_process_info(pid: u32) -> Option<ProcessInfo> {
        let process_info = get_process_entry(pid)?;
        let parent_info = get_process_entry(process_info.th32ParentProcessID)?;
        get_process_info(parent_info.th32ParentProcessID)
    }

    /// 現在のプロセスの親プロセス情報を取得
    pub fn get_current_parent_info() -> Option<ProcessInfo> {
        get_parent_process_info(std::process::id())
    }

    /// 現在のプロセスの祖父プロセス情報を取得
    pub fn get_current_grandparent_info() -> Option<ProcessInfo> {
        get_grandparent_process_info(std::process::id())
    }

    /// 現在の親プロセスのビット数を取得
    pub fn get_current_parent_bitness() -> Option<ProcessBitness> {
        let parent = get_parent_process_info(std::process::id())?;
        get_process_bitness(parent.pid)
    }

    fn get_process_entry(pid: u32) -> Option<PROCESSENTRY32W> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };

            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    if entry.th32ProcessID == pid {
                        let _ = CloseHandle(snapshot);
                        return Some(entry);
                    }
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snapshot);
            None
        }
    }

    fn get_process_info(pid: u32) -> Option<ProcessInfo> {
        let entry = get_process_entry(pid)?;
        let name = wchar_to_string(&entry.szExeFile);
        let path = get_process_path(pid);

        Some(ProcessInfo {
            pid,
            name,
            path,
        })
    }

    fn get_process_path(pid: u32) -> Option<String> {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            struct HandleGuard(windows::Win32::Foundation::HANDLE);
            impl Drop for HandleGuard {
                fn drop(&mut self) {
                    unsafe { let _ = CloseHandle(self.0); }
                }
            }
            let _guard = HandleGuard(handle);

            let mut cap: usize = 260;
            loop {
                let mut buffer = vec![0u16; cap];
                let mut size = buffer.len() as u32;
                let result = QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_WIN32,
                    PWSTR(buffer.as_mut_ptr()),
                    &mut size,
                );

                if result.is_ok() && size > 0 {
                    return Some(String::from_utf16_lossy(&buffer[..size as usize]));
                }

                let err = GetLastError();
                if err == ERROR_INSUFFICIENT_BUFFER && cap < 32768 {
                    let required = (size as usize).saturating_add(1);
                    cap = cap.saturating_mul(2).max(required).min(32768);
                    continue;
                }
                return None;
            }
        }
    }

    fn get_process_bitness(pid: u32) -> Option<ProcessBitness> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        let ok = unsafe {
            IsWow64Process2(handle, &mut process_machine, Some(&mut native_machine))
        }
        .is_ok();
        unsafe { let _ = CloseHandle(handle); }
        if !ok {
            return None;
        }
        if process_machine != IMAGE_FILE_MACHINE_UNKNOWN {
            return Some(ProcessBitness::Bit32);
        }
        match native_machine {
            IMAGE_FILE_MACHINE_I386 => Some(ProcessBitness::Bit32),
            IMAGE_FILE_MACHINE_AMD64 | IMAGE_FILE_MACHINE_ARM64 => Some(ProcessBitness::Bit64),
            _ => None,
        }
    }

    fn wchar_to_string(wchar: &[u16]) -> String {
        let end = wchar.iter().position(|&c| c == 0).unwrap_or(wchar.len());
        String::from_utf16_lossy(&wchar[..end])
    }
}

/// 親プロセス情報
#[derive(Debug, Clone, Default)]
pub struct ParentProcessInfo {
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub path: Option<String>,
}

/// 祖父母プロセス情報
pub type GrandparentProcessInfo = ParentProcessInfo;

/// 親プロセス情報取得
pub fn get_parent_process_info() -> ParentProcessInfo {
    #[cfg(target_os = "windows")]
    {
        windows_process::get_current_parent_info()
            .map(|info| ParentProcessInfo {
                pid: Some(info.pid),
                name: Some(info.name),
                path: info.path,
            })
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "windows"))]
    {
        ParentProcessInfo::default()
    }
}

/// 親プロセスのビット数を推定
pub fn get_parent_process_bitness() -> Option<ProcessBitness> {
    #[cfg(target_os = "windows")]
    {
        windows_process::get_current_parent_bitness()
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

/// 祖父母プロセス情報取得
pub fn get_grandparent_process_info() -> GrandparentProcessInfo {
    #[cfg(target_os = "windows")]
    {
        windows_process::get_current_grandparent_info()
            .map(|info| GrandparentProcessInfo {
                pid: Some(info.pid),
                name: Some(info.name),
                path: info.path,
            })
            .unwrap_or_default()
    }
    #[cfg(not(target_os = "windows"))]
    {
        GrandparentProcessInfo::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_local_absolute_path_rejects_unc() {
        assert_eq!(normalize_local_absolute_path_for_launch(r"\\server\share\cmd.exe"), None);
    }

    #[test]
    fn normalize_local_absolute_path_rejects_unc_device_prefix() {
        assert_eq!(
            normalize_local_absolute_path_for_launch(r"\\?\UNC\server\share\cmd.exe"),
            None
        );
    }

    #[test]
    fn normalize_local_absolute_path_allows_device_drive_prefix() {
        let got = normalize_local_absolute_path_for_launch(r"\\?\C:\Windows\System32\cmd.exe")
            .expect("device drive path should normalize");
        assert_eq!(got, r"C:\Windows\System32\cmd.exe");
    }

    #[test]
    fn resolve_target_path_rejects_unc_absolute_even_if_absolute() {
        assert_eq!(resolve_target_path(r"\\server\share\cmd.exe", &[]), None);
        assert_eq!(
            resolve_target_path(r"\\?\UNC\server\share\cmd.exe", &[]),
            None
        );
    }

    #[test]
    fn map_sysnative_to_system32_rewrites() {
        assert_eq!(
            map_sysnative_to_system32(r"C:\Windows\Sysnative\cmd.exe"),
            Some(r"C:\Windows\System32\cmd.exe".to_string())
        );
    }

    #[test]
    fn map_sysnative_to_system32_ignores_other_paths() {
        assert_eq!(
            map_sysnative_to_system32(r"C:\Windows\System32\cmd.exe"),
            None
        );
        assert_eq!(map_sysnative_to_system32(r"C:\Other\Sysnative"), None);
    }
}
