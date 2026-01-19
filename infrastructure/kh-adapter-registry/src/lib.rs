//! Windows IFEOレジストリアダプター
//!
//! IFEOレジストリ (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options)
//! のデバッガ値を読み書きする。
//! 64bit/32bit(WOW6432Node) 両ビューに対応。

use kh_domain::DomainError;
use kh_domain::model::{RegistryView, Target};
use kh_domain::port::driven::{IfeoRepository, LeaseStore, RegistryPort};
use std::collections::HashSet;
use std::path::PathBuf;

/// デバッガ値の生情報
#[derive(Debug, Clone)]
pub enum DebuggerValue {
    /// 文字列型（REG_SZ、REG_EXPAND_SZ）
    String {
        raw: String,
        expanded: Option<String>,
        value_type: u32,
    },
    /// その他の型（REG_BINARY など）
    Other {
        value_type: u32,
        bytes: Vec<u8>,
    },
}

impl DebuggerValue {
    pub fn raw_string(&self) -> Option<&str> {
        match self {
            DebuggerValue::String { raw, .. } => Some(raw.as_str()),
            DebuggerValue::Other { .. } => None,
        }
    }

    pub fn is_empty_string(&self) -> bool {
        match self {
            DebuggerValue::String { raw, .. } => raw.trim().is_empty(),
            DebuggerValue::Other { .. } => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebuggerOwnership {
    Owned,
    Foreign,
    Disabled,
}

// ============================================================================
// Targetsレジストリ（HKLM\SOFTWARE\KaptainhooK\Targets）
// ============================================================================

pub const TARGETS_REG_PATH: &str = r"SOFTWARE\KaptainhooK\Targets";
pub const TARGETS_SCHEMA_VERSION: u32 = 1;
pub const TARGETS_SDDL_AU_READ: &str = "D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;AU)";

pub const LEASE_STATE_REG_PATH: &str = r"SOFTWARE\KaptainhooK\LeaseState";
pub const LEASE_STATE_SCHEMA_VERSION: u32 = 1;
pub const LEASE_STATE_SDDL_ADMIN_ONLY: &str = "D:P(A;;KA;;;SY)(A;;KA;;;BA)";

pub use kh_domain::port::driven::LeaseState;

#[derive(Debug, Default, Clone)]
pub struct TargetsRegistry;

impl TargetsRegistry {
    pub fn new() -> Self {
        Self
    }

    pub fn read_enabled_targets(&self) -> Result<HashSet<String>, DomainError> {
        read_enabled_targets_impl()
    }

    pub fn write_enabled_targets(&self, targets: &[String]) -> Result<(), DomainError> {
        write_enabled_targets_impl(targets)
    }
}

/// 信頼済みレジストリから有効対象を読み取る
pub fn load_enabled_targets() -> Result<HashSet<String>, DomainError> {
    TargetsRegistry::new().read_enabled_targets()
}

/// 信頼済みレジストリへ有効対象を書き込む
pub fn write_enabled_targets(targets: &[String]) -> Result<(), DomainError> {
    TargetsRegistry::new().write_enabled_targets(targets)
}

pub fn read_lease_state() -> Result<Option<LeaseState>, DomainError> {
    read_lease_state_impl()
}

pub fn write_lease_state(state: &LeaseState) -> Result<(), DomainError> {
    write_lease_state_impl(state)
}

pub fn clear_lease_state() -> Result<(), DomainError> {
    clear_lease_state_impl()
}

/// プラットフォーム中立のハンドル
#[cfg(windows)]
pub type RegistryAdapter = WindowsRegistryAdapter;
#[cfg(not(windows))]
pub type RegistryAdapter = NonWindowsRegistryAdapter;

#[cfg(windows)]
pub struct WindowsRegistryAdapter {
    debugger_path: String,
}

#[cfg(windows)]
impl WindowsRegistryAdapter {
    /// 明示的なデバッガパスを指定
    pub fn with_debugger_path(debugger_path: impl Into<String>) -> Self {
        Self {
            debugger_path: debugger_path.into(),
        }
    }

    /// デフォルトのデバッガパスを使用（既定のProgram Files配下）
    pub fn new() -> Self {
        Self::with_debugger_path(default_debugger_path())
    }

    /// このアダプターがデバッガとして設定するパス
    pub fn debugger_path(&self) -> &str {
        &self.debugger_path
    }

    /// デバッガ値の生情報を取得（型/raw/expanded/bytes）
    pub fn get_debugger_value(
        &self,
        target: &str,
        view: RegistryView,
    ) -> Result<Option<DebuggerValue>, DomainError> {
        get_debugger_value_impl(target, view)
    }
}

#[cfg(not(windows))]
#[derive(Default)]
pub struct NonWindowsRegistryAdapter;

#[cfg(not(windows))]
impl NonWindowsRegistryAdapter {
    pub fn new() -> Self {
        Self
    }

    pub fn debugger_path(&self) -> &str {
        "kaptainhook_bootstrap.exe"
    }

    pub fn get_debugger_value(
        &self,
        _target: &str,
        _view: RegistryView,
    ) -> Result<Option<DebuggerValue>, DomainError> {
        Ok(None)
    }
}

#[cfg(not(windows))]
impl RegistryPort for NonWindowsRegistryAdapter {
    fn register(&self, _target: &Target) -> Result<(), DomainError> {
        Err(DomainError::Unknown(
            "IFEO registry is not supported on this platform".into(),
        ))
    }
    fn unregister(&self, _target: &Target) -> Result<(), DomainError> {
        Err(DomainError::Unknown(
            "IFEO registry is not supported on this platform".into(),
        ))
    }
}

#[cfg(not(windows))]
impl IfeoRepository for NonWindowsRegistryAdapter {
    fn get_debugger(
        &self,
        _target: &str,
        _view: RegistryView,
    ) -> Result<Option<String>, DomainError> {
        Ok(None)
    }
    fn set_debugger(
        &self,
        _target: &str,
        _view: RegistryView,
        _path: &str,
    ) -> Result<(), DomainError> {
        Err(DomainError::Unknown(
            "IFEO registry is not supported on this platform".into(),
        ))
    }
    fn remove_debugger(&self, _target: &str, _view: RegistryView) -> Result<(), DomainError> {
        Ok(())
    }
    fn list_all_targets(&self, _view: RegistryView) -> Result<Vec<(String, String)>, DomainError> {
        Ok(Vec::new())
    }
}

#[cfg(not(windows))]
impl LeaseStore for NonWindowsRegistryAdapter {
    fn read_lease(&self) -> Result<Option<LeaseState>, DomainError> {
        read_lease_state()
    }

    fn write_lease(&self, state: &LeaseState) -> Result<(), DomainError> {
        write_lease_state(state)
    }

    fn clear_lease(&self) -> Result<(), DomainError> {
        clear_lease_state()
    }
}

/// デフォルトのデバッガパスを計算（全呼び出し元で共有）
/// 既定インストールパスのみを前提とする。
pub fn default_debugger_path() -> String {
    #[cfg(windows)]
    {
        return default_install_bin_dir()
            .join("kh-bootstrap.exe")
            .to_string_lossy()
            .to_string();
    }
    #[cfg(not(windows))]
    {
        "kaptainhook_bootstrap.exe".to_string()
    }
}

/// デフォルトのガード実行ファイルパス（IPCクライアント検証用）
/// 既定インストールパスのみを前提とする。
pub fn default_guard_path() -> String {
    #[cfg(windows)]
    {
        return default_install_bin_dir()
            .join("kh-guard.exe")
            .to_string_lossy()
            .to_string();
    }
    #[cfg(not(windows))]
    {
        "kh-guard.exe".to_string()
    }
}

#[cfg(windows)]
fn known_folder_path(id: &windows::core::GUID) -> Option<PathBuf> {
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
            Some(PathBuf::from(s))
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
fn default_install_bin_dir() -> PathBuf {
    use windows::Win32::UI::Shell::FOLDERID_ProgramFiles;

    known_folder_path(&FOLDERID_ProgramFiles)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
        .join("KaptainhooK")
        .join("bin")
}

/// IFEOグローバルMutex名（IFEO操作の排他用）
pub const IFEO_MUTEX_NAME: &str = r"Global\KaptainhooKIfeoMutex";

/// IFEOグローバルMutexのガード
#[cfg(windows)]
pub struct IfeoMutexGuard {
    handle: windows::Win32::Foundation::HANDLE,
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(windows)]
impl Drop for IfeoMutexGuard {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::ReleaseMutex;
        unsafe {
            let _ = ReleaseMutex(self.handle);
            let _ = CloseHandle(self.handle);
        }
    }
}

/// IFEOグローバルMutexを取得
#[cfg(windows)]
pub fn acquire_ifeo_mutex(timeout_ms: u32) -> Result<IfeoMutexGuard, DomainError> {
    use windows::Win32::Foundation::{GetLastError, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
    use windows::core::PCWSTR;

    fn to_wide(s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }

    let name = to_wide(IFEO_MUTEX_NAME);
    let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }
        .map_err(|e| DomainError::Unknown(format!("CreateMutexW failed: {}", e.message())))?;

    let wait = unsafe { WaitForSingleObject(handle, timeout_ms) };
    match wait {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(IfeoMutexGuard {
            handle,
            _not_send: std::marker::PhantomData,
        }),
        WAIT_TIMEOUT => {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
            Err(DomainError::Timeout("IFEO mutex busy".into()))
        }
        _ => {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(handle);
            }
            Err(DomainError::Unknown(format!(
                "WaitForSingleObject failed: {}",
                unsafe { GetLastError().0 }
            )))
        }
    }
}

#[cfg(not(windows))]
pub struct IfeoMutexGuard;

#[cfg(not(windows))]
pub fn acquire_ifeo_mutex(_timeout_ms: u32) -> Result<IfeoMutexGuard, DomainError> {
    Ok(IfeoMutexGuard)
}

#[cfg(windows)]
fn get_debugger_value_impl(
    target: &str,
    view: RegistryView,
) -> Result<Option<DebuggerValue>, DomainError> {
    windows_impl::get_debugger_value_impl(target, view)
}

#[cfg(not(windows))]
#[allow(dead_code)]
fn get_debugger_value_impl(
    _target: &str,
    _view: RegistryView,
) -> Result<Option<DebuggerValue>, DomainError> {
    Ok(None)
}

#[cfg(windows)]
pub fn classify_debugger_value(
    value: Option<DebuggerValue>,
    expected_debugger: &str,
) -> DebuggerOwnership {
    windows_impl::classify_debugger_value(value, expected_debugger)
}

#[cfg(not(windows))]
pub fn classify_debugger_value(
    value: Option<DebuggerValue>,
    _expected_debugger: &str,
) -> DebuggerOwnership {
    match value {
        None => DebuggerOwnership::Disabled,
        Some(DebuggerValue::String { raw, .. }) if raw.trim().is_empty() => DebuggerOwnership::Disabled,
        Some(_) => DebuggerOwnership::Foreign,
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_DATA, ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
        REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RRF_RT_ANY,
        RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteValueW,
        RegGetValueW, RegOpenKeyExW, RegSetValueExW,
    };
    use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
    use windows::core::{PCWSTR, PWSTR};

    const IFEO_BASE_64: &str =
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    // 32bit ビューは KEY_WOW64_32KEY フラグで切り替えるため、ベースパスは共通にする。
    const IFEO_BASE_32: &str =
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";


    impl RegistryPort for WindowsRegistryAdapter {
        fn register(&self, target: &Target) -> Result<(), DomainError> {
            for view in [RegistryView::Bit64, RegistryView::Bit32] {
                self.set_debugger(target.exe_name(), view, &self.debugger_path)?;
            }
            Ok(())
        }

        fn unregister(&self, target: &Target) -> Result<(), DomainError> {
            let mut first_error: Option<DomainError> = None;
            for view in [RegistryView::Bit64, RegistryView::Bit32] {
                if let Err(err) = self.remove_debugger(target.exe_name(), view) {
                    eprintln!(
                        "[ERROR] unregister failed for {} in {:?}: {}",
                        target.exe_name(),
                        view,
                        err
                    );
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
            if let Some(err) = first_error {
                Err(err)
            } else {
                Ok(())
            }
        }
    }

    impl IfeoRepository for WindowsRegistryAdapter {
        fn get_debugger(
            &self,
            target: &str,
            view: RegistryView,
        ) -> Result<Option<String>, DomainError> {
            let key = match open_existing_key_readonly(target, view) {
                Ok(k) => k,
                Err(DomainError::TargetNotFound(_)) => return Ok(None),
                Err(e) => return Err(e),
            };
            let debugger_name = to_wide("Debugger"); // API呼び出し中にVecを生存させる
            let mut value_type = REG_VALUE_TYPE(0);
            let mut size_bytes: u32 = 0;
            let status = unsafe {
                RegGetValueW(
                    key,
                    PCWSTR::null(),
                    PCWSTR(debugger_name.as_ptr()),
                    RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                    Some(&mut value_type),
                    None,
                    Some(&mut size_bytes),
                )
            };
            if status != ERROR_SUCCESS {
                let _ = unsafe { RegCloseKey(key) };
                return match status.0 {
                    2 => Ok(None),
                    code if code == ERROR_ACCESS_DENIED.0 => {
                        Err(DomainError::RegistryAccessDenied(format!(
                            "Access denied reading IFEO for {}",
                            target
                        )))
                    }
                    _ => Err(DomainError::Unknown(format!(
                        "Failed to read IFEO Debugger for {}: status={}",
                        target
                        ,
                        status.0
                    ))),
                };
            }

            let mut buffer: Vec<u16> = vec![0u16; (size_bytes as usize / 2).max(1)];
            let status = unsafe {
                RegGetValueW(
                    key,
                    PCWSTR::null(),
                    PCWSTR(debugger_name.as_ptr()),
                    RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                    Some(&mut value_type),
                    Some(buffer.as_mut_ptr() as *mut _),
                    Some(&mut size_bytes),
                )
            };
            let _ = unsafe { RegCloseKey(key) };
            if status != ERROR_SUCCESS {
                return match status.0 {
                    2 => Ok(None),
                    code if code == ERROR_ACCESS_DENIED.0 => {
                        Err(DomainError::RegistryAccessDenied(format!(
                            "Access denied reading IFEO for {}",
                            target
                        )))
                    }
                    _ => Err(DomainError::Unknown(format!(
                        "Failed to read IFEO Debugger for {}: status={}",
                        target
                        ,
                        status.0
                    ))),
                };
            }
            // size_bytesは終端nullを含むため適切に切り詰める
            let char_len = (size_bytes as usize / 2).saturating_sub(1);
            buffer.truncate(char_len);
            let value = String::from_utf16_lossy(&buffer);
            Ok(Some(value))
        }

        fn set_debugger(
            &self,
            target: &str,
            view: RegistryView,
            path: &str,
        ) -> Result<(), DomainError> {
            let key = open_or_create_key(target, view)?;
            let value = format_debugger_value_for_write(path, view, &self.debugger_path);
            let data = to_wide(&value);
            let debugger_name = to_wide("Debugger"); // API呼び出し中にVecを生存させる
            let status = unsafe {
                RegSetValueExW(
                    key,
                    PCWSTR(debugger_name.as_ptr()),
                    Some(0),
                    REG_SZ,
                    Some(std::slice::from_raw_parts(
                        data.as_ptr() as *const u8,
                        data.len() * 2,
                    )),
                )
            };
            let _ = unsafe { RegCloseKey(key) };
            if status != ERROR_SUCCESS {
                return match status.0 {
                    code if code == ERROR_ACCESS_DENIED.0 => {
                        Err(DomainError::RegistryAccessDenied(format!(
                            "Access denied writing IFEO for {}",
                            target
                        )))
                    }
                    _ => Err(DomainError::Unknown(format!(
                        "Failed to write IFEO Debugger for {}: status={}",
                        target
                        ,
                        status.0
                    ))),
                };
            }
            Ok(())
        }

        fn remove_debugger(&self, target: &str, view: RegistryView) -> Result<(), DomainError> {
            let key = match open_existing_key_write(target, view) {
                Ok(k) => k,
                Err(DomainError::TargetNotFound(_)) => return Ok(()),
                Err(e) => return Err(e),
            };
            let debugger_name = to_wide("Debugger"); // API呼び出し中にVecを生存させる
            let status = unsafe { RegDeleteValueW(key, PCWSTR(debugger_name.as_ptr())) };
            let _ = unsafe { RegCloseKey(key) };
            if status != ERROR_SUCCESS {
                return match status.0 {
                    2 => Ok(()), // 値が見つからない
                    code if code == ERROR_ACCESS_DENIED.0 => {
                        Err(DomainError::RegistryAccessDenied(format!(
                            "Access denied deleting IFEO for {}",
                            target
                        )))
                    }
                    _ => Err(DomainError::Unknown(format!(
                        "Failed to delete IFEO Debugger for {}: status={}",
                        target
                        ,
                        status.0
                    ))),
                };
            }
            Ok(())
        }

        fn list_all_targets(&self, view: RegistryView) -> Result<Vec<(String, String)>, DomainError> {
            list_ifeo_targets_with_debugger(self, view)
        }
    }

    impl LeaseStore for WindowsRegistryAdapter {
        fn read_lease(&self) -> Result<Option<LeaseState>, DomainError> {
            read_lease_state()
        }

        fn write_lease(&self, state: &LeaseState) -> Result<(), DomainError> {
            write_lease_state(state)
        }

        fn clear_lease(&self) -> Result<(), DomainError> {
            clear_lease_state()
        }
    }

    pub(super) fn get_debugger_value_impl(
        target: &str,
        view: RegistryView,
    ) -> Result<Option<DebuggerValue>, DomainError> {
        let key = match open_existing_key_readonly(target, view) {
            Ok(k) => k,
            Err(DomainError::TargetNotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };

        let debugger_name = to_wide("Debugger");
        let mut value_type = REG_VALUE_TYPE(0);
        let mut size_bytes: u32 = 0;
        let status = unsafe {
            RegGetValueW(
                key,
                PCWSTR::null(),
                PCWSTR(debugger_name.as_ptr()),
                RRF_RT_ANY,
                Some(&mut value_type),
                None,
                Some(&mut size_bytes),
            )
        };
        if status != ERROR_SUCCESS {
            let _ = unsafe { RegCloseKey(key) };
            return match status.0 {
                2 => Ok(None),
                code if code == ERROR_ACCESS_DENIED.0 => {
                    Err(DomainError::RegistryAccessDenied(format!(
                        "Access denied reading IFEO for {}",
                        target
                    )))
                }
                _ => Err(DomainError::Unknown(format!(
                    "Failed to read IFEO Debugger for {}: status={}",
                    target
                    ,
                    status.0
                ))),
            };
        }

        let mut data: Vec<u8> = vec![0u8; size_bytes as usize];
        if size_bytes > 0 {
            let status = unsafe {
                RegGetValueW(
                    key,
                    PCWSTR::null(),
                    PCWSTR(debugger_name.as_ptr()),
                    RRF_RT_ANY,
                    Some(&mut value_type),
                    Some(data.as_mut_ptr() as *mut _),
                    Some(&mut size_bytes),
                )
            };
            if status != ERROR_SUCCESS {
                let _ = unsafe { RegCloseKey(key) };
                return Err(DomainError::Unknown(format!(
                    "Failed to read IFEO Debugger for {}: status={}",
                    target
                    ,
                    status.0
                )));
            }
            data.truncate(size_bytes as usize);
        }

        let _ = unsafe { RegCloseKey(key) };

        match value_type {
            REG_SZ | REG_EXPAND_SZ => {
                let raw = decode_utf16(&data);
                let expanded = if value_type == REG_EXPAND_SZ {
                    expand_env_string(&raw).ok()
                } else {
                    None
                };
                Ok(Some(DebuggerValue::String {
                    raw,
                    expanded,
                    value_type: value_type.0,
                }))
            }
            _ => Ok(Some(DebuggerValue::Other {
                value_type: value_type.0,
                bytes: data,
            })),
        }
    }

    pub(super) fn classify_debugger_value(
        value: Option<DebuggerValue>,
        expected_debugger: &str,
    ) -> DebuggerOwnership {
        match value {
            None => DebuggerOwnership::Disabled,
            Some(v) if v.is_empty_string() => DebuggerOwnership::Disabled,
            Some(DebuggerValue::Other { .. }) => DebuggerOwnership::Foreign,
            Some(DebuggerValue::String { raw, expanded, .. }) => {
                let cmdline = expanded.as_deref().unwrap_or(raw.as_str());
                if kh_domain::service::ownership_service::is_owned_debugger(
                    cmdline,
                    expected_debugger,
                ) {
                    DebuggerOwnership::Owned
                } else {
                    DebuggerOwnership::Foreign
                }
            }
        }
    }

    fn decode_utf16(bytes: &[u8]) -> String {
        let mut wide: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i + 1 < bytes.len() {
            wide.push(u16::from_le_bytes([bytes[i], bytes[i + 1]]));
            i += 2;
        }
        while matches!(wide.last(), Some(0)) {
            wide.pop();
        }
        String::from_utf16_lossy(&wide)
    }

    fn expand_env_string(raw: &str) -> Result<String, DomainError> {
        let src = to_wide(raw);
        unsafe {
            let required = ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), None);
            if required == 0 {
                return Err(DomainError::Unknown(
                    "ExpandEnvironmentStringsW failed".into(),
                ));
            }
            let mut buffer: Vec<u16> = vec![0u16; required as usize];
            let written = ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), Some(buffer.as_mut_slice()));
            if written == 0 {
                return Err(DomainError::Unknown(
                    "ExpandEnvironmentStringsW failed".into(),
                ));
            }
            if written > 0 {
                buffer.truncate((written as usize).saturating_sub(1));
            }
            Ok(String::from_utf16_lossy(&buffer))
        }
    }

    fn format_debugger_value(path: &str) -> String {
        let trimmed = path.trim();
        if trimmed.starts_with('"') && trimmed.ends_with('"') {
            trimmed.to_string()
        } else {
            format!("\"{}\"", trimmed)
        }
    }

    fn format_debugger_value_for_write(
        path: &str,
        view: RegistryView,
        our_debugger: &str,
    ) -> String {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            return format_debugger_value(trimmed);
        }
        if has_ifeo_view_flag(trimmed) {
            return trimmed.to_string();
        }
        if kh_domain::service::ownership_service::is_owned_debugger(trimmed, our_debugger) {
            return format_ifeo_view_debugger(our_debugger, view);
        }
        format_debugger_value(trimmed)
    }

    fn format_ifeo_view_debugger(path: &str, view: RegistryView) -> String {
        let exe = format_debugger_value(path);
        let view_flag = match view {
            RegistryView::Bit64 => "--ifeo-view=64",
            RegistryView::Bit32 => "--ifeo-view=32",
        };
        format!("{} {}", exe, view_flag)
    }

    fn has_ifeo_view_flag(cmdline: &str) -> bool {
        cmdline.to_ascii_lowercase().contains("--ifeo-view")
    }

    /// デバッガ値が設定されている全IFEOサブキーを列挙
    fn list_ifeo_targets_with_debugger(
        adapter: &WindowsRegistryAdapter,
        view: RegistryView,
    ) -> Result<Vec<(String, String)>, DomainError> {
        use windows::Win32::System::Registry::{
            KEY_ENUMERATE_SUB_KEYS, RegEnumKeyExW,
        };

        let base_path = match view {
            RegistryView::Bit64 => IFEO_BASE_64,
            RegistryView::Bit32 => IFEO_BASE_32,
        };
        let wide_path = to_wide(base_path);
        let mut key: HKEY = HKEY::default();
        let sam = sam_with_view(KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, view);

        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(wide_path.as_ptr()),
                Some(0),
                sam,
                &mut key,
            )
        };
        if status != ERROR_SUCCESS {
            return Ok(Vec::new()); // IFEOキーが存在しない/アクセス不可
        }

        let mut results = Vec::new();
        let mut index: u32 = 0;
        let mut name_buf: [u16; 260] = [0; 260];

        loop {
            let mut name_len = name_buf.len() as u32;
            let enum_status = unsafe {
                RegEnumKeyExW(
                    key,
                    index,
                    Some(PWSTR(name_buf.as_mut_ptr())),
                    &mut name_len,
                    None,
                    None, // 予約
                    None, // クラス
                    None, // 最終書き込み時刻
                )
            };

            if enum_status != ERROR_SUCCESS {
                break; // サブキー終了
            }

            // 名前をStringに変換
            let target_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);

            // デバッガ値があるか確認
            if let Ok(Some(debugger)) = adapter.get_debugger(&target_name, view) {
                results.push((target_name, debugger));
            }

            index += 1;
        }

        let _ = unsafe { RegCloseKey(key) };
        Ok(results)
    }

    fn open_or_create_key(target: &str, view: RegistryView) -> Result<HKEY, DomainError> {
        let path = subkey_path(target, view);
        let wide_path = to_wide(&path); // API呼び出し中にVecを生存させる
        let mut key: HKEY = HKEY::default();
        // ベースパスは共通。KEY_WOW64_* フラグでビューを選択する。
        let sam = sam_with_view(KEY_SET_VALUE | KEY_QUERY_VALUE, view);
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(wide_path.as_ptr()),
                Some(0),
                None,
                REG_OPTION_NON_VOLATILE,
                sam,
                None,
                &mut key,
                None,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(map_win32_error(status, target));
        }
        Ok(key)
    }

    fn open_existing_key_readonly(target: &str, view: RegistryView) -> Result<HKEY, DomainError> {
        let path = subkey_path(target, view);
        let wide_path = to_wide(&path); // API呼び出し中にVecを生存させる
        let mut key: HKEY = HKEY::default();
        // get_debugger用の読み取りアクセス
        let sam = sam_with_view(KEY_QUERY_VALUE, view);
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(wide_path.as_ptr()),
                Some(0),
                sam,
                &mut key,
            )
        };
        if status != ERROR_SUCCESS {
            return match status.0 {
                2 => Err(DomainError::TargetNotFound(target.into())),
                _ => Err(map_win32_error(status, target)),
            };
        }
        Ok(key)
    }

    fn open_existing_key_write(target: &str, view: RegistryView) -> Result<HKEY, DomainError> {
        let path = subkey_path(target, view);
        let wide_path = to_wide(&path); // API呼び出し中にVecを生存させる
        let mut key: HKEY = HKEY::default();
        // remove_debugger用の書き込みアクセス
        let sam = sam_with_view(KEY_SET_VALUE | KEY_QUERY_VALUE, view);
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(wide_path.as_ptr()),
                Some(0),
                sam,
                &mut key,
            )
        };
        if status != ERROR_SUCCESS {
            return match status.0 {
                2 => Err(DomainError::TargetNotFound(target.into())),
                _ => Err(map_win32_error(status, target)),
            };
        }
        Ok(key)
    }

    fn subkey_path(target: &str, view: RegistryView) -> String {
        let base = match view {
            RegistryView::Bit64 => IFEO_BASE_64,
            RegistryView::Bit32 => IFEO_BASE_32,
        };
        format!("{}\\{}", base, target)
    }

    fn to_wide(s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }

    fn map_win32_error(status: WIN32_ERROR, target: &str) -> DomainError {
        if status == ERROR_ACCESS_DENIED {
            return DomainError::RegistryAccessDenied(format!("Access denied for target {}", target));
        }
        if status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND {
            return DomainError::Unknown(format!(
                "Registry entry not found for {}: status={}",
                target, status.0
            ));
        }
        if status == ERROR_INVALID_DATA {
            return DomainError::Unknown(format!(
                "Registry data invalid for {}: status={}",
                target, status.0
            ));
        }
        DomainError::Unknown(format!(
            "Registry error for {}: status={}",
            target, status.0
        ))
    }

    fn sam_with_view(base: REG_SAM_FLAGS, view: RegistryView) -> REG_SAM_FLAGS {
        base | match view {
            RegistryView::Bit64 => KEY_WOW64_64KEY,
            RegistryView::Bit32 => KEY_WOW64_32KEY,
        }
    }
}

// Windows実装のトレイトは境界で自動的に利用できる

// ============================================================================
// Targetsレジストリ補助（Windows）
// ============================================================================

#[cfg(windows)]
fn read_enabled_targets_impl() -> Result<HashSet<String>, DomainError> {
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY, RRF_RT_REG_DWORD,
        RRF_RT_REG_MULTI_SZ, RegCloseKey, RegGetValueW, RegOpenKeyExW,
    };
    use windows::core::PCWSTR;

    fn to_wide(s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }

    let path = to_wide(TARGETS_REG_PATH);
    let mut key: HKEY = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            Some(0),
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(match status {
            s if s == ERROR_ACCESS_DENIED => DomainError::RegistryAccessDenied(
                "failed to open Targets key".into(),
            ),
            s if s == ERROR_FILE_NOT_FOUND || s == ERROR_PATH_NOT_FOUND => {
                DomainError::InvalidConfig("Targets registry not found".into())
            }
            _ => DomainError::Unknown(format!(
                "failed to open Targets key: status={}",
                status.0
            )),
        });
    }

    let schema_name = to_wide("SchemaVersion");
    let mut schema_value: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            key,
            PCWSTR::null(),
            PCWSTR(schema_name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut schema_value as *mut _ as *mut _),
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS || schema_value != TARGETS_SCHEMA_VERSION {
        let _ = unsafe { RegCloseKey(key) };
        return Err(DomainError::InvalidConfig(
            "invalid schema version".into(),
        ));
    }

    let enabled_name = to_wide("Enabled");
    let mut size_bytes: u32 = 0;
    let status = unsafe {
        RegGetValueW(
            key,
            PCWSTR::null(),
            PCWSTR(enabled_name.as_ptr()),
            RRF_RT_REG_MULTI_SZ,
            None,
            None,
            Some(&mut size_bytes),
        )
    };
    if status != ERROR_SUCCESS || size_bytes == 0 {
        let _ = unsafe { RegCloseKey(key) };
        return Err(DomainError::InvalidConfig(
            "failed to read Enabled list".into(),
        ));
    }

    let mut buffer: Vec<u16> = vec![0u16; size_bytes as usize / 2];
    let status = unsafe {
        RegGetValueW(
            key,
            PCWSTR::null(),
            PCWSTR(enabled_name.as_ptr()),
            RRF_RT_REG_MULTI_SZ,
            None,
            Some(buffer.as_mut_ptr() as *mut _),
            Some(&mut size_bytes),
        )
    };
    let _ = unsafe { RegCloseKey(key) };
    if status != ERROR_SUCCESS {
        return Err(DomainError::InvalidConfig(
            "failed to read Enabled list".into(),
        ));
    }

    let len = (size_bytes as usize / 2).saturating_sub(1);
    buffer.truncate(len);
    let mut set = HashSet::new();
    let mut saw_entry = false;
    let mut current = String::new();
    for ch in String::from_utf16_lossy(&buffer).chars() {
        if ch == '\u{0}' {
            if !current.is_empty() {
                saw_entry = true;
                let normalized = current.to_ascii_lowercase();
                if Target::validate_name(&normalized).is_ok() {
                    set.insert(normalized);
                }
                current.clear();
            }
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        saw_entry = true;
        let normalized = current.to_ascii_lowercase();
        if Target::validate_name(&normalized).is_ok() {
            set.insert(normalized);
        }
    }
    if !saw_entry {
        return Ok(set);
    }
    if set.is_empty() {
        return Err(DomainError::InvalidConfig(
            "enabled targets list contains no valid entries".into(),
        ));
    }
    Ok(set)
}

#[cfg(not(windows))]
fn read_enabled_targets_impl() -> Result<HashSet<String>, DomainError> {
    Ok(HashSet::new())
}

#[cfg(windows)]
fn write_enabled_targets_impl(targets: &[String]) -> Result<(), DomainError> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::Storage::FileSystem::WRITE_DAC;
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, RegCloseKey, HKEY_LOCAL_MACHINE, KEY_CREATE_SUB_KEY,
        KEY_SET_VALUE, KEY_WOW64_64KEY, REG_DWORD, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE,
        REG_SAM_FLAGS,
    };
    use windows::core::PCWSTR;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let mut normalized: Vec<String> = targets
        .iter()
        .map(|t| t.to_ascii_lowercase())
        .filter(|t| Target::validate_name(t).is_ok())
        .collect();
    normalized.sort();
    normalized.dedup();

    let key_path: Vec<u16> = OsStr::new(TARGETS_REG_PATH)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    struct RegKeyGuard(windows::Win32::System::Registry::HKEY);
    impl Drop for RegKeyGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_path.as_ptr()),
            Some(0),
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY | REG_SAM_FLAGS(WRITE_DAC.0),
            None,
            &mut hkey,
            None,
        );
        if status.0 != ERROR_SUCCESS.0 {
            return Err(DomainError::RegistryAccessDenied(format!(
                "RegCreateKeyExW failed: status={}",
                status.0
            )));
        }
        let _guard = RegKeyGuard(hkey);

        let schema_name: Vec<u16> = OsStr::new("SchemaVersion")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let schema_value = (TARGETS_SCHEMA_VERSION as u32).to_le_bytes();
        let status = RegSetValueExW(
            hkey,
            PCWSTR(schema_name.as_ptr()),
            Some(0),
            REG_DWORD,
            Some(&schema_value),
        );
        if status != ERROR_SUCCESS {
            return Err(DomainError::Unknown(format!(
                "Failed to set SchemaVersion: status={}",
                status.0
            )));
        }

        let mut multi: Vec<u16> = Vec::new();
        if normalized.is_empty() {
            multi.push(0);
            multi.push(0);
        } else {
            for value in &normalized {
                multi.extend(OsStr::new(value).encode_wide());
                multi.push(0);
            }
            multi.push(0);
        }
        let enabled_name: Vec<u16> = OsStr::new("Enabled")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let bytes = &multi.align_to::<u8>().1[..multi.len() * 2];
        let status = RegSetValueExW(
            hkey,
            PCWSTR(enabled_name.as_ptr()),
            Some(0),
            REG_MULTI_SZ,
            Some(bytes),
        );
        if status != ERROR_SUCCESS {
            return Err(DomainError::Unknown(format!(
                "Failed to set Enabled list: status={}",
                status.0
            )));
        }

        apply_registry_key_acl(hkey, TARGETS_SDDL_AU_READ)?;
    }

    Ok(())
}

#[cfg(not(windows))]
fn write_enabled_targets_impl(_targets: &[String]) -> Result<(), DomainError> {
    Ok(())
}

// ============================================================================
// リース状態レジストリ（Windows）
// ============================================================================

#[cfg(windows)]
fn read_lease_state_impl() -> Result<Option<LeaseState>, DomainError> {
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    };
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY, REG_VALUE_TYPE,
        RRF_RT_REG_DWORD, RRF_RT_REG_QWORD, RRF_RT_REG_SZ, RegCloseKey, RegGetValueW,
        RegOpenKeyExW,
    };
    use windows::core::PCWSTR;
    fn to_wide(s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }

    let path = to_wide(LEASE_STATE_REG_PATH);
    let mut key: HKEY = HKEY::default();
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path.as_ptr()),
            Some(0),
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if status != ERROR_SUCCESS {
        return match status {
            s if s == ERROR_FILE_NOT_FOUND || s == ERROR_PATH_NOT_FOUND => Ok(None),
            s if s == ERROR_ACCESS_DENIED => Err(DomainError::RegistryAccessDenied(
                "failed to open LeaseState key".into(),
            )),
            _ => Err(DomainError::Unknown(format!(
                "failed to open LeaseState key: status={}",
                status.0
            ))),
        };
    }

    let schema_name = to_wide("SchemaVersion");
    let mut schema_value: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            key,
            PCWSTR::null(),
            PCWSTR(schema_name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut schema_value as *mut _ as *mut _),
            Some(&mut size),
        )
    };
    if status != ERROR_SUCCESS || schema_value != LEASE_STATE_SCHEMA_VERSION {
        let _ = unsafe { RegCloseKey(key) };
        return Err(DomainError::InvalidConfig(
            "invalid lease schema version".into(),
        ));
    }

    let target_name = to_wide("Target");
    let mut size_bytes: u32 = 0;
    let status = unsafe {
        RegGetValueW(
            key,
            PCWSTR::null(),
            PCWSTR(target_name.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut size_bytes),
        )
    };
    if status != ERROR_SUCCESS || size_bytes == 0 {
        let _ = unsafe { RegCloseKey(key) };
        return Err(DomainError::InvalidConfig(
            "failed to read lease target".into(),
        ));
    }

    let mut buffer: Vec<u16> = vec![0u16; size_bytes as usize / 2];
    let status = unsafe {
        RegGetValueW(
            key,
            PCWSTR::null(),
            PCWSTR(target_name.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr() as *mut _),
            Some(&mut size_bytes),
        )
    };
    if status != ERROR_SUCCESS {
        let _ = unsafe { RegCloseKey(key) };
        return Err(DomainError::InvalidConfig(
            "failed to read lease target".into(),
        ));
    }
    let len = (size_bytes as usize / 2).saturating_sub(1);
    buffer.truncate(len);
    let target = String::from_utf16_lossy(&buffer).trim().to_ascii_lowercase();
    if target.is_empty() {
        let _ = unsafe { RegCloseKey(key) };
        return Err(DomainError::InvalidConfig(
            "lease target empty".into(),
        ));
    }

    let expires_name = to_wide("ExpiresAtMs");
    let mut value_type = REG_VALUE_TYPE(0);
    let mut expires: u64 = 0;
    let mut size = std::mem::size_of::<u64>() as u32;
    let status = unsafe {
        RegGetValueW(
            key,
            PCWSTR::null(),
            PCWSTR(expires_name.as_ptr()),
            RRF_RT_REG_QWORD,
            Some(&mut value_type),
            Some(&mut expires as *mut _ as *mut _),
            Some(&mut size),
        )
    };
    let _ = unsafe { RegCloseKey(key) };
    if status != ERROR_SUCCESS {
        return Err(DomainError::InvalidConfig(
            "failed to read lease expiry".into(),
        ));
    }

    Ok(Some(LeaseState {
        target: target.to_string(),
        expires_at_ms: expires,
    }))
}

#[cfg(not(windows))]
fn read_lease_state_impl() -> Result<Option<LeaseState>, DomainError> {
    Ok(None)
}

#[cfg(windows)]
fn write_lease_state_impl(state: &LeaseState) -> Result<(), DomainError> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::Storage::FileSystem::WRITE_DAC;
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, RegCloseKey, HKEY_LOCAL_MACHINE, KEY_CREATE_SUB_KEY,
        KEY_SET_VALUE, KEY_WOW64_64KEY, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_QWORD, REG_SAM_FLAGS,
        REG_SZ,
    };
    use windows::core::PCWSTR;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let key_path: Vec<u16> = OsStr::new(LEASE_STATE_REG_PATH)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    struct RegKeyGuard(windows::Win32::System::Registry::HKEY);
    impl Drop for RegKeyGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }

    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_path.as_ptr()),
            Some(0),
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY | REG_SAM_FLAGS(WRITE_DAC.0),
            None,
            &mut hkey,
            None,
        );
        if status.0 != ERROR_SUCCESS.0 {
            return Err(DomainError::RegistryAccessDenied(format!(
                "RegCreateKeyExW failed: status={}",
                status.0
            )));
        }
        let _guard = RegKeyGuard(hkey);
        apply_registry_key_acl(hkey, LEASE_STATE_SDDL_ADMIN_ONLY)?;

        let schema_name: Vec<u16> = OsStr::new("SchemaVersion")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let schema_value = (LEASE_STATE_SCHEMA_VERSION as u32).to_le_bytes();
        let status = RegSetValueExW(
            hkey,
            PCWSTR(schema_name.as_ptr()),
            Some(0),
            REG_DWORD,
            Some(&schema_value),
        );
        if status != ERROR_SUCCESS {
            return Err(DomainError::Unknown(format!(
                "Failed to set lease SchemaVersion: status={}",
                status.0
            )));
        }

        let target_name: Vec<u16> = OsStr::new("Target")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let target_normalized = state.target.to_ascii_lowercase();
        let target_value: Vec<u16> = OsStr::new(&target_normalized)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let target_bytes = &target_value.align_to::<u8>().1[..target_value.len() * 2];
        let status = RegSetValueExW(
            hkey,
            PCWSTR(target_name.as_ptr()),
            Some(0),
            REG_SZ,
            Some(target_bytes),
        );
        if status != ERROR_SUCCESS {
            return Err(DomainError::Unknown(format!(
                "Failed to set lease target: status={}",
                status.0
            )));
        }

        let expires_name: Vec<u16> = OsStr::new("ExpiresAtMs")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let expires_value = state.expires_at_ms.to_le_bytes();
        let status = RegSetValueExW(
            hkey,
            PCWSTR(expires_name.as_ptr()),
            Some(0),
            REG_QWORD,
            Some(&expires_value),
        );
        if status != ERROR_SUCCESS {
            return Err(DomainError::Unknown(format!(
                "Failed to set lease expiry: status={}",
                status.0
            )));
        }
    }

    Ok(())
}

#[cfg(not(windows))]
fn write_lease_state_impl(_state: &LeaseState) -> Result<(), DomainError> {
    Ok(())
}

#[cfg(windows)]
fn clear_lease_state_impl() -> Result<(), DomainError> {
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    };
    use windows::Win32::System::Registry::{RegDeleteKeyW, RegDeleteTreeW, HKEY_LOCAL_MACHINE};
    use windows::core::PCWSTR;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let key_path: Vec<u16> = OsStr::new(LEASE_STATE_REG_PATH)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(key_path.as_ptr()));
        if status != ERROR_SUCCESS
            && status != ERROR_FILE_NOT_FOUND
            && status != ERROR_PATH_NOT_FOUND
        {
            return Err(match status {
                s if s == ERROR_ACCESS_DENIED => DomainError::RegistryAccessDenied(
                    "failed to delete LeaseState key".into(),
                ),
                _ => DomainError::Unknown(format!(
                    "failed to delete LeaseState tree: status={}",
                    status.0
                )),
            });
        }
        let status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR(key_path.as_ptr()));
        if status != ERROR_SUCCESS
            && status != ERROR_FILE_NOT_FOUND
            && status != ERROR_PATH_NOT_FOUND
        {
            return Err(match status {
                s if s == ERROR_ACCESS_DENIED => DomainError::RegistryAccessDenied(
                    "failed to delete LeaseState key".into(),
                ),
                _ => DomainError::Unknown(format!(
                    "failed to delete LeaseState key: status={}",
                    status.0
                )),
            });
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn clear_lease_state_impl() -> Result<(), DomainError> {
    Ok(())
}

#[cfg(windows)]
fn apply_registry_key_acl(
    hkey: windows::Win32::System::Registry::HKEY,
    sddl: &str,
) -> Result<(), DomainError> {
    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::System::Registry::RegSetKeySecurity;
    use windows::core::PCWSTR;

    fn to_wide(s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }

    let sddl_w = to_wide(sddl);
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1 as u32,
            &mut sd,
            None,
        )
        .map_err(|e| DomainError::Unknown(format!("SDDL parse failed: {}", e.message())))?;

        let info: OBJECT_SECURITY_INFORMATION =
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        let status = RegSetKeySecurity(hkey, info, sd);

        let _ = LocalFree(Some(HLOCAL(sd.0)));
        if status != ERROR_SUCCESS {
            return Err(DomainError::Unknown(format!(
                "RegSetKeySecurity failed: status={}",
                status.0
            )));
        }
    }
    Ok(())
}
