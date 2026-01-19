#![allow(clippy::result_large_err)]

#[derive(Debug, Clone)]
pub struct ReportItem {
    pub target: String,
    pub view: String,
    pub outcome: String,
    pub detail: String,
    pub read_back_ok: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct IfeoRestoreReport {
    pub processed: u32,
    pub items: Vec<ReportItem>,
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum ForeignPolicy {
    Skip,
    Force,
    Error,
    Prompt(fn(&str, &str, &str) -> bool),
}

#[derive(Clone, Debug)]
pub struct RestoreOptions {
    pub expected_debugger_path: String,
    pub foreign_policy: ForeignPolicy,
    pub logger: Option<fn(&str)>,
}

pub fn restore_ifeo_from_uninstall_state(
    options: &RestoreOptions,
) -> Result<IfeoRestoreReport, String> {
    #[cfg(windows)]
    {
        return windows_impl::restore_ifeo_from_uninstall_state(options);
    }
    #[cfg(not(windows))]
    {
        let _ = options;
        Ok(IfeoRestoreReport::default())
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::{ForeignPolicy, IfeoRestoreReport, ReportItem, RestoreOptions};
    use kh_domain::path::normalize_local_drive_absolute_path;
    use std::collections::HashSet;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    use windows::Win32::System::Environment::ExpandEnvironmentStringsW;
    use windows::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, KEY_WRITE, KEY_WOW64_32KEY,
        KEY_WOW64_64KEY, REG_BINARY, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ,
        REG_VALUE_TYPE, RRF_RT_ANY, RRF_RT_REG_BINARY, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
        RegSetValueExW,
    };
    use windows::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
    use windows::Win32::UI::Shell::CommandLineToArgvW;
    use windows::core::{PCWSTR, PWSTR};

    const UNINSTALL_IFEO_BACKUPS_REG_PATH: &str =
        r"SOFTWARE\KaptainhooK\UninstallState\IfeoBackups";
    const IFEO_BASE: &str =
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    const IFEO_MUTEX_NAME: &str = r"Global\KaptainhooKIfeoMutex";

    const INSTALL_ACTION_NONE: u32 = 0;
    const INSTALL_ACTION_TAKE_OVER: u32 = 1;
    const INSTALL_ACTION_QUARANTINE: u32 = 2;

    #[derive(Debug, Clone)]
    struct BackupRecord {
        kind: u32,
        raw: Option<String>,
        reg_type: Option<u32>,
        bytes: Option<Vec<u8>>,
        install_action: u32,
    }

    #[derive(Debug, Clone)]
    struct BackupItem {
        target: String,
        view_name: String,
        view_flag: REG_SAM_FLAGS,
        record: BackupRecord,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DebuggerOwnership {
        Owned,
        Foreign,
        Disabled,
    }

    #[derive(Debug, Clone)]
    enum DebuggerValue {
        String { raw: String, value_type: u32 },
        Other { value_type: u32, bytes: Vec<u8> },
    }

    struct IfeoMutexGuard(HANDLE);
    impl Drop for IfeoMutexGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = windows::Win32::System::Threading::ReleaseMutex(self.0);
                let _ = CloseHandle(self.0);
            }
        }
    }

    pub(super) fn restore_ifeo_from_uninstall_state(
        options: &RestoreOptions,
    ) -> Result<IfeoRestoreReport, String> {
        let _ifeo_lock = acquire_ifeo_mutex(5000)?;
        let ifeo_path = IFEO_BASE;
        let our_debugger = options.expected_debugger_path.clone();
        let mut processed = 0u32;
        let mut items: Vec<ReportItem> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        let backup_items = load_uninstall_backups()?;
        let mut backup_set = HashSet::new();
        for item in &backup_items {
            backup_set.insert((item.target.clone(), item.view_flag.0));
        }

        for item in backup_items {
            let current = read_debugger_value(&item.target, item.view_flag)?;
            let current_summary = format_debugger_value(&current);
            let ownership = classify_debugger_value(current.clone(), &our_debugger);
            if matches!(ownership, DebuggerOwnership::Foreign) {
                let detail = format_foreign_detail(item.record.install_action);
                log(options, &format!(
                    "Foreign debugger detected for {} ({})",
                    item.target, item.view_name
                ));

                let should_restore = match options.foreign_policy {
                    ForeignPolicy::Force => true,
                    ForeignPolicy::Skip => false,
                    ForeignPolicy::Error => {
                        let err = format!(
                            "foreign debugger detected for {} ({})",
                            item.target, item.view_name
                        );
                        errors.push(err);
                        items.push(ReportItem {
                            target: item.target.clone(),
                            view: item.view_name.clone(),
                            outcome: "failed".to_string(),
                            detail,
                            read_back_ok: None,
                        });
                        continue;
                    }
                    ForeignPolicy::Prompt(prompt) => {
                        prompt(&item.target, &item.view_name, &current_summary)
                    }
                };

                if !should_restore {
                    log(options, &format!(
                        "Skipping foreign debugger for {} ({})",
                        item.target, item.view_name
                    ));
                    items.push(ReportItem {
                        target: item.target.clone(),
                        view: item.view_name.clone(),
                        outcome: "skipped".to_string(),
                        detail,
                        read_back_ok: None,
                    });
                    continue;
                }
            }

            match restore_backup_value(&item, item.view_flag) {
                Ok(result) => {
                    processed += 1;
                    log(
                        options,
                        &format!(
                            "Restored IFEO for {} (view {}), read-back ok: {}",
                            item.target, item.view_name, result.read_back_ok
                        ),
                    );
                    items.push(ReportItem {
                        target: item.target.clone(),
                        view: item.view_name.clone(),
                        outcome: result.action.to_string(),
                        detail: result.detail,
                        read_back_ok: Some(result.read_back_ok),
                    });
                }
                Err(e) => {
                    items.push(ReportItem {
                        target: item.target.clone(),
                        view: item.view_name.clone(),
                        outcome: "failed".to_string(),
                        detail: e.clone(),
                        read_back_ok: None,
                    });
                    errors.push(e);
                }
            }
        }

        // バックアップなしで残りの自社エントリを削除
        unsafe {
            let ifeo_key_path = wstr(ifeo_path);
            for (view_name, wow_flag) in [("64", KEY_WOW64_64KEY), ("32", KEY_WOW64_32KEY)] {
                let mut ifeo_key = HKEY::default();
                let result = RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    PCWSTR(ifeo_key_path.as_ptr()),
                    Some(0),
                    KEY_READ | KEY_WRITE | wow_flag,
                    &mut ifeo_key,
                );
                if result != ERROR_SUCCESS {
                    continue;
                }

                let targets = enumerate_subkeys(ifeo_key)?;
                for target in targets {
                    if backup_set.contains(&(target.clone(), wow_flag.0)) {
                        continue;
                    }
                    let current = read_debugger_value(&target, wow_flag)?;
                    let ownership = classify_debugger_value(current, &our_debugger);
                    if matches!(ownership, DebuggerOwnership::Owned) {
                        match delete_debugger_value(&target, wow_flag) {
                            Ok(()) => {
                                let read_back_ok = match read_debugger_value(&target, wow_flag) {
                                    Ok(v) => v.is_none(),
                                    Err(_) => false,
                                };
                                processed += 1;
                                log(
                                    options,
                                    &format!("Removed IFEO for {} (view {})", target, view_name),
                                );
                                items.push(ReportItem {
                                    target: target.clone(),
                                    view: view_name.to_string(),
                                    outcome: "removed".to_string(),
                                    detail: "owned without backup".to_string(),
                                    read_back_ok: Some(read_back_ok),
                                });
                            }
                            Err(e) => {
                                items.push(ReportItem {
                                    target: target.clone(),
                                    view: view_name.to_string(),
                                    outcome: "failed".to_string(),
                                    detail: e.clone(),
                                    read_back_ok: None,
                                });
                                errors.push(e);
                            }
                        }
                    }
                }
                let _ = RegCloseKey(ifeo_key);
            }
        }

        Ok(IfeoRestoreReport {
            processed,
            items,
            errors,
        })
    }

    fn log(options: &RestoreOptions, message: &str) {
        if let Some(logger) = options.logger {
            logger(message);
        }
    }

    fn acquire_ifeo_mutex(timeout_ms: u32) -> Result<IfeoMutexGuard, String> {
        let name = wstr(IFEO_MUTEX_NAME);
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }
            .map_err(|e| format!("CreateMutexW failed: {}", e.message()))?;
        let wait = unsafe { WaitForSingleObject(handle, timeout_ms) };
        match wait {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(IfeoMutexGuard(handle)),
            WAIT_TIMEOUT => {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                Err("IFEO mutex busy".to_string())
            }
            _ => {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                Err("WaitForSingleObject failed".to_string())
            }
        }
    }

    fn load_uninstall_backups() -> Result<Vec<BackupItem>, String> {
        unsafe {
            let root_w = wstr(UNINSTALL_IFEO_BACKUPS_REG_PATH);
            let mut root = HKEY::default();
            let result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(root_w.as_ptr()),
                Some(0),
                KEY_READ,
                &mut root,
            );
            if result != ERROR_SUCCESS {
                return Ok(Vec::new());
            }

            let targets = enumerate_subkeys(root)?;
            let mut items = Vec::new();

            for target in targets {
                let target_w = wstr(&target);
                let mut target_key = HKEY::default();
                let open_result = RegOpenKeyExW(
                    root,
                    PCWSTR(target_w.as_ptr()),
                    Some(0),
                    KEY_READ,
                    &mut target_key,
                );
                if open_result != ERROR_SUCCESS {
                    continue;
                }
                let view_keys = enumerate_subkeys(target_key)?;
                for view_name in view_keys {
                    if let Some(view_flag) = parse_view_flag(&view_name) {
                        let view_w = wstr(&view_name);
                        let mut view_key = HKEY::default();
                        let view_result = RegOpenKeyExW(
                            target_key,
                            PCWSTR(view_w.as_ptr()),
                            Some(0),
                            KEY_READ,
                            &mut view_key,
                        );
                        if view_result != ERROR_SUCCESS {
                            continue;
                        }
                        if let Some(record) = read_backup_record(view_key)? {
                            items.push(BackupItem {
                                target: target.clone(),
                                view_name: view_name.clone(),
                                view_flag,
                                record,
                            });
                        }
                        let _ = RegCloseKey(view_key);
                    }
                }
                let _ = RegCloseKey(target_key);
            }

            let _ = RegCloseKey(root);
            Ok(items)
        }
    }

    fn parse_view_flag(view: &str) -> Option<REG_SAM_FLAGS> {
        match view.to_ascii_lowercase().as_str() {
            "64" | "bit64" | "x64" => Some(KEY_WOW64_64KEY),
            "32" | "bit32" | "x86" => Some(KEY_WOW64_32KEY),
            _ => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::parse_view_flag;
        use windows::Win32::System::Registry::{KEY_WOW64_32KEY, KEY_WOW64_64KEY};

        #[test]
        fn parse_view_flag_accepts_legacy_and_numeric_names() {
            assert_eq!(parse_view_flag("64"), Some(KEY_WOW64_64KEY));
            assert_eq!(parse_view_flag("Bit64"), Some(KEY_WOW64_64KEY));
            assert_eq!(parse_view_flag("x64"), Some(KEY_WOW64_64KEY));
            assert_eq!(parse_view_flag("32"), Some(KEY_WOW64_32KEY));
            assert_eq!(parse_view_flag("Bit32"), Some(KEY_WOW64_32KEY));
            assert_eq!(parse_view_flag("x86"), Some(KEY_WOW64_32KEY));
            assert_eq!(parse_view_flag("unknown"), None);
        }
    }

    fn read_backup_record(hkey: HKEY) -> Result<Option<BackupRecord>, String> {
        let kind = read_reg_dword(hkey, "OriginalKind")?;
        let kind = match kind {
            Some(v) => v,
            None => return Ok(None),
        };
        let install_action = read_reg_dword(hkey, "InstallAction")?.unwrap_or(INSTALL_ACTION_NONE);

        let (raw, reg_type, bytes) = match kind {
            0 => (None, None, None),
            1 | 2 => (read_reg_string(hkey, "OriginalDebuggerRaw")?, None, None),
            3 => (
                None,
                read_reg_dword(hkey, "OriginalRegType")?,
                read_reg_binary(hkey, "OriginalBytes")?,
            ),
            _ => (None, None, None),
        };

        Ok(Some(BackupRecord {
            kind,
            raw,
            reg_type,
            bytes,
            install_action,
        }))
    }

    struct RestoreResult {
        action: &'static str,
        detail: String,
        read_back_ok: bool,
    }

    fn restore_backup_value(item: &BackupItem, view_flag: REG_SAM_FLAGS) -> Result<RestoreResult, String> {
        let action = match item.record.kind {
            0 => {
                delete_debugger_value(&item.target, view_flag)?;
                "removed"
            }
            1 => {
                set_debugger_string(&item.target, view_flag, item.record.raw.as_deref(), REG_SZ.0)?;
                "restored"
            }
            2 => {
                set_debugger_string(
                    &item.target,
                    view_flag,
                    item.record.raw.as_deref(),
                    REG_EXPAND_SZ.0,
                )?;
                "restored"
            }
            3 => {
                set_debugger_binary(
                    &item.target,
                    view_flag,
                    item.record.reg_type.unwrap_or(REG_BINARY.0),
                    item.record.bytes.as_deref().unwrap_or(&[]),
                )?;
                "restored"
            }
            _ => {
                return Err(format!(
                    "unsupported OriginalKind {}",
                    item.record.kind
                ));
            }
        };

        let read_back_ok = verify_backup_value(item, view_flag);
        Ok(RestoreResult {
            action,
            detail: format_backup_detail(item.record.kind, item.record.install_action),
            read_back_ok,
        })
    }

    fn verify_backup_value(item: &BackupItem, view_flag: REG_SAM_FLAGS) -> bool {
        let current = match read_debugger_value(&item.target, view_flag) {
            Ok(v) => v,
            Err(_) => return false,
        };
        match item.record.kind {
            0 => current.is_none(),
            1 => match current {
                Some(DebuggerValue::String { raw, value_type }) => {
                    value_type == REG_SZ.0 && item.record.raw.as_deref() == Some(raw.as_str())
                }
                _ => false,
            },
            2 => match current {
                Some(DebuggerValue::String { raw, value_type }) => {
                    value_type == REG_EXPAND_SZ.0 && item.record.raw.as_deref() == Some(raw.as_str())
                }
                _ => false,
            },
            3 => match current {
                Some(DebuggerValue::Other { value_type, bytes }) => {
                    value_type == item.record.reg_type.unwrap_or(REG_BINARY.0)
                        && Some(bytes.as_slice()) == item.record.bytes.as_deref()
                }
                _ => false,
            },
            _ => false,
        }
    }

    fn action_label(action: u32) -> Option<&'static str> {
        match action {
            INSTALL_ACTION_TAKE_OVER => Some("TakeOver"),
            INSTALL_ACTION_QUARANTINE => Some("Quarantine"),
            _ => None,
        }
    }

    fn format_backup_detail(kind: u32, action: u32) -> String {
        match action_label(action) {
            Some(label) => format!("OriginalKind={}; Action={}", kind, label),
            None => format!("OriginalKind={}", kind),
        }
    }

    fn format_foreign_detail(action: u32) -> String {
        match action_label(action) {
            Some(label) => format!("foreign debugger detected (action={})", label),
            None => "foreign debugger detected".to_string(),
        }
    }

    fn delete_debugger_value(target: &str, view_flag: REG_SAM_FLAGS) -> Result<(), String> {
        unsafe {
            let ifeo_path = wstr(IFEO_BASE);
            let mut ifeo_key = HKEY::default();
            let result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(ifeo_path.as_ptr()),
                Some(0),
                KEY_WRITE | view_flag,
                &mut ifeo_key,
            );
            if result != ERROR_SUCCESS {
                return Ok(());
            }

            let target_w = wstr(target);
            let mut target_key = HKEY::default();
            let open_result = RegOpenKeyExW(
                ifeo_key,
                PCWSTR(target_w.as_ptr()),
                Some(0),
                KEY_SET_VALUE,
                &mut target_key,
            );
            if open_result != ERROR_SUCCESS {
                let _ = RegCloseKey(ifeo_key);
                return Ok(());
            }

            let debugger_name = wstr("Debugger");
            let _ = RegDeleteValueW(target_key, PCWSTR(debugger_name.as_ptr()));
            let _ = RegCloseKey(target_key);
            let _ = RegCloseKey(ifeo_key);
        }
        Ok(())
    }

    fn set_debugger_string(
        target: &str,
        view_flag: REG_SAM_FLAGS,
        raw: Option<&str>,
        reg_type: u32,
    ) -> Result<(), String> {
        let raw = raw.unwrap_or("");
        let mut wide: Vec<u16> = OsStr::new(raw).encode_wide().collect();
        wide.push(0);

        unsafe {
            let ifeo_path = wstr(IFEO_BASE);
            let mut ifeo_key = HKEY::default();
            let status = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(ifeo_path.as_ptr()),
                Some(0),
                KEY_WRITE | view_flag,
                &mut ifeo_key,
            );
            if status != ERROR_SUCCESS {
                return Err(format!("Open IFEO failed: status={}", status.0));
            }

            let target_w = wstr(target);
            let mut target_key = HKEY::default();
            let status = RegCreateKeyExW(
                ifeo_key,
                PCWSTR(target_w.as_ptr()),
                Some(0),
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &mut target_key,
                None,
            );
            if status != ERROR_SUCCESS {
                let _ = RegCloseKey(ifeo_key);
                return Err(format!("Create target key failed: status={}", status.0));
            }

            let debugger_name = wstr("Debugger");
            let data = std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2);
            let status = RegSetValueExW(
                target_key,
                PCWSTR(debugger_name.as_ptr()),
                Some(0),
                REG_VALUE_TYPE(reg_type),
                Some(data),
            );
            if status != ERROR_SUCCESS {
                let _ = RegCloseKey(target_key);
                let _ = RegCloseKey(ifeo_key);
                return Err(format!("Set Debugger failed: status={}", status.0));
            }

            let _ = RegCloseKey(target_key);
            let _ = RegCloseKey(ifeo_key);
        }
        Ok(())
    }

    fn set_debugger_binary(
        target: &str,
        view_flag: REG_SAM_FLAGS,
        reg_type: u32,
        data: &[u8],
    ) -> Result<(), String> {
        unsafe {
            let ifeo_path = wstr(IFEO_BASE);
            let mut ifeo_key = HKEY::default();
            let status = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(ifeo_path.as_ptr()),
                Some(0),
                KEY_WRITE | view_flag,
                &mut ifeo_key,
            );
            if status != ERROR_SUCCESS {
                return Err(format!("Open IFEO failed: status={}", status.0));
            }

            let target_w = wstr(target);
            let mut target_key = HKEY::default();
            let status = RegCreateKeyExW(
                ifeo_key,
                PCWSTR(target_w.as_ptr()),
                Some(0),
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &mut target_key,
                None,
            );
            if status != ERROR_SUCCESS {
                let _ = RegCloseKey(ifeo_key);
                return Err(format!("Create target key failed: status={}", status.0));
            }

            let debugger_name = wstr("Debugger");
            let status = RegSetValueExW(
                target_key,
                PCWSTR(debugger_name.as_ptr()),
                Some(0),
                REG_VALUE_TYPE(reg_type),
                Some(data),
            );
            if status != ERROR_SUCCESS {
                let _ = RegCloseKey(target_key);
                let _ = RegCloseKey(ifeo_key);
                return Err(format!("Set Debugger failed: status={}", status.0));
            }

            let _ = RegCloseKey(target_key);
            let _ = RegCloseKey(ifeo_key);
        }
        Ok(())
    }

    fn read_debugger_value(target: &str, view_flag: REG_SAM_FLAGS) -> Result<Option<DebuggerValue>, String> {
        unsafe {
            let ifeo_path = wstr(IFEO_BASE);
            let mut ifeo_key = HKEY::default();
            let result = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(ifeo_path.as_ptr()),
                Some(0),
                KEY_READ | view_flag,
                &mut ifeo_key,
            );
            if result != ERROR_SUCCESS {
                return Ok(None);
            }

            let target_w = wstr(target);
            let mut target_key = HKEY::default();
            let open_result = RegOpenKeyExW(
                ifeo_key,
                PCWSTR(target_w.as_ptr()),
                Some(0),
                KEY_READ,
                &mut target_key,
            );
            if open_result != ERROR_SUCCESS {
                let _ = RegCloseKey(ifeo_key);
                return Ok(None);
            }

            let debugger_name = wstr("Debugger");
            let mut value_type = REG_VALUE_TYPE(0);
            let mut size_bytes: u32 = 0;
            let status = RegGetValueW(
                target_key,
                PCWSTR::null(),
                PCWSTR(debugger_name.as_ptr()),
                RRF_RT_ANY,
                Some(&mut value_type),
                None,
                Some(&mut size_bytes),
            );
            if status != ERROR_SUCCESS {
                let _ = RegCloseKey(target_key);
                let _ = RegCloseKey(ifeo_key);
                return Ok(None);
            }

            let mut data: Vec<u8> = vec![0u8; size_bytes as usize];
            if size_bytes > 0 {
                let status = RegGetValueW(
                    target_key,
                    PCWSTR::null(),
                    PCWSTR(debugger_name.as_ptr()),
                    RRF_RT_ANY,
                    Some(&mut value_type),
                    Some(data.as_mut_ptr() as *mut _),
                    Some(&mut size_bytes),
                );
                if status != ERROR_SUCCESS {
                    let _ = RegCloseKey(target_key);
                    let _ = RegCloseKey(ifeo_key);
                    return Err(format!("RegGetValueW failed: status={}", status.0));
                }
                data.truncate(size_bytes as usize);
            }

            let _ = RegCloseKey(target_key);
            let _ = RegCloseKey(ifeo_key);

            match value_type {
                REG_SZ | REG_EXPAND_SZ => {
                    let raw = decode_utf16(&data);
                    Ok(Some(DebuggerValue::String {
                        raw,
                        value_type: value_type.0,
                    }))
                }
                _ => Ok(Some(DebuggerValue::Other {
                    value_type: value_type.0,
                    bytes: data,
                })),
            }
        }
    }

    fn format_debugger_value(value: &Option<DebuggerValue>) -> String {
        match value {
            Some(DebuggerValue::String { raw, .. }) => raw.clone(),
            Some(DebuggerValue::Other { value_type, .. }) => {
                format!("<non-string debugger type {}>", value_type)
            }
            None => "<none>".to_string(),
        }
    }

    fn classify_debugger_value(value: Option<DebuggerValue>, expected_debugger: &str) -> DebuggerOwnership {
        let expected = match normalize_local_absolute_path(expected_debugger) {
            Some(p) => p,
            None => return DebuggerOwnership::Foreign,
        };

        match value {
            None => DebuggerOwnership::Disabled,
            Some(DebuggerValue::String { raw, value_type }) => {
                if raw.trim().is_empty() {
                    return DebuggerOwnership::Disabled;
                }
                let cmdline = if value_type == REG_EXPAND_SZ.0 {
                    expand_env_string(&raw).unwrap_or(raw)
                } else {
                    raw
                };
                let exe = match extract_argv0(&cmdline) {
                    Some(p) => p,
                    None => return DebuggerOwnership::Foreign,
                };
                let normalized = match normalize_local_absolute_path(&exe) {
                    Some(p) => p,
                    None => return DebuggerOwnership::Foreign,
                };
                if normalized.eq_ignore_ascii_case(&expected) {
                    DebuggerOwnership::Owned
                } else {
                    DebuggerOwnership::Foreign
                }
            }
            Some(DebuggerValue::Other { .. }) => DebuggerOwnership::Foreign,
        }
    }

    fn enumerate_subkeys(hkey: HKEY) -> Result<Vec<String>, String> {
        let mut names = Vec::new();
        let mut index = 0u32;
        loop {
            let mut buf = [0u16; 260];
            let mut len = buf.len() as u32;
            let result = unsafe {
                RegEnumKeyExW(
                    hkey,
                    index,
                    Some(PWSTR(buf.as_mut_ptr())),
                    &mut len,
                    None,
                    None,
                    None,
                    None,
                )
            };
            if result != ERROR_SUCCESS {
                if result == ERROR_NO_MORE_ITEMS {
                    break;
                }
                return Err(format!("RegEnumKeyExW failed: status={}", result.0));
            }
            if len > 0 {
                names.push(String::from_utf16_lossy(&buf[..len as usize]));
            }
            index += 1;
        }
        Ok(names)
    }

    fn read_reg_dword(hkey: HKEY, name: &str) -> Result<Option<u32>, String> {
        unsafe {
            let name_w = wstr(name);
            let mut value: u32 = 0;
            let mut size = std::mem::size_of::<u32>() as u32;
            let result = RegGetValueW(
                hkey,
                PCWSTR::null(),
                PCWSTR(name_w.as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some(&mut value as *mut _ as *mut _),
                Some(&mut size),
            );
            if result != ERROR_SUCCESS {
                return Ok(None);
            }
            Ok(Some(value))
        }
    }

    fn read_reg_string(hkey: HKEY, name: &str) -> Result<Option<String>, String> {
        unsafe {
            let name_w = wstr(name);
            let mut buffer: Vec<u16> = vec![0u16; 2048];
            let mut size_bytes: u32 = (buffer.len() * 2) as u32;
            let result = RegGetValueW(
                hkey,
                PCWSTR::null(),
                PCWSTR(name_w.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr() as *mut _),
                Some(&mut size_bytes),
            );
            if result != ERROR_SUCCESS {
                return Ok(None);
            }
            let len = (size_bytes as usize / 2).saturating_sub(1);
            buffer.truncate(len);
            Ok(Some(String::from_utf16_lossy(&buffer)))
        }
    }

    fn read_reg_binary(hkey: HKEY, name: &str) -> Result<Option<Vec<u8>>, String> {
        unsafe {
            let name_w = wstr(name);
            let mut size_bytes: u32 = 0;
            let result = RegGetValueW(
                hkey,
                PCWSTR::null(),
                PCWSTR(name_w.as_ptr()),
                RRF_RT_REG_BINARY,
                None,
                None,
                Some(&mut size_bytes),
            );
            if result != ERROR_SUCCESS {
                return Ok(None);
            }
            let mut data: Vec<u8> = vec![0u8; size_bytes as usize];
            let result = RegGetValueW(
                hkey,
                PCWSTR::null(),
                PCWSTR(name_w.as_ptr()),
                RRF_RT_REG_BINARY,
                None,
                Some(data.as_mut_ptr() as *mut _),
                Some(&mut size_bytes),
            );
            if result != ERROR_SUCCESS {
                return Ok(None);
            }
            data.truncate(size_bytes as usize);
            Ok(Some(data))
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

    fn expand_env_string(raw: &str) -> Option<String> {
        let src = wstr(raw);
        unsafe {
            let required = ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), None);
            if required == 0 {
                return None;
            }
            let mut buffer: Vec<u16> = vec![0u16; required as usize];
            let written = ExpandEnvironmentStringsW(PCWSTR(src.as_ptr()), Some(buffer.as_mut_slice()));
            if written == 0 {
                return None;
            }
            if written > 0 {
                buffer.truncate((written as usize).saturating_sub(1));
            }
            Some(String::from_utf16_lossy(&buffer))
        }
    }

    fn extract_argv0(cmdline: &str) -> Option<String> {
        let wide = wstr(cmdline);
        unsafe {
            let mut argc: i32 = 0;
            let argv = CommandLineToArgvW(PCWSTR(wide.as_ptr()), &mut argc);
            if argv.is_null() || argc < 1 {
                return None;
            }
            let first = *argv;
            let exe = pwstr_to_string(first);
            let _ = windows::Win32::Foundation::LocalFree(Some(
                windows::Win32::Foundation::HLOCAL(argv as *mut _),
            ));
            Some(exe)
        }
    }

    fn pwstr_to_string(pwstr: PWSTR) -> String {
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

    fn normalize_local_absolute_path(path: &str) -> Option<String> {
        normalize_local_drive_absolute_path(path)
    }

    fn wstr(s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }
}
