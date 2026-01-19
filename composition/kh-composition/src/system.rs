//! セットアップ/アンインストールのシステム操作ヘルパー。

use crate::error::{Result, err};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

#[derive(Clone, Copy, Debug)]
pub struct ProgramMetadata<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub publisher: &'a str,
    pub url: &'a str,
}

pub const SERVICE_NAME: &str = "KaptainhooKService";
pub const SERVICE_DISPLAY_NAME: &str = "KaptainhooK Service";
pub const UNINSTALL_KEY_NAME: &str = "KaptainhooK";
pub const TARGETS_REG_PATH: &str = r"SOFTWARE\\KaptainhooK\\Targets";
pub const TRUSTED_HASHES_REG_PATH: &str = r"SOFTWARE\\KaptainhooK\\TrustedHashes";
pub const UNINSTALL_STATE_REG_PATH: &str = r"SOFTWARE\\KaptainhooK\\UninstallState";
pub const LEASE_STATE_REG_PATH: &str = r"SOFTWARE\\KaptainhooK\\LeaseState";
#[cfg(windows)]
const SDDL_REG_AU_READ: &str = "D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;AU)";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
    StartPending,
    StopPending,
    NotInstalled,
    Unknown,
}

#[cfg(windows)]
pub fn register_startup(bin_dir: &Path) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_WRITE, REG_SZ,
    };

    let tray_exe = bin_dir.join("kh-tray.exe");
    let tray_path = tray_exe.to_string_lossy();

    let key_path: Vec<u16> = OsStr::new(r"Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let value_name: Vec<u16> = OsStr::new("KaptainhooK")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let value_data: Vec<u16> = OsStr::new(&format!("\"{}\"", tray_path))
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(key_path.as_ptr()),
            Some(0),
            KEY_WRITE,
            &mut hkey,
        );
        if result.is_err() {
            return Err(err("Failed to open registry key"));
        }

        let result = RegSetValueExW(
            hkey,
            PCWSTR(value_name.as_ptr()),
            Some(0),
            REG_SZ,
            Some(&value_data.align_to::<u8>().1[..value_data.len() * 2]),
        );
        let _ = RegCloseKey(hkey);

        if result.is_err() {
            return Err(err("Failed to set registry value"));
        }
    }

    Ok(())
}

#[cfg(windows)]
pub fn remove_startup_entries() -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        KEY_WRITE,
    };

    fn delete_value(hive: windows::Win32::System::Registry::HKEY, path: &str) {
        let path_w: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let mut key = windows::Win32::System::Registry::HKEY::default();
            if RegOpenKeyExW(hive, PCWSTR(path_w.as_ptr()), Some(0), KEY_WRITE, &mut key)
                == ERROR_SUCCESS
            {
                let value_name = OsStr::new("KaptainhooK")
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect::<Vec<_>>();
                let _ = RegDeleteValueW(key, PCWSTR(value_name.as_ptr()));
                let _ = RegCloseKey(key);
            }
        }
    }

    delete_value(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    );
    delete_value(
        HKEY_CURRENT_USER,
        r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    );

    Ok(())
}

#[cfg(windows)]
pub fn register_in_programs(bin_dir: &Path, meta: &ProgramMetadata<'_>) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, HKEY_LOCAL_MACHINE, KEY_WRITE, REG_OPTION_NON_VOLATILE,
    };

    let uninstall_key = format!(
        r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{}",
        meta.name
    );
    let key_path: Vec<u16> = OsStr::new(&uninstall_key)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let uninstall_exe = bin_dir.join("kh-uninstall.exe");
    let uninstall_string = format!("\"{}\"", uninstall_exe.to_string_lossy());
    let quiet_uninstall = format!("\"{}\" --quiet", uninstall_exe.to_string_lossy());
    let icon_path = preferred_shell_icon_path(bin_dir)
        .unwrap_or(uninstall_exe.clone())
        .to_string_lossy()
        .to_string();
    let install_location = bin_dir.to_string_lossy().to_string();

    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let result = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_path.as_ptr()),
            Some(0),
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );

        if result.is_err() {
            return Err(err("Failed to create uninstall registry key"));
        }

        set_reg_sz(hkey, "DisplayName", meta.name)?;
        set_reg_sz(hkey, "DisplayVersion", meta.version)?;
        set_reg_sz(hkey, "Publisher", meta.publisher)?;
        set_reg_sz(hkey, "UninstallString", &uninstall_string)?;
        set_reg_sz(hkey, "QuietUninstallString", &quiet_uninstall)?;
        set_reg_sz(hkey, "DisplayIcon", &icon_path)?;
        set_reg_sz(hkey, "InstallLocation", &install_location)?;
        set_reg_sz(hkey, "URLInfoAbout", meta.url)?;
        set_reg_dword(hkey, "NoModify", 1)?;
        set_reg_dword(hkey, "NoRepair", 1)?;
        set_reg_dword(hkey, "EstimatedSize", 5000)?;

        let _ = RegCloseKey(hkey);
    }

    Ok(())
}

#[cfg(windows)]
pub fn remove_from_programs(key_name: &str) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegDeleteKeyW, RegDeleteTreeW, HKEY_LOCAL_MACHINE};

    let uninstall_path = format!(
        r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{}",
        key_name
    );
    let path_w: Vec<u16> = OsStr::new(&uninstall_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(path_w.as_ptr()));
        if result != ERROR_SUCCESS {
            let _ = RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR(path_w.as_ptr()));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn create_service_restart_shortcut(bin_dir: &Path) -> Result<()> {
    use windows::core::Interface;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, S_FALSE, S_OK};
    use windows::Win32::System::Com::{
        COINIT_MULTITHREADED, CLSCTX_INPROC_SERVER, CoCreateInstance, CoInitializeEx,
        CoUninitialize, IPersistFile,
    };
    use windows::Win32::UI::Shell::{
        IShellLinkDataList, IShellLinkW, ShellLink, SLDF_RUNAS_USER,
    };

    let exe_path = bin_dir.join("kh-service-restart.exe");
    if !exe_path.exists() {
        return Ok(());
    }

    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let shortcut_dir = PathBuf::from(program_data)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("KaptainhooK");
    std::fs::create_dir_all(&shortcut_dir)?;

    let shortcut_path = shortcut_dir.join("サービス再起動.lnk");
    let exe_w = to_wide(&exe_path.to_string_lossy());
    let work_w = to_wide(&bin_dir.to_string_lossy());

    unsafe {
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        let did_init = if hr == S_OK || hr == S_FALSE {
            true
        } else if hr == RPC_E_CHANGED_MODE {
            false
        } else {
            return Err(err(format!("COM init failed: 0x{:08x}", hr.0 as u32)));
        };

        struct CoUninit(bool);
        impl Drop for CoUninit {
            fn drop(&mut self) {
                if self.0 {
                    unsafe { CoUninitialize() }
                }
            }
        }
        let _guard = CoUninit(did_init);

        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| err(format!("CoCreateInstance(ShellLink) failed: {e}")))?;

        link.SetPath(PCWSTR(exe_w.as_ptr()))
            .map_err(|e| err(format!("SetPath failed: {e}")))?;
        link.SetWorkingDirectory(PCWSTR(work_w.as_ptr()))
            .map_err(|e| err(format!("SetWorkingDirectory failed: {e}")))?;
        let icon_path = preferred_shell_icon_path(bin_dir).unwrap_or_else(|| exe_path.clone());
        let icon_w = to_wide(&icon_path.to_string_lossy());
        link.SetIconLocation(PCWSTR(icon_w.as_ptr()), 0)
            .map_err(|e| err(format!("SetIconLocation failed: {e}")))?;

        if let Ok(data_list) = link.cast::<IShellLinkDataList>() {
            let flags = data_list.GetFlags()?;
            data_list.SetFlags(flags | SLDF_RUNAS_USER.0 as u32)?;
        }

        let persist: IPersistFile = link.cast()?;
        let shortcut_w = to_wide(&shortcut_path.to_string_lossy());
        persist
            .Save(PCWSTR(shortcut_w.as_ptr()), true)
            .map_err(|e| err(format!("Save shortcut failed: {e}")))?;
    }

    Ok(())
}

pub fn remove_service_restart_shortcut() -> Result<()> {
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let shortcut_dir = PathBuf::from(program_data)
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("KaptainhooK");
    let shortcut = shortcut_dir.join("サービス再起動.lnk");

    if shortcut.exists() {
        let _ = std::fs::remove_file(&shortcut)
            .map_err(|e| err(format!("Failed to remove shortcut: {e}")))?;
    }

    if shortcut_dir.exists() {
        let empty = std::fs::read_dir(&shortcut_dir)
            .map_err(|e| err(format!("Failed to read shortcut dir: {e}")))?
            .next()
            .is_none();
        if empty {
            let _ = std::fs::remove_dir(&shortcut_dir);
        }
    }

    Ok(())
}

#[cfg(windows)]
fn preferred_shell_icon_path(bin_dir: &Path) -> Option<PathBuf> {
    let candidates = [
        bin_dir.join("assets").join("K-hook.ico"),
        bin_dir.join("assets").join("k-hook.ico"),
        bin_dir.join("assets").join("kh_tray_icon.ico"),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(windows)]
pub fn ensure_service_installed(bin_dir: &Path) -> Result<()> {
    use windows::Win32::Foundation::{ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_EXISTS};
    use windows::Win32::System::Services::{
        ChangeServiceConfigW, CreateServiceW, OpenSCManagerW, OpenServiceW, SERVICE_ALL_ACCESS,
        SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG, SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS,
        SERVICE_START, SERVICE_WIN32_OWN_PROCESS, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    };

    let service_exe = bin_dir.join("kh-service.exe");
    if !service_exe.exists() {
        return Err(err(format!(
            "Service executable not found: {}",
            service_exe.display()
        )));
    }
    let bin_path = format!("\"{}\"", service_exe.display());

    let name_w = to_wide(SERVICE_NAME);
    let display_w = to_wide(SERVICE_DISPLAY_NAME);
    let bin_w = to_wide(&bin_path);

    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)
            .map_err(|e| err(format!("OpenSCManagerW failed: {}", e.message())))?;
        let _scm_guard = ScmHandle(scm);

        let service = match CreateServiceW(
            scm,
            windows::core::PCWSTR(name_w.as_ptr()),
            windows::core::PCWSTR(display_w.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            windows::core::PCWSTR(bin_w.as_ptr()),
            None,
            None,
            None,
            None,
            None,
        ) {
            Ok(handle) => ServiceHandle(handle),
            Err(e) => {
                let code = e.code().0 as u32;
                let hresult_from_win32 = |win32: u32| -> u32 {
                    if win32 == 0 {
                        0
                    } else {
                        (win32 & 0xFFFF) | (7u32 << 16) | 0x8000_0000
                    }
                };
                let exists = code == ERROR_SERVICE_EXISTS.0
                    || code == ERROR_SERVICE_ALREADY_RUNNING.0
                    || code == hresult_from_win32(ERROR_SERVICE_EXISTS.0)
                    || code == hresult_from_win32(ERROR_SERVICE_ALREADY_RUNNING.0);
                if exists {
                    let service = OpenServiceW(
                        scm,
                        windows::core::PCWSTR(name_w.as_ptr()),
                        SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG,
                    )
                    .map_err(|e| err(format!("OpenServiceW failed: {}", e.message())))?;

                    ChangeServiceConfigW(
                        service,
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        windows::core::PCWSTR(bin_w.as_ptr()),
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    .map_err(|e| err(format!("ChangeServiceConfigW failed: {}", e.message())))?;

                    ServiceHandle(service)
                } else {
                    return Err(err(format!(
                        "CreateServiceW failed: {}",
                        e.message()
                    )));
                }
            }
        };

        start_service(&service)?;
    }

    Ok(())
}

#[cfg(windows)]
pub fn get_service_state() -> Result<ServiceState> {
    use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows::Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
        SERVICE_START_PENDING, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    };

    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
            .map_err(|e| err(format!("OpenSCManagerW failed: {}", e.message())))?;
        let _scm_guard = ScmHandle(scm);

        let name_w = to_wide(SERVICE_NAME);
        let service = match OpenServiceW(
            scm,
            windows::core::PCWSTR(name_w.as_ptr()),
            SERVICE_QUERY_STATUS,
        ) {
            Ok(handle) => ServiceHandle(handle),
            Err(e) => {
                if e.code().0 as u32 == ERROR_SERVICE_DOES_NOT_EXIST.0 {
                    return Ok(ServiceState::NotInstalled);
                }
                return Err(err(format!("OpenServiceW failed: {}", e.message())));
            }
        };

        let status = query_service_status(&service)?;
        let state = match status.dwCurrentState {
            SERVICE_RUNNING => ServiceState::Running,
            SERVICE_STOPPED => ServiceState::Stopped,
            SERVICE_START_PENDING => ServiceState::StartPending,
            SERVICE_STOP_PENDING => ServiceState::StopPending,
            _ => ServiceState::Unknown,
        };
        Ok(state)
    }
}

#[cfg(not(windows))]
pub fn get_service_state() -> Result<ServiceState> {
    Ok(ServiceState::Unknown)
}

#[cfg(windows)]
pub fn remove_service() -> Result<()> {
    use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
    use windows::Win32::Storage::FileSystem::DELETE;
    use windows::Win32::System::Services::{
        ControlService, DeleteService, OpenSCManagerW, OpenServiceW, SERVICE_CONTROL_STOP,
        SERVICE_QUERY_STATUS, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        SC_MANAGER_CONNECT,
    };

    unsafe {
        let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
            .map_err(|e| err(format!("OpenSCManagerW failed: {}", e.message())))?;
        let _scm_guard = ScmHandle(scm);

        let name_w = to_wide(SERVICE_NAME);
        let service = match OpenServiceW(
            scm,
            windows::core::PCWSTR(name_w.as_ptr()),
            SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE.0,
        ) {
            Ok(handle) => ServiceHandle(handle),
            Err(e) => {
                if e.code().0 as u32 == ERROR_SERVICE_DOES_NOT_EXIST.0 {
                    return Ok(());
                }
                return Err(err(format!("OpenServiceW failed: {}", e.message())));
            }
        };

        let status = query_service_status(&service)?;
        if status.dwCurrentState == SERVICE_STOP_PENDING {
            wait_for_service_status(&service, SERVICE_STOPPED, 10_000)?;
        } else if status.dwCurrentState != SERVICE_STOPPED {
            let mut svc_status = SERVICE_STATUS::default();
            ControlService(service.0, SERVICE_CONTROL_STOP, &mut svc_status)
                .map_err(|e| err(format!("ControlService stop failed: {}", e.message())))?;
            wait_for_service_status(&service, SERVICE_STOPPED, 10_000)?;
        }

        DeleteService(service.0)
            .map_err(|e| err(format!("DeleteService failed: {}", e.message())))?;
    }

    Ok(())
}

#[cfg(windows)]
pub fn apply_locked_bin_dir_acl(bin_dir: &Path) -> Result<()> {
    const SDDL_DIR_READONLY_AU: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;AU)";
    const SDDL_FILE_EXECUTABLE_AU_RX: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;AU)";

    set_dacl_from_sddl(bin_dir, SDDL_DIR_READONLY_AU)?;

    let entries = std::fs::read_dir(bin_dir)
        .map_err(|e| err(format!("read bin dir {:?}: {e}", bin_dir)))?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.is_file() {
            set_dacl_from_sddl(&path, SDDL_FILE_EXECUTABLE_AU_RX)?;
        }
    }

    Ok(())
}

#[cfg(windows)]
pub fn apply_locked_data_dir_acl(data_dir: &Path) -> Result<()> {
    const SDDL_DIR_READONLY_AU: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;AU)";
    const SDDL_DIR_LOG_AU_RX: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;GRGX;;;AU)";
    const SDDL_FILE_READONLY_AU: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)";
    const SDDL_FILE_LOG_AU_R: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)";

    let config_dir = data_dir.join("config");
    let backup_dir = data_dir.join("backups");
    let log_dir = data_dir.join("logs");
    for dir in [&config_dir, &backup_dir, &log_dir] {
        std::fs::create_dir_all(dir).map_err(|e| err(format!("create {:?}: {e}", dir)))?;
    }

    // data_dir 自体も固定する（ProgramData 配下の書き込み/置換は権限昇格経路になり得る）
    set_dacl_from_sddl(data_dir, SDDL_DIR_READONLY_AU)?;
    set_dacl_from_sddl(&config_dir, SDDL_DIR_READONLY_AU)?;
    set_dacl_from_sddl(&backup_dir, SDDL_DIR_READONLY_AU)?;
    set_dacl_from_sddl(&log_dir, SDDL_DIR_LOG_AU_RX)?;

    let config_file = config_dir.join("config.json");
    let backup_file = backup_dir.join("backups.json");
    let guard_log = log_dir.join("guard.log.jsonl");
    let op_log = log_dir.join("operation.log.jsonl");
    let lifecycle_log = log_dir.join("kh-lifecycle.log");
    for (path, sddl) in [
        (&config_file, SDDL_FILE_READONLY_AU),
        (&backup_file, SDDL_FILE_READONLY_AU),
        (&guard_log, SDDL_FILE_LOG_AU_R),
        (&op_log, SDDL_FILE_LOG_AU_R),
        (&lifecycle_log, SDDL_FILE_LOG_AU_R),
    ] {
        if path.exists() {
            set_dacl_from_sddl(path, sddl)?;
        }
    }

    Ok(())
}

#[cfg(windows)]
pub fn write_trusted_hashes(bin_dir: &Path) -> Result<()> {
    use windows::Win32::System::Registry::RegCloseKey;

    let guard_path = bin_dir.join("kh-guard.exe");

    let guard_hash = compute_sha256_hex(&guard_path)?;

    let hkey = create_hklm_key(TRUSTED_HASHES_REG_PATH)?;
    set_reg_sz(hkey, "GuardHash", &guard_hash)?;
    apply_registry_key_acl(hkey, SDDL_REG_AU_READ)?;
    unsafe {
        let _ = RegCloseKey(hkey);
    }

    Ok(())
}

#[cfg(windows)]
pub fn remove_registry_state() -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegDeleteKeyW, RegDeleteTreeW, HKEY_LOCAL_MACHINE};

    unsafe {
        for path in [TARGETS_REG_PATH, TRUSTED_HASHES_REG_PATH, UNINSTALL_STATE_REG_PATH, LEASE_STATE_REG_PATH] {
            let path_w: Vec<u16> = OsStr::new(path)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let result = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(path_w.as_ptr()));
            if result != ERROR_SUCCESS {
                let _ = RegDeleteKeyW(HKEY_LOCAL_MACHINE, PCWSTR(path_w.as_ptr()));
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
fn set_reg_sz(hkey: windows::Win32::System::Registry::HKEY, name: &str, value: &str) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{RegSetValueExW, REG_SZ};

    let name_wide: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let value_wide: Vec<u16> = OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let result = RegSetValueExW(
            hkey,
            PCWSTR(name_wide.as_ptr()),
            Some(0),
            REG_SZ,
            Some(&value_wide.align_to::<u8>().1[..value_wide.len() * 2]),
        );
        if result.is_err() {
            return Err(err(format!("Failed to set registry value: {}", name)));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn set_reg_dword(hkey: windows::Win32::System::Registry::HKEY, name: &str, value: u32) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{RegSetValueExW, REG_DWORD};

    let name_wide: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let value_bytes = value.to_le_bytes();

    unsafe {
        let result = RegSetValueExW(
            hkey,
            PCWSTR(name_wide.as_ptr()),
            Some(0),
            REG_DWORD,
            Some(&value_bytes),
        );
        if result.is_err() {
            return Err(err(format!("Failed to set registry DWORD: {}", name)));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn create_hklm_key(path: &str) -> Result<windows::Win32::System::Registry::HKEY> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::Storage::FileSystem::WRITE_DAC;
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, HKEY_LOCAL_MACHINE, KEY_CREATE_SUB_KEY, KEY_SET_VALUE, KEY_WOW64_64KEY,
        REG_CREATE_KEY_DISPOSITION, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS,
    };

    let key_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let mut disposition = REG_CREATE_KEY_DISPOSITION(0);
        let status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_path.as_ptr()),
            Some(0),
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY | REG_SAM_FLAGS(WRITE_DAC.0),
            None,
            &mut hkey,
            Some(&mut disposition),
        );
        if status != ERROR_SUCCESS {
            return Err(err(format!(
                "RegCreateKeyExW failed for {}: status={}",
                path,
                status.0
            )));
        }
        Ok(hkey)
    }
}

#[cfg(windows)]
fn apply_registry_key_acl(
    hkey: windows::Win32::System::Registry::HKEY,
    sddl: &str,
) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::System::Registry::RegSetKeySecurity;

    let sddl_w: Vec<u16> = OsStr::new(sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1 as u32,
            &mut sd,
            None,
        )
        .map_err(|e| err(format!("parse SDDL failed: {}", e.message())))?;

        struct SdGuard(PSECURITY_DESCRIPTOR);
        impl Drop for SdGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0 .0)));
                }
            }
        }
        let _guard = SdGuard(sd);

        let info: OBJECT_SECURITY_INFORMATION =
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        let status = RegSetKeySecurity(hkey, info, sd);
        if status != ERROR_SUCCESS {
            return Err(err(format!(
                "RegSetKeySecurity failed: status={}",
                status.0
            )));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn set_dacl_from_sddl(path: &Path, sddl: &str) -> Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };

    if !path.exists() {
        return Err(err(format!("ACL target does not exist: {:?}", path)));
    }

    let path_w: Vec<u16> = OsStr::new(path.as_os_str())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let sddl_w: Vec<u16> = OsStr::new(sddl)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1 as u32,
            &mut sd,
            None,
        )
        .map_err(|e| err(format!("parse SDDL failed: {}", e.message())))?;

        struct SdGuard(PSECURITY_DESCRIPTOR);
        impl Drop for SdGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(self.0 .0)));
                }
            }
        }
        let _guard = SdGuard(sd);

        let info: OBJECT_SECURITY_INFORMATION =
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        let ok = SetFileSecurityW(PCWSTR(path_w.as_ptr()), info, sd).as_bool();
        if !ok {
            let e = windows::core::Error::from_thread();
            return Err(err(format!(
                "SetFileSecurityW failed for {:?}: {}",
                path,
                e.message()
            )));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn compute_sha256_hex(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path)
        .map_err(|e| err(format!("Failed to open {:?}: {}", path, e)))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| err(format!("Failed to read {:?}: {}", path, e)))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    Ok(hash.iter().map(|b| format!("{:02x}", b)).collect())
}

#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    let mut wide: Vec<u16> = s.encode_utf16().collect();
    wide.push(0);
    wide
}

#[cfg(windows)]
struct ScmHandle(windows::Win32::System::Services::SC_HANDLE);

#[cfg(windows)]
impl Drop for ScmHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::System::Services::CloseServiceHandle(self.0);
        }
    }
}

#[cfg(windows)]
struct ServiceHandle(windows::Win32::System::Services::SC_HANDLE);

#[cfg(windows)]
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::System::Services::CloseServiceHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn start_service(service: &ServiceHandle) -> Result<()> {
    use windows::Win32::System::Services::{
        StartServiceW, SERVICE_RUNNING, SERVICE_START_PENDING,
    };

    let status = query_service_status(service)?;
    if status.dwCurrentState == SERVICE_RUNNING {
        return Ok(());
    }
    if status.dwCurrentState == SERVICE_START_PENDING {
        return wait_for_service_status(service, SERVICE_RUNNING, 10_000);
    }

    unsafe {
        StartServiceW(service.0, None)
            .map_err(|e| err(format!("StartServiceW failed: {}", e.message())))?;
    }
    wait_for_service_status(service, SERVICE_RUNNING, 10_000)
}

#[cfg(windows)]
fn query_service_status(
    service: &ServiceHandle,
) -> Result<windows::Win32::System::Services::SERVICE_STATUS_PROCESS> {
    use windows::Win32::System::Services::{QueryServiceStatusEx, SC_STATUS_PROCESS_INFO, SERVICE_STATUS_PROCESS};
    unsafe {
        let mut bytes_needed = 0u32;
        let mut buffer = vec![0u8; std::mem::size_of::<SERVICE_STATUS_PROCESS>()];
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            Some(buffer.as_mut_slice()),
            &mut bytes_needed,
        )
        .map_err(|e| err(format!("QueryServiceStatusEx failed: {}", e.message())))?;
        if bytes_needed as usize > buffer.len() {
            return Err(err("QueryServiceStatusEx returned short buffer"));
        }
        let ptr = buffer.as_ptr() as *const SERVICE_STATUS_PROCESS;
        Ok(std::ptr::read_unaligned(ptr))
    }
}

#[cfg(windows)]
fn wait_for_service_status(
    service: &ServiceHandle,
    desired: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
    timeout_ms: u64,
) -> Result<()> {
    use std::time::{Duration, Instant};
    use windows::Win32::System::Threading::Sleep;

    let start = Instant::now();
    loop {
        let status = query_service_status(service)?;
        if status.dwCurrentState == desired {
            return Ok(());
        }
        if start.elapsed() > Duration::from_millis(timeout_ms) {
            return Err(err("Timeout waiting for service state"));
        }
        unsafe {
            Sleep(200);
        }
    }
}

#[cfg(not(windows))]
pub fn register_startup(_bin_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn remove_startup_entries() -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn register_in_programs(_bin_dir: &Path, _meta: &ProgramMetadata<'_>) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn remove_from_programs(_key_name: &str) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn create_service_restart_shortcut(_bin_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn remove_service_restart_shortcut() -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn ensure_service_installed(_bin_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn remove_service() -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn apply_locked_bin_dir_acl(_bin_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn apply_locked_data_dir_acl(_data_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn write_trusted_hashes(_bin_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn remove_registry_state() -> Result<()> {
    Ok(())
}
