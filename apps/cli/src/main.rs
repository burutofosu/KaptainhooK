//! kh-cli: IFEO のインストール／状態確認／競合検出／クリーンアップ／ロールバック／
//! アンインストールなどを行う管理用 CLI。フルインストールは kh-setup を使用する。

use std::error::Error;
use clap::{Parser, Subcommand};
use kh_composition::cli::{CliRuntime, UninstallReport};
use kh_composition::paths;
use kh_composition::system;
use kh_composition::targets;
use kh_composition::app::admin::{
    AdminDeps, AdminService, ApplyTargetsRequest, ConflictAction as AdminConflictAction,
    ConflictDecision as AdminConflictDecision, NonStringConflict,
};
use kh_composition::domain::model::{
    InstallConfig, PathHint, PathHintKind, SignatureNoticeKind, Target,
};
use kh_composition::domain::port::driving::ConflictResolution;
use kh_composition::engine::{ConflictEntry, InstallReport, SafeCleanupReport};
use kh_composition::guard::is_admin;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::PathBuf;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
type StringResult<T> = std::result::Result<T, String>;

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

const ARG_APPLY_TARGETS_PIPE: &str = "--apply-targets-pipe";
const ARG_APPLY_TARGETS_CLIENT: &str = "--apply-targets-client";
const PIPE_HANDSHAKE_TIMEOUT_SECS: u64 = 30;

macro_rules! bail {
    ($($t:tt)*) => {
        return Err(err(format!($($t)*)));
    };
}

fn parse_apply_targets_pipe_args() -> Option<(String, u32)> {
    let args: Vec<OsString> = std::env::args_os().collect();
    let mut iter = args.iter();
    let mut pipe_name: Option<String> = None;
    let mut client_pid: Option<u32> = None;
    while let Some(arg) = iter.next() {
        if arg == ARG_APPLY_TARGETS_PIPE {
            pipe_name = iter
                .next()
                .and_then(|v| v.to_str().map(|s| s.to_string()));
            continue;
        }
        if arg == ARG_APPLY_TARGETS_CLIENT {
            client_pid = iter
                .next()
                .and_then(|v| v.to_str())
                .and_then(|s| s.parse::<u32>().ok());
            continue;
        }
    }
    match (pipe_name, client_pid) {
        (Some(name), Some(pid)) if !name.trim().is_empty() => Some((name, pid)),
        _ => None,
    }
}

#[cfg(windows)]
fn wstr(s: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn quote_windows_arg(arg: &OsStr) -> String {
    let s = arg.to_string_lossy();
    if s.contains([' ', '\t', '\n', '\r', '"']) {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

#[cfg(windows)]
fn new_guid_string() -> StringResult<String> {
    use windows::Win32::System::Com::CoCreateGuid;
    let guid = unsafe { CoCreateGuid().map_err(|e| format!("CoCreateGuid failed: {e}"))? };
    Ok(format_guid(&guid))
}

#[cfg(not(windows))]
fn new_guid_string() -> StringResult<String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Ok(format!("guid-{}", nanos))
}

#[cfg(windows)]
fn format_guid(guid: &windows::core::GUID) -> String {
    let d4 = guid.data4;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        d4[0],
        d4[1],
        d4[2],
        d4[3],
        d4[4],
        d4[5],
        d4[6],
        d4[7]
    )
}

#[cfg(windows)]
fn run_self_as_admin_and_wait_with_pipe(
    parameters: &str,
    pipe_name: &str,
    payload: &[u8],
) -> StringResult<u32> {
    use windows::Win32::Foundation::ERROR_CANCELLED;
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::PCWSTR;

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_w = wstr(exe.as_os_str());
    let params_w = wstr(OsStr::new(parameters));
    let verb_w = wstr(OsStr::new("runas"));
    let mut exec = SHELLEXECUTEINFOW::default();
    exec.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    exec.fMask = SEE_MASK_NOCLOSEPROCESS;
    exec.lpVerb = PCWSTR(verb_w.as_ptr());
    exec.lpFile = PCWSTR(exe_w.as_ptr());
    exec.lpParameters = PCWSTR(params_w.as_ptr());
    exec.nShow = SW_SHOWNORMAL.0 as i32;

    if let Err(err) = unsafe { ShellExecuteExW(&mut exec) } {
        if err.code().0 as u32 == ERROR_CANCELLED.0 {
            return Err("User cancelled UAC prompt.".to_string());
        }
        return Err(format!("ShellExecuteExW failed: {}", err.message()));
    }
    let process = exec.hProcess;
    if process.is_invalid() {
        return Err("Failed to get process handle.".to_string());
    }

    let send_result = send_payload_to_pipe(pipe_name, payload);
    let _ = unsafe { WaitForSingleObject(process, INFINITE) };
    let code = unsafe {
        let mut exit_code: u32 = 0;
        if GetExitCodeProcess(process, &mut exit_code).is_ok() {
            exit_code
        } else {
            1
        }
    };
    unsafe {
        let _ = CloseHandle(process);
    }

    match send_result {
        Ok(()) => Ok(code),
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn send_payload_to_pipe(pipe_name: &str, payload: &[u8]) -> StringResult<()> {
    use std::time::{Duration, Instant};
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GetLastError};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_MODE,
        OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeW;
    use windows::core::PCWSTR;

    let name = wstr(OsStr::new(pipe_name));
    let desired_access = FILE_GENERIC_WRITE.0;
    let deadline = Instant::now() + Duration::from_secs(PIPE_HANDSHAKE_TIMEOUT_SECS);
    loop {
        if Instant::now() >= deadline {
            return Err("Timed out waiting for pipe.".to_string());
        }
        let handle = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                desired_access,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        let handle = match handle {
            Ok(handle) => handle,
            Err(_) => {
                let err = unsafe { GetLastError() };
                if err == ERROR_PIPE_BUSY {
                    let _ = unsafe { WaitNamedPipeW(PCWSTR(name.as_ptr()), 2_000) };
                    continue;
                }
                if err == ERROR_FILE_NOT_FOUND {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
                return Err(format!("Failed to open pipe: {}", err.0));
            }
        };
        let mut written: u32 = 0;
        let write_ok = unsafe { WriteFile(handle, Some(payload), Some(&mut written), None) };
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(handle) };
        if write_ok.is_err() {
            return Err("Failed to write payload to pipe.".to_string());
        }
        if written as usize != payload.len() {
            return Err("Incomplete payload write.".to_string());
        }
        return Ok(());
    }
}

#[cfg(windows)]
fn apply_targets_with_uac_if_needed(payload: ApplyTargetsRequest) -> StringResult<()> {
    if payload.enable.is_empty() && payload.disable.is_empty() && payload.enabled_targets.is_empty() {
        return Ok(());
    }
    if is_admin() {
        return apply_targets_admin(payload);
    }

    let data =
        serde_json::to_vec_pretty(&TargetApplyPayload::from(&payload)).map_err(|e| e.to_string())?;
    let pipe_id = new_guid_string()?;
    let pipe_name = format!(r"\\.\pipe\\kh-apply-targets-{}", pipe_id);
    let client_pid = std::process::id();
    let params = format!(
        "{} {} {} {}",
        ARG_APPLY_TARGETS_PIPE,
        quote_windows_arg(OsStr::new(&pipe_id)),
        ARG_APPLY_TARGETS_CLIENT,
        client_pid
    );

    let result = match run_self_as_admin_and_wait_with_pipe(&params, &pipe_name, &data) {
        Ok(0) => Ok(()),
        Ok(code) => Err(format!("Target update failed (exit {code}).")),
        Err(e) => Err(e),
    };
    result
}

#[cfg(not(windows))]
fn apply_targets_with_uac_if_needed(_payload: ApplyTargetsRequest) -> StringResult<()> {
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TargetApplyPayload {
    enable: Vec<String>,
    disable: Vec<String>,
    enabled_targets: Vec<String>,
    conflicts: Vec<TargetConflictDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TargetConflictDecision {
    target: String,
    action: TargetConflictAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TargetConflictAction {
    Respect,
    TakeOver,
    Quarantine,
    Abort,
}

impl From<&ApplyTargetsRequest> for TargetApplyPayload {
    fn from(request: &ApplyTargetsRequest) -> Self {
        Self {
            enable: request.enable.clone(),
            disable: request.disable.clone(),
            enabled_targets: request.enabled_targets.clone(),
            conflicts: request
                .conflicts
                .iter()
                .map(|c| TargetConflictDecision {
                    target: c.target.clone(),
                    action: TargetConflictAction::from(c.action),
                })
                .collect(),
        }
    }
}

impl From<TargetApplyPayload> for ApplyTargetsRequest {
    fn from(payload: TargetApplyPayload) -> Self {
        Self {
            enable: payload.enable,
            disable: payload.disable,
            enabled_targets: payload.enabled_targets,
            conflicts: payload
                .conflicts
                .into_iter()
                .map(|c| AdminConflictDecision {
                    target: c.target,
                    action: AdminConflictAction::from(c.action),
                })
                .collect(),
        }
    }
}

impl From<AdminConflictAction> for TargetConflictAction {
    fn from(action: AdminConflictAction) -> Self {
        match action {
            AdminConflictAction::Respect => TargetConflictAction::Respect,
            AdminConflictAction::TakeOver => TargetConflictAction::TakeOver,
            AdminConflictAction::Quarantine => TargetConflictAction::Quarantine,
            AdminConflictAction::Abort => TargetConflictAction::Abort,
        }
    }
}

impl From<TargetConflictAction> for AdminConflictAction {
    fn from(action: TargetConflictAction) -> Self {
        match action {
            TargetConflictAction::Respect => AdminConflictAction::Respect,
            TargetConflictAction::TakeOver => AdminConflictAction::TakeOver,
            TargetConflictAction::Quarantine => AdminConflictAction::Quarantine,
            TargetConflictAction::Abort => AdminConflictAction::Abort,
        }
    }
}

#[cfg(windows)]
fn apply_targets_from_pipe(pipe_id: &str, expected_pid: u32) -> StringResult<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;
    use windows::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED, GetLastError, FALSE};
    use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_INBOUND};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::core::PCWSTR;

    const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

    if !is_admin() {
        return Err("Administrator privileges are required.".to_string());
    }
    if pipe_id.trim().is_empty() {
        return Err("Invalid pipe id.".to_string());
    }

    let full_name = format!(r"\\.\pipe\\kh-apply-targets-{}", pipe_id);
    let name = wstr(OsStr::new(&full_name));
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
    let mut sd_len: u32 = 0;
    if let Err(err) = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wstr(OsStr::new(PIPE_SDDL)).as_ptr()),
            SDDL_REVISION_1 as u32,
            &mut sd,
            Some(&mut sd_len),
        )
    } {
        return Err(format!(
            "Failed to build pipe security descriptor: {}",
            err.message()
        ));
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0 as *mut _,
        bInheritHandle: FALSE,
    };

    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name.as_ptr()),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0,
            64 * 1024,
            5_000,
            Some(&sa),
        )
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0 as _)));
    }
    if handle.is_invalid() {
        return Err(format!(
            "Failed to create pipe: {}",
            unsafe { GetLastError().0 }
        ));
    }
    let _guard = PipeHandleGuard(handle);

    let connected_flag = Arc::new(AtomicBool::new(false));
    let watchdog_flag = Arc::clone(&connected_flag);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(PIPE_HANDSHAKE_TIMEOUT_SECS));
        if !watchdog_flag.load(Ordering::SeqCst) {
            std::process::exit(1);
        }
    });

    let connected = unsafe { ConnectNamedPipe(handle, None) };
    if connected.is_err() {
        let err = unsafe { GetLastError() };
        if err != ERROR_PIPE_CONNECTED {
            return Err(format!("Pipe connect failed: {}", err.0));
        }
    }
    connected_flag.store(true, Ordering::SeqCst);

    let mut client_pid: u32 = 0;
    let pid_ok = unsafe { GetNamedPipeClientProcessId(handle, &mut client_pid) };
    if pid_ok.is_err() || client_pid != expected_pid {
        return Err("Pipe client mismatch.".to_string());
    }

    let mut buf = vec![0u8; 8192];
    let mut data: Vec<u8> = Vec::new();
    loop {
        let mut read = 0u32;
        let ok = unsafe { ReadFile(handle, Some(buf.as_mut_slice()), Some(&mut read), None) };
        if ok.is_err() {
            let err = unsafe { GetLastError() };
            if err == ERROR_BROKEN_PIPE {
                break;
            }
            return Err(format!("Pipe read failed: {}", err.0));
        }
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buf[..read as usize]);
    }

    let payload: TargetApplyPayload = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    apply_targets_admin(payload.into())?;
    Ok(())
}

#[cfg(not(windows))]
fn apply_targets_from_pipe(_pipe_id: &str, _expected_pid: u32) -> StringResult<()> {
    Err("UAC elevation is not supported on this platform.".to_string())
}

#[cfg(windows)]
struct PipeHandleGuard(HANDLE);

#[cfg(windows)]
impl Drop for PipeHandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn apply_targets_admin(payload: ApplyTargetsRequest) -> StringResult<()> {
    let runtime = CliRuntime::new();
    let admin = AdminService::new(AdminDeps { port: &runtime });
    admin
        .apply_targets(payload)
        .map_err(|e| format!("Failed to apply targets: {e}"))
}

#[cfg(not(windows))]
fn apply_targets_admin(_payload: ApplyTargetsRequest) -> StringResult<()> {
    Ok(())
}

#[derive(Parser, Debug)]
#[command(name = "kh-cli", about = "KaptainhooK management CLI")]
struct Cli {
    /// 既定インストールパス以外での実行を許可（危険）
    #[arg(long, global = true, default_value_t = false)]
    allow_unsafe_path: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// 保護対象のIFEOエントリを再適用（フルインストールは kh-setup）
    Install {
        /// 変更せず実行計画のみ表示
        #[arg(long)]
        dry_run: bool,
        /// JSON形式で出力
        #[arg(long, default_value_t = false)]
        json: bool,
        /// 競合時の処理（abort|skip|overwrite|prompt|interactive）
        #[arg(long, default_value = "abort", value_parser = ["abort", "skip", "overwrite", "prompt", "interactive"])]
        conflict: String,
    },
    /// 現在のIFEO登録状態を表示
    Status {
        /// JSON形式で出力
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// 他製品との競合を検出
    Conflicts {
        /// JSON形式で出力
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// 保護対象ターゲットの管理
    Targets {
        #[command(subcommand)]
        command: TargetsCommand,
    },
    /// IFEOエントリを削除
    Cleanup {
        /// 設定ファイルではなくレジストリをスキャン
        /// （設定が欠損している場合に推奨）
        #[arg(long)]
        scan: bool,
        /// JSON形式で出力
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// バックアップストアの状態にIFEOをロールバック
    Rollback {
        /// JSON形式で出力
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// IFEO + タスク + データのクリーンアップ（完全アンインストールは kh-uninstall または kh-setup --uninstall）
    Uninstall {
        /// データディレクトリも削除（設定、ログ、バックアップ）
        #[arg(long)]
        remove_data: bool,
        /// JSON形式で出力
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// タスクスケジューラの状態表示（診断用）
    TaskInfo {
        /// JSON形式で出力
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// TrustedHashes の更新
    TrustedHashes {
        #[command(subcommand)]
        command: TrustedHashesCommand,
    },
}

#[derive(Subcommand, Debug)]
enum TargetsCommand {
    /// ターゲット一覧を表示
    List {
        /// JSON形式で出力
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// ターゲットを有効化（存在しなければ追加）
    Enable {
        /// 対象 exe 名（例: powershell.exe）
        #[arg(required = true, num_args = 1..)]
        targets: Vec<String>,
        /// 競合時の処理（respect|overwrite|quarantine|abort）
        #[arg(long, default_value = "respect", value_parser = ["respect", "overwrite", "quarantine", "abort"])]
        conflict: String,
    },
    /// ターゲットを無効化（存在しなければ追加）
    Disable {
        /// 対象 exe 名（例: powershell.exe）
        #[arg(required = true, num_args = 1..)]
        targets: Vec<String>,
    },
    /// ターゲットを設定から削除
    Remove {
        /// 対象 exe 名（例: powershell.exe）
        #[arg(required = true, num_args = 1..)]
        targets: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum TrustedHashesCommand {
    /// Guard/Bootstrap のハッシュを再計算してレジストリへ書き込み
    Refresh {
        /// 対象 bin ディレクトリ（未指定なら既定）
        #[arg(long)]
        bin_dir: Option<PathBuf>,
    },
}

fn main() {
    if let Some((pipe_id, client_pid)) = parse_apply_targets_pipe_args() {
        let code = match apply_targets_from_pipe(&pipe_id, client_pid) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("kh-cli failed: {}", e);
                1
            }
        };
        std::process::exit(code);
    }
    if let Err(err) = run() {
        eprintln!("kh-cli failed: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let allow_unsafe = allow_unsafe_paths(cli.allow_unsafe_path);

    // 全依存関係はComposition Rootで組み立て
    let runtime = CliRuntime::new();

    match cli.command {
        Command::Install {
            dry_run,
            json,
            conflict,
        } => {
            let mut config = runtime.load_config()?;
            let conflict_mode = ConflictMode::from_flag(&conflict);

            // dry_runまたは非JSON対話出力時のみプラン表示
            if dry_run {
                let expected = runtime.expected_debugger_path();
                let entries = runtime.app().install_plan(&config, true, &expected)?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&JsonInstallPlan {
                            dry_run: true,
                            entries: map_install_plan(entries),
                        })?
                    );
                } else {
                    println!("Install plan (dry_run=true):");
                    for entry in &entries {
                        println!("  {} -> {:?}", entry.target, entry.action);
                    }
                }
                return Ok(());
            }

            ensure_safe_bin_dir(allow_unsafe, "install")?;
            ensure_install_prereqs(&runtime)?;

            // 実行モード: 人間可読形式でのみプラン表示
            if !json {
                let expected = runtime.expected_debugger_path();
                let entries = runtime.app().install_plan(&config, false, &expected)?;
                println!("Install plan (dry_run=false):");
                for entry in &entries {
                    println!("  {} -> {:?}", entry.target, entry.action);
                }
            }

            match conflict_mode {
                ConflictMode::Prompt => {
                    if json {
                        bail!("Interactive conflict resolution does not support --json output");
                    }
                    handle_interactive_install(&runtime, &mut config)?;
                }
                ConflictMode::Abort | ConflictMode::Skip | ConflictMode::Overwrite => {
                    let resolution = conflict_mode.into_resolution();
                    let report = runtime.install_with_backup(&config, resolution)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&map_install_report(&report))?);
                    } else {
                        print_install_report(&report);
                    }
                }
            }

        }

        Command::Status { json } => {
            let config = runtime.load_config()?;
            let entries = runtime.status(&config)?;
            if json {
                let body: Vec<JsonStatusEntry> = entries
                    .into_iter()
                    .map(|e| JsonStatusEntry {
                        target: e.target,
                        enabled: e.enabled,
                        debugger: e.debugger,
                        view: format!("{:?}", e.view),
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else {
                println!("IFEO Status ({} entries):", entries.len());
                for entry in entries {
                    let status = match &entry.debugger {
                        Some(dbg) => format!("registered -> {}", dbg),
                        None => "not registered".to_string(),
                    };
                    println!(
                        "  {:<20} [{:?}] enabled={:<5} {}",
                        entry.target, entry.view, entry.enabled, status
                    );
                }
            }
        }

        Command::Conflicts { json } => {
            let config = runtime.load_config()?;
            let conflicts = runtime.detect_conflicts(&config)?;
            if json {
                let body: Vec<JsonConflict> = conflicts
                    .into_iter()
                    .map(|c| JsonConflict {
                        target: c.target,
                        view: format!("{:?}", c.view),
                        existing_debugger: c.existing_debugger,
                        expected_debugger: c.expected_debugger,
                        signature: format!("{:?}", c.signature),
                        signature_notice: c
                            .signature_notice
                            .as_ref()
                            .map(|kind| signature_notice_label(kind).to_string()),
                        path_hints: c
                            .path_hints
                            .into_iter()
                            .map(|h| format_path_hint(&h))
                            .collect(),
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&body)?);
            } else if conflicts.is_empty() {
                println!("No conflicts found.");
            } else {
                println!("Conflicts detected ({}):", conflicts.len());
                for c in conflicts {
                    println!(
                        "  {} [{:?}]\n    Existing:    {}\n    Expected:    {}\n    Signature:   {:?}",
                        c.target,
                        c.view,
                        c.existing_debugger,
                        c.expected_debugger,
                        c.signature
                    );
                    if let Some(note) = &c.signature_notice {
                        println!("    Note:        {}", signature_notice_label(note));
                    }
                    if !c.path_hints.is_empty() {
                        println!("    Path hints:");
                        for hint in &c.path_hints {
                            println!("      - {}", format_path_hint(hint));
                        }
                    }
                }
            }
        }

        Command::Targets { command } => {
            handle_targets_command(&runtime, command)?;
        }

        Command::Cleanup { scan, json } => {
            ensure_safe_bin_dir(allow_unsafe, "cleanup")?;
            if scan {
                // 包括クリーンアップ - レジストリスキャンで自社エントリ検出
                let report = runtime.comprehensive_cleanup()?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&map_safe_cleanup_report(&report))?);
                } else {
                    println!("Comprehensive cleanup completed (registry scan):");
                    if !report.removed.is_empty() {
                        println!("  Removed (ours): {} entries", report.removed.len());
                        for target in &report.removed {
                            println!("    - {}", target);
                        }
                    } else {
                        println!("  No KaptainhooK entries found in registry.");
                    }
                }
            } else {
                let config = load_config_with_default_if_missing(&runtime)?;
                // 安全クリーンアップ - 設定ベースで自社エントリのみ削除
                let report = runtime.safe_cleanup(&config)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&map_safe_cleanup_report(&report))?);
                } else {
                    println!("Safe cleanup completed:");
                    if !report.removed.is_empty() {
                        println!("  Removed (ours): {} entries", report.removed.len());
                        for target in &report.removed {
                            println!("    - {}", target);
                        }
                    }
                    if !report.skipped.is_empty() {
                        println!(
                            "  Skipped (other products): {} entries",
                            report.skipped.len()
                        );
                        for (target, debugger) in &report.skipped {
                            println!("    ! {} -> {}", target, debugger);
                        }
                    }
                    if !report.not_registered.is_empty() {
                        println!("  Not registered: {} entries", report.not_registered.len());
                    }
                }
            }
        }

        Command::Rollback { json } => {
            ensure_safe_bin_dir(allow_unsafe, "rollback")?;
            let restored = runtime.rollback()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&restored)?);
            } else if restored.is_empty() {
                println!("No backup entries to restore.");
            } else {
                println!("Rolled back {} targets:", restored.len());
                for t in &restored {
                    println!("  - {}", t);
                }
            }
        }

        Command::Uninstall { remove_data, json } => {
            ensure_safe_bin_dir(allow_unsafe, "uninstall")?;
            let config = InstallConfig::default();
            let report = runtime.uninstall(&config, remove_data)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_uninstall_report(&report);
            }
        }

        Command::TaskInfo { json } => {
            print_task_info(json)?;
        }
        Command::TrustedHashes { command } => {
            ensure_safe_bin_dir(allow_unsafe, "trusted-hashes")?;
            match command {
                TrustedHashesCommand::Refresh { bin_dir } => {
                    #[cfg(windows)]
                    {
                        let dir = bin_dir.unwrap_or_else(paths::default_bin_dir);
                        system::write_trusted_hashes(&dir)
                            .map_err(|e| err(format!("Failed to write TrustedHashes: {e}")))?;
                        println!("TrustedHashes updated: {}", dir.display());
                    }
                    #[cfg(not(windows))]
                    {
                        let _ = bin_dir;
                        bail!("TrustedHashes is supported on Windows only");
                    }
                }
            }
        }
    }
    Ok(())
}

fn load_config_with_default_if_missing(runtime: &CliRuntime) -> Result<InstallConfig> {
    match runtime.load_config() {
        Ok(config) => Ok(config),
        Err(err) => {
            if !runtime.config_exists() {
                eprintln!("WARNING: Config file not found. Using default targets only.");
                eprintln!("         Use --scan to search registry for all our entries.");
                Ok(InstallConfig::default())
            } else {
                bail!("Config load failed: {err}");
            }
        }
    }
}

fn allow_unsafe_paths(flag: bool) -> bool {
    if flag {
        return true;
    }
    std::env::var("KH_ALLOW_UNSAFE_PATHS")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn normalize_path_for_compare(path: &std::path::Path) -> String {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut s = canonical.to_string_lossy().to_string();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        s = stripped.to_string();
    }
    s = s.replace('/', "\\").to_ascii_lowercase();
    while s.ends_with('\\') {
        s.pop();
    }
    s
}

fn ensure_safe_bin_dir(allow_unsafe: bool, action: &str) -> Result<()> {
    if allow_unsafe {
        return Ok(());
    }
    #[cfg(windows)]
    {
        let bin_dir = paths::default_bin_dir();
        let required = ["kh-bootstrap.exe", "kh-guard.exe"];
        let mut missing: Vec<&str> = Vec::new();
        for bin in required {
            if !bin_dir.join(bin).is_file() {
                missing.push(bin);
            }
        }
        if !missing.is_empty() {
            bail!(
                "Refusing to {action}: expected install dir {:?} is missing {}. Run kh-setup or set KH_ALLOW_UNSAFE_PATHS=1 / --allow-unsafe-path to override.",
                bin_dir,
                missing.join(", ")
            );
        }

        let current_exe = std::env::current_exe()
            .map_err(|e| err(format!("Failed to get current executable path: {e}")))?;
        let current_dir = current_exe
            .parent()
            .ok_or_else(|| err("Failed to get current executable directory"))?;
        let current_norm = normalize_path_for_compare(current_dir);
        let expected_norm = normalize_path_for_compare(&bin_dir);
        if current_norm != expected_norm {
            bail!(
                "Refusing to {action}: running from {:?} but expected install dir is {:?}. Running outside Program Files can leave IFEO debugger entries. Use the installed binaries or set KH_ALLOW_UNSAFE_PATHS=1 / --allow-unsafe-path to override.",
                current_dir,
                bin_dir
            );
        }
    }
    Ok(())
}

fn ensure_install_prereqs(runtime: &CliRuntime) -> Result<()> {
    if !runtime.config_exists() {
        bail!("Config not found. Run kh-setup first for a full installation.");
    }
    let targets = targets::load_enabled_targets()
        .map_err(|e| err(format!("Failed to read Targets registry: {e}")))?;
    if targets.is_empty() {
        bail!("No enabled targets found. Run kh-setup to initialize protected targets.");
    }
    Ok(())
}
fn print_task_info(json_output: bool) -> Result<()> {
    #[cfg(windows)]
    {
        use kh_composition::cli::RESTORE_TASK_NAME;
        match kh_composition::task::query_task_details(RESTORE_TASK_NAME) {
            Ok(info) => {
                if json_output {
                    println!(
                        "{}",
                        serde_json::json!({
                            "exists": true,
                            "task_name": info.task_name,
                            "status": info.status,
                            "run_as_user": info.run_as_user,
                            "run_level": info.run_level,
                            "task_to_run": info.task_to_run,
                            "last_run_time": info.last_run_time,
                            "last_result": info.last_result,
                        })
                    );
                } else {
                    println!("Restore Task Status:");
                    println!("  Task Name:     {}", info.task_name);
                    println!("  Status:        {}", info.status);
                    println!("  Run As User:   {}", info.run_as_user);
                    println!("  Run Level:     {}", info.run_level);
                    println!("  Command:       {}", info.task_to_run);
                    println!("  Last Run:      {}", info.last_run_time);
                    println!("  Last Result:   {}", info.last_result);
                }
            }
            Err(_) => {
                if json_output {
                    println!(
                        "{}",
                        serde_json::json!({
                            "exists": false,
                            "message": "Task not found. Run 'kh-setup' to register the restore task."
                        })
                    );
                } else {
                    println!("Restore task '{}' not found.", RESTORE_TASK_NAME);
                    println!("Run 'kh-setup' to register the restore task.");
                }
            }
        }
    }

    #[cfg(not(windows))]
    {
        if json_output {
            println!(
                "{}",
                serde_json::json!({
                    "exists": false,
                    "message": "Task scheduler is only available on Windows"
                })
            );
        } else {
            println!("Task scheduler is only available on Windows.");
        }
    }

    Ok(())
}

fn print_uninstall_report(report: &UninstallReport) {
    println!("Uninstall completed:");

    if !report.ifeo_removed.is_empty() {
        println!("  IFEO removed: {} entries", report.ifeo_removed.len());
        for target in &report.ifeo_removed {
            println!("    - {}", target);
        }
    }

    if !report.ifeo_restored.is_empty() {
        println!("  IFEO restored: {} entries", report.ifeo_restored.len());
        for target in &report.ifeo_restored {
            println!("    - {}", target);
        }
    }

    if !report.ifeo_skipped.is_empty() {
        println!(
            "  IFEO skipped (other products): {} entries",
            report.ifeo_skipped.len()
        );
        for (target, debugger) in &report.ifeo_skipped {
            println!("    ! {} -> {}", target, debugger);
        }
    }

    if !report.ifeo_restore_errors.is_empty() {
        println!(
            "  IFEO restore errors: {}",
            report.ifeo_restore_errors.len()
        );
        for err in &report.ifeo_restore_errors {
            println!("    ! {}", err);
        }
    }

    if report.task_deleted {
        println!("  Scheduled task: deleted");
    } else if let Some(err) = &report.task_error {
        println!("  Scheduled task: error - {}", err);
    } else {
        println!("  Scheduled task: not found (already removed)");
    }

    if report.backup_cleared {
        println!("  Backup store: cleared");
    } else if let Some(err) = &report.backup_error {
        println!("  Backup store: error - {}", err);
    }

    if report.bin_removed {
        println!("  Bin directory: removed");
    } else if let Some(err) = &report.bin_error {
        println!("  Bin directory: error - {}", err);
    }

    if report.data_removed {
        println!("  Data directory: removed");
    } else if let Some(err) = &report.data_error {
        println!("  Data directory: error - {}", err);
    }
}

// -------------------------------------------------------------------------
// ターゲット管理
// -------------------------------------------------------------------------

fn handle_targets_command(runtime: &CliRuntime, command: TargetsCommand) -> Result<()> {
    match command {
        TargetsCommand::List { json } => list_targets(runtime, json),
        TargetsCommand::Enable { targets, conflict } => {
            let mode = TargetConflictMode::from_flag(&conflict);
            update_targets(runtime, targets, TargetUpdate::Enable(mode))
        }
        TargetsCommand::Disable { targets } => {
            update_targets(runtime, targets, TargetUpdate::Disable)
        }
        TargetsCommand::Remove { targets } => {
            update_targets(runtime, targets, TargetUpdate::Remove)
        }
    }
}

fn list_targets(runtime: &CliRuntime, json: bool) -> Result<()> {
    let mut config = load_config_or_default_with_warning(runtime)?;
    config.normalize();
    let mut items = config.targets.clone();
    items.sort_by(|a, b| a.exe_name().cmp(b.exe_name()));

    if json {
        let body: Vec<JsonTargetEntry> = items
            .into_iter()
            .map(|t| JsonTargetEntry {
                target: t.exe_name().to_string(),
                enabled: t.enabled(),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else {
        println!("Targets ({}):", items.len());
        for t in items {
            println!("  {:<20} enabled={}", t.exe_name(), t.enabled());
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TargetUpdate {
    Enable(TargetConflictMode),
    Disable,
    Remove,
}

fn update_targets(runtime: &CliRuntime, raw_targets: Vec<String>, action: TargetUpdate) -> Result<()> {
    let targets = normalize_target_args(raw_targets)?;

    let mut config = load_config_or_default_with_warning(runtime)?;
    let original = config.clone();
    let mut removed: Vec<String> = Vec::new();

    match action {
        TargetUpdate::Enable(_) => {
            for name in &targets {
                if let Some(existing) = config
                    .targets
                    .iter_mut()
                    .find(|t| t.exe_name().eq_ignore_ascii_case(name))
                {
                    existing.set_enabled(true);
                } else {
                    config.targets.push(Target::new(name, true).map_err(|e| err(e.to_string()))?);
                }
            }
        }
        TargetUpdate::Disable => {
            for name in &targets {
                if let Some(existing) = config
                    .targets
                    .iter_mut()
                    .find(|t| t.exe_name().eq_ignore_ascii_case(name))
                {
                    existing.set_enabled(false);
                } else {
                    config.targets.push(Target::new(name, false).map_err(|e| err(e.to_string()))?);
                }
            }
        }
        TargetUpdate::Remove => {
            for name in &targets {
                let before = config.targets.len();
                config
                    .targets
                    .retain(|t| !t.exe_name().eq_ignore_ascii_case(name));
                if before != config.targets.len() {
                    removed.push(name.clone());
                }
            }
        }
    }

    config.normalize();
    config.validate().map_err(|e| err(e.to_string()))?;

    let mut diff = compute_target_diff(&original, &config);
    let mut decisions: Vec<AdminConflictDecision> = Vec::new();

    if let TargetUpdate::Enable(mode) = action {
        if !diff.enable.is_empty() {
            let report = scan_foreign_conflicts(runtime, &diff.enable)?;
            if !report.targets.is_empty() {
                print_conflict_report(&report);
                match mode {
                    TargetConflictMode::Respect => {
                        for target in &report.targets {
                            set_target_enabled(&mut config, target, false);
                        }
                        config.normalize();
                        config.validate().map_err(|e| err(e.to_string()))?;
                        diff = compute_target_diff(&original, &config);
                    }
                    TargetConflictMode::Overwrite => {
                        decisions = report
                            .targets
                            .iter()
                            .map(|t| AdminConflictDecision {
                                target: t.clone(),
                                action: AdminConflictAction::TakeOver,
                            })
                            .collect();
                    }
                    TargetConflictMode::Quarantine => {
                        decisions = report
                            .targets
                            .iter()
                            .map(|t| AdminConflictDecision {
                                target: t.clone(),
                                action: AdminConflictAction::Quarantine,
                            })
                            .collect();
                    }
                    TargetConflictMode::Abort => {
                        bail!(
                            "Conflicts detected for {} target(s); aborting per --conflict=abort.",
                            report.targets.len()
                        );
                    }
                }
            }
        }
    }

    if config == original {
        println!("No target changes required.");
        return Ok(());
    }

    apply_target_changes(&diff.enable, &diff.disable, &config, decisions)?;
    runtime
        .save_config(&config)
        .map_err(|e| err(format!("Failed to save config: {e}")))?;

    println!("Targets updated.");
    if !diff.enable.is_empty() {
        println!("  Enabled: {}", diff.enable.join(", "));
    }
    if !diff.disable.is_empty() {
        println!("  Disabled: {}", diff.disable.join(", "));
    }
    if matches!(action, TargetUpdate::Remove) && !removed.is_empty() {
        println!("  Removed: {}", removed.join(", "));
    }
    Ok(())
}

fn load_config_or_default_with_warning(runtime: &CliRuntime) -> Result<InstallConfig> {
    match runtime.load_config() {
        Ok(config) => Ok(config),
        Err(err) => {
            if !runtime.config_exists() {
                eprintln!("WARNING: Config file not found. Using default targets.");
                Ok(InstallConfig::default())
            } else {
                bail!("Config load failed: {err}");
            }
        }
    }
}

fn normalize_target_args(raw_targets: Vec<String>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for raw in raw_targets {
        let target = Target::new(raw, true).map_err(|e| err(e.to_string()))?;
        out.push(target.exe_name().to_string());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn apply_target_changes(
    to_enable: &[String],
    to_disable: &[String],
    next_config: &InstallConfig,
    conflicts: Vec<AdminConflictDecision>,
) -> Result<()> {
    let enabled_targets: Vec<String> = next_config
        .targets
        .iter()
        .filter(|t| t.enabled())
        .map(|t| t.exe_name().to_string())
        .collect();

    let payload = ApplyTargetsRequest {
        enable: to_enable.to_vec(),
        disable: to_disable.to_vec(),
        enabled_targets,
        conflicts,
    };

    apply_targets_with_uac_if_needed(payload).map_err(|e| err(e))?;
    Ok(())
}

fn set_target_enabled(config: &mut InstallConfig, name: &str, enabled: bool) {
    for target in &mut config.targets {
        if target.exe_name().eq_ignore_ascii_case(name) {
            target.set_enabled(enabled);
        }
    }
}

#[derive(Default)]
struct ConflictScan {
    targets: Vec<String>,
    entries: Vec<ConflictEntry>,
    non_string: Vec<NonStringConflict>,
}

#[cfg(windows)]
fn scan_foreign_conflicts(runtime: &CliRuntime, to_enable: &[String]) -> Result<ConflictScan> {
    if to_enable.is_empty() {
        return Ok(ConflictScan::default());
    }

    let mut temp_config = InstallConfig::default();
    temp_config.targets.clear();
    for target in to_enable {
        if let Ok(t) = Target::new(target, true) {
            temp_config.targets.push(t);
        }
    }
    if temp_config.targets.is_empty() {
        return Ok(ConflictScan::default());
    }

    let conflict_entries = runtime
        .detect_conflicts(&temp_config)
        .map_err(|e| err(format!("Failed to detect conflicts: {e}")))?;

    let admin = AdminService::new(AdminDeps { port: runtime });
    let non_string = admin
        .scan_non_string_conflicts(to_enable)
        .map_err(|e| err(format!("Failed to detect non-string conflicts: {e}")))?;

    let mut targets: HashSet<String> = HashSet::new();
    for entry in &conflict_entries {
        targets.insert(entry.target.to_ascii_lowercase());
    }
    for entry in &non_string {
        targets.insert(entry.target.to_ascii_lowercase());
    }

    let mut targets: Vec<String> = targets.into_iter().collect();
    targets.sort();

    Ok(ConflictScan {
        targets,
        entries: conflict_entries,
        non_string,
    })
}

#[cfg(not(windows))]
fn scan_foreign_conflicts(_runtime: &CliRuntime, _to_enable: &[String]) -> Result<ConflictScan> {
    Ok(ConflictScan::default())
}

fn signature_notice_label(kind: &SignatureNoticeKind) -> &'static str {
    match kind {
        SignatureNoticeKind::Unsigned => "Unsigned",
        SignatureNoticeKind::Untrusted => "Untrusted signature",
        SignatureNoticeKind::Revoked => "Revoked signature",
        SignatureNoticeKind::RevocationNotChecked => "Revocation not checked",
        SignatureNoticeKind::RevocationCheckFailed => "Revocation check failed",
        SignatureNoticeKind::Error => "Signature verification error",
        SignatureNoticeKind::Unsupported => "Signature verification unsupported",
    }
}

fn path_hint_label(kind: PathHintKind) -> &'static str {
    match kind {
        PathHintKind::PublicUserDir => "Under Public user",
        PathHintKind::TempDir => "Under Temp",
        PathHintKind::UserTempDir => "Under user Temp",
        PathHintKind::DownloadsDir => "Under Downloads",
        PathHintKind::DesktopDir => "Under Desktop",
        PathHintKind::ProgramFilesDir => "Under Program Files",
        PathHintKind::ProgramFilesX86Dir => "Under Program Files (x86)",
        PathHintKind::System32Dir => "Under System32",
        PathHintKind::SysWow64Dir => "Under SysWOW64",
    }
}

fn format_path_hint(hint: &PathHint) -> String {
    format!("{} ({})", path_hint_label(hint.kind), hint.pattern)
}

fn print_conflict_report(report: &ConflictScan) {
    if report.targets.is_empty() {
        return;
    }
    println!(
        "Conflicts detected for {} target(s):",
        report.targets.len()
    );

    for entry in &report.entries {
        println!(
            "  {} [{:?}] existing={} expected={}",
            entry.target, entry.view, entry.existing_debugger, entry.expected_debugger
        );
        println!("    Signature: {:?}", entry.signature);
        if let Some(note) = &entry.signature_notice {
            println!("    Note: {}", signature_notice_label(note));
        }
        if !entry.path_hints.is_empty() {
            let hints: Vec<String> = entry
                .path_hints
                .iter()
                .map(format_path_hint)
                .collect();
            println!("    Path hints: {}", hints.join(", "));
        }
    }

    for entry in &report.non_string {
        println!(
            "  {} [{:?}] existing=<non-string debugger>",
            entry.target, entry.view
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetConflictMode {
    Respect,
    Overwrite,
    Quarantine,
    Abort,
}

impl TargetConflictMode {
    fn from_flag(flag: &str) -> Self {
        match flag {
            "overwrite" => TargetConflictMode::Overwrite,
            "quarantine" => TargetConflictMode::Quarantine,
            "abort" => TargetConflictMode::Abort,
            _ => TargetConflictMode::Respect,
        }
    }
}

struct TargetDiff {
    enable: Vec<String>,
    disable: Vec<String>,
}

fn compute_target_diff(old_cfg: &InstallConfig, new_cfg: &InstallConfig) -> TargetDiff {
    let mut old_map: HashMap<String, bool> = HashMap::new();
    for target in &old_cfg.targets {
        old_map.insert(target.exe_name().to_ascii_lowercase(), target.enabled());
    }

    let mut new_map: HashMap<String, bool> = HashMap::new();
    for target in &new_cfg.targets {
        new_map.insert(target.exe_name().to_ascii_lowercase(), target.enabled());
    }

    let mut to_enable = Vec::new();
    for (name, enabled) in &new_map {
        let was_enabled = old_map.get(name).copied().unwrap_or(false);
        if *enabled && !was_enabled {
            to_enable.push(name.clone());
        }
    }

    let mut to_disable = Vec::new();
    for (name, was_enabled) in &old_map {
        let enabled_now = new_map.get(name).copied().unwrap_or(false);
        if *was_enabled && !enabled_now {
            to_disable.push(name.clone());
        }
    }

    to_enable.sort();
    to_disable.sort();

    TargetDiff {
        enable: to_enable,
        disable: to_disable,
    }
}

// JSON出力用構造体（CLIプレゼンテーション層専用）

#[derive(Serialize)]
struct JsonTargetEntry {
    target: String,
    enabled: bool,
}

#[derive(Serialize)]
struct JsonInstallPlan {
    dry_run: bool,
    entries: Vec<JsonInstallPlanEntry>,
}

#[derive(Serialize)]
struct JsonInstallPlanEntry {
    target: String,
    action: JsonPlanAction,
    debugger_path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum JsonPlanAction {
    Install,
    WouldInstall,
}

#[derive(Serialize)]
struct JsonInstallReport {
    registered: Vec<String>,
    unregistered: Vec<String>,
}

#[derive(Serialize)]
struct JsonSafeCleanupReport {
    removed: Vec<String>,
    skipped: Vec<(String, String)>,
    not_registered: Vec<String>,
}

fn map_plan_action(action: kh_composition::app::PlanAction) -> JsonPlanAction {
    match action {
        kh_composition::app::PlanAction::Install => JsonPlanAction::Install,
        kh_composition::app::PlanAction::WouldInstall => JsonPlanAction::WouldInstall,
    }
}

fn map_install_plan(entries: Vec<kh_composition::app::InstallPlanEntry>) -> Vec<JsonInstallPlanEntry> {
    entries
        .into_iter()
        .map(|entry| JsonInstallPlanEntry {
            target: entry.target,
            action: map_plan_action(entry.action),
            debugger_path: entry.debugger_path,
        })
        .collect()
}

fn map_install_report(report: &InstallReport) -> JsonInstallReport {
    JsonInstallReport {
        registered: report.registered.clone(),
        unregistered: report.unregistered.clone(),
    }
}

fn map_safe_cleanup_report(report: &SafeCleanupReport) -> JsonSafeCleanupReport {
    JsonSafeCleanupReport {
        removed: report.removed.clone(),
        skipped: report.skipped.clone(),
        not_registered: report.not_registered.clone(),
    }
}

#[derive(Serialize)]
struct JsonStatusEntry {
    target: String,
    enabled: bool,
    debugger: Option<String>,
    view: String,
}

#[derive(Serialize)]
struct JsonConflict {
    target: String,
    view: String,
    existing_debugger: String,
    expected_debugger: String,
    signature: String,
    signature_notice: Option<String>,
    path_hints: Vec<String>,
}

// -------------------------------------------------------------------------
// 競合処理ヘルパー
// -------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConflictMode {
    Abort,
    Skip,
    Overwrite,
    Prompt,
}

impl ConflictMode {
    fn from_flag(flag: &str) -> Self {
        match flag {
            "skip" => ConflictMode::Skip,
            "overwrite" => ConflictMode::Overwrite,
            "prompt" | "interactive" => ConflictMode::Prompt,
            _ => ConflictMode::Abort,
        }
    }

    fn into_resolution(self) -> ConflictResolution {
        match self {
            ConflictMode::Abort => ConflictResolution::Abort,
            ConflictMode::Skip => ConflictResolution::Skip,
            ConflictMode::Overwrite => ConflictResolution::Overwrite,
            ConflictMode::Prompt => {
                // 呼び出し元でガードされているため到達しない
                ConflictResolution::Abort
            }
        }
    }
}

fn print_install_report(report: &InstallReport) {
    println!("Install completed:");
    println!("  Registered: {} targets", report.registered.len());
    for target in &report.registered {
        println!("    + {}", target);
    }
    if !report.unregistered.is_empty() {
        println!("  Unregistered: {} targets", report.unregistered.len());
        for target in &report.unregistered {
            println!("    - {}", target);
        }
    }
}

fn handle_interactive_install(runtime: &CliRuntime, config: &mut InstallConfig) -> Result<()> {
    let conflicts = runtime.detect_conflicts(&config)?;
    if conflicts.is_empty() {
        println!("No conflicts detected. Proceeding with install.");
        let report = runtime.install_with_backup(&config, ConflictResolution::Abort)?;
        print_install_report(&report);
        return Ok(());
    }

    let mut grouped: BTreeMap<String, Vec<ConflictEntry>> = BTreeMap::new();
    for entry in conflicts {
        grouped
            .entry(entry.target.clone())
            .or_insert_with(Vec::new)
            .push(entry);
    }

    println!(
        "Conflicts detected for {} target(s). Choose how to handle each:",
        grouped.len()
    );

    let mut skip_targets: HashSet<String> = HashSet::new();
    let mut overwrite_targets: HashSet<String> = HashSet::new();

    for (target, entries) in &grouped {
        println!("\nTarget: {}", target);
        for entry in entries {
            println!("  [{:?}] Existing: {}", entry.view, entry.existing_debugger);
            println!("          Expected: {}", entry.expected_debugger);
            println!("          Signature: {:?}", entry.signature);
            if let Some(note) = &entry.signature_notice {
                println!("          Note: {}", signature_notice_label(note));
            }
            if !entry.path_hints.is_empty() {
                println!("          Path hints:");
                for hint in &entry.path_hints {
                    println!("            - {}", format_path_hint(hint));
                }
            }
        }

        match prompt_conflict_decision()? {
            ConflictDecision::Skip => {
                skip_targets.insert(target_key(target));
                println!("  -> Will skip installing for {}", target);
            }
            ConflictDecision::Overwrite => {
                overwrite_targets.insert(target_key(target));
                println!("  -> Will overwrite IFEO for {}", target);
            }
            ConflictDecision::Abort => {
                println!("Installation aborted by user.");
                return Ok(());
            }
        }
    }

    if overwrite_targets.is_empty() && !skip_targets.is_empty() {
        println!("All conflicted targets will be skipped. Continuing with non-conflicting targets.");
    }

    for target in config.targets.iter_mut() {
        if skip_targets.contains(&target_key(target.exe_name())) {
            target.set_enabled(false);
        }
    }

    let resolution = if overwrite_targets.is_empty() {
        ConflictResolution::Skip
    } else {
        ConflictResolution::Overwrite
    };

    let report = runtime.install_with_backup(&config, resolution)?;
    print_install_report(&report);

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConflictDecision {
    Skip,
    Overwrite,
    Abort,
}

fn prompt_conflict_decision() -> Result<ConflictDecision> {
    loop {
        print!("Choose action: [s]kip / [o]verwrite / [a]bort > ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        match input.trim().to_ascii_lowercase().as_str() {
            "s" | "skip" => return Ok(ConflictDecision::Skip),
            "o" | "overwrite" => return Ok(ConflictDecision::Overwrite),
            "a" | "abort" => return Ok(ConflictDecision::Abort),
            _ => {
                println!("  Invalid choice. Please enter s, o, or a.");
            }
        }
    }
}

fn target_key(value: &str) -> String {
    value.to_ascii_lowercase()
}

