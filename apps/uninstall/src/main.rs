#![windows_subsystem = "windows"]
//! KaptainhooK 単体アンインストーラー。
//! IFEOに依存せず削除/復元を行う緊急用。
//! 主な処理: IFEO復元、タスク/サービス/起動登録/データ/バイナリ削除。

use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use kh_log_utils::lifecycle_line;
use kh_composition::cli::CliRuntime;
use kh_composition::domain::path::normalize_local_drive_absolute_path;
use kh_composition::domain::port::driven::TaskScheduler;
use kh_composition::domain::model::Language;
use kh_composition::system;
use kh_composition::app::uninstall::{
    ForeignPolicy, RestoreOptions, RestoreReportItem as ReportItem, UninstallDeps, UninstallService,
};
use kh_composition::ui_common::i18n;
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, KF_FLAG_DEFAULT,
    SHGetKnownFolderPath, ShellExecuteW,
};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, WAIT_TIMEOUT, ERROR_INSUFFICIENT_BUFFER};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
    WaitForSingleObject, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE, PROCESS_SYNCHRONIZE,
};
use windows::Win32::System::SystemInformation::GetLocalTime;
use windows::core::{PCWSTR, PWSTR};

const RESTORE_TASK_NAME: &str = kh_composition::task::DEFAULT_RESTORE_TASK_NAME;

#[derive(Clone, Copy, Debug)]
struct UninstallOptions {
    quiet: bool,
    allow_unsafe_path: bool,
}

fn parse_options() -> UninstallOptions {
    let mut options = UninstallOptions {
        quiet: false,
        allow_unsafe_path: false,
    };
    for arg in std::env::args().skip(1) {
        let arg = arg.to_ascii_lowercase();
        match arg.as_str() {
            "/quiet" | "--quiet" | "/silent" | "--silent" | "/s" | "-s" => {
                options.quiet = true;
            }
            "/allow-unsafe-path" | "--allow-unsafe-path" | "/unsafe-path" | "--unsafe-path" => {
                options.allow_unsafe_path = true;
            }
            _ => {}
        }
    }
    options
}

fn allow_unsafe_paths(options: &UninstallOptions) -> bool {
    if options.allow_unsafe_path {
        return true;
    }
    std::env::var("KH_ALLOW_UNSAFE_PATHS")
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn is_japanese() -> bool {
    matches!(i18n::current_language(), Language::Japanese)
}

fn uninstall_title() -> &'static str {
    if is_japanese() {
        "KaptainhooK アンインストール"
    } else {
        "KaptainhooK Uninstall"
    }
}

fn normalize_dir_for_compare(dir: &PathBuf) -> Option<String> {
    let raw = dir.to_string_lossy().to_string();
    let mut normalized = normalize_local_absolute_path(&raw)?;
    normalized = normalized.to_lowercase();
    while normalized.ends_with('\\') {
        normalized.pop();
    }
    Some(normalized)
}

fn expected_install_bin_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(pf) = known_folder_path(&FOLDERID_ProgramFiles) {
        dirs.push(pf.join("KaptainhooK").join("bin"));
    }
    if let Some(pd) = known_folder_path(&FOLDERID_ProgramData) {
        dirs.push(pd.join("KaptainhooK").join("bin"));
    }
    if dirs.is_empty() {
        dirs.push(
            PathBuf::from(r"C:\Program Files")
                .join("KaptainhooK")
                .join("bin"),
        );
    }
    dirs
}

fn ensure_safe_uninstall_location(options: &UninstallOptions) -> bool {
    if allow_unsafe_paths(options) {
        return true;
    }

    let current_dir = match std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) {
        Some(dir) => dir,
        None => {
            log("Failed to resolve current executable directory for safety check.");
            if !options.quiet {
                msgbox(
                    uninstall_title(),
                    if is_japanese() {
                        "実行ファイルのパスを取得できませんでした。\n\n\
                        インストール済み以外の場所から実行すると、IFEO デバッガが残る可能性があります。\n\n\
                        インストール済みのアンインストーラーを使用するか、KH_ALLOW_UNSAFE_PATHS=1 / --allow-unsafe-path を指定してください。"
                    } else {
                        "Failed to resolve the current executable path.\n\n\
                        Running from a non-installed location can leave IFEO debugger entries.\n\n\
                        Use the installed uninstaller or set KH_ALLOW_UNSAFE_PATHS=1 / --allow-unsafe-path to proceed."
                    },
                    MB_OK | MB_ICONWARNING,
                );
            }
            return false;
        }
    };

    let current_norm = match normalize_dir_for_compare(&current_dir) {
        Some(norm) => norm,
        None => {
            log("Current executable directory is not a local absolute path.");
            if !options.quiet {
                msgbox(
                    uninstall_title(),
                    if is_japanese() {
                        "実行ファイルのパスがローカルの絶対パスではありません。\n\n\
                        インストール済み以外の場所から実行すると、IFEO デバッガが残る可能性があります。\n\n\
                        インストール済みのアンインストーラーを使用するか、KH_ALLOW_UNSAFE_PATHS=1 / --allow-unsafe-path を指定してください。"
                    } else {
                        "Current executable path is not a local absolute path.\n\n\
                        Running from a non-installed location can leave IFEO debugger entries.\n\n\
                        Use the installed uninstaller or set KH_ALLOW_UNSAFE_PATHS=1 / --allow-unsafe-path to proceed."
                    },
                    MB_OK | MB_ICONWARNING,
                );
            }
            return false;
        }
    };

    let expected_dirs = expected_install_bin_dirs();
    let matches = expected_dirs.iter().any(|dir| {
        normalize_dir_for_compare(dir)
            .map(|norm| norm == current_norm)
            .unwrap_or(false)
    });
    if matches {
        return true;
    }

    let expected_list = expected_dirs
        .iter()
        .map(|d| d.to_string_lossy())
        .collect::<Vec<_>>()
        .join(", ");
    let msg = if is_japanese() {
        format!(
            "アンインストーラーは {:?} から実行されています。\n\n想定されるインストール先:\n{}\n\n\
            Program Files 以外から実行すると、IFEO デバッガが残る可能性があります。\n\n\
            インストール済みのアンインストーラーを使用するか、KH_ALLOW_UNSAFE_PATHS=1 / --allow-unsafe-path を指定してください。",
            current_dir,
            expected_list
        )
    } else {
        format!(
            "Uninstaller is running from {:?}.\n\nExpected install directory:\n{}\n\n\
            Running from outside Program Files can leave IFEO debugger entries.\n\n\
            Use the installed uninstaller or set KH_ALLOW_UNSAFE_PATHS=1 / --allow-unsafe-path to proceed.",
            current_dir,
            expected_list
        )
    };
    log(&msg);
    if !options.quiet {
        msgbox(
            uninstall_title(),
            &msg,
            MB_OK | MB_ICONWARNING,
        );
    }
    false
}

/// 管理者権限で実行中かチェック
fn is_admin() -> bool {
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::Foundation::HANDLE;

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;

        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            size,
            &mut size,
        );

        let _ = windows::Win32::Foundation::CloseHandle(token);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// 管理者権限で再起動（UAC昇格）
fn relaunch_as_admin() -> bool {
    let exe_path = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return false,
    };

    let exe_wide: Vec<u16> = exe_path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let params = if args.is_empty() {
        Vec::new()
    } else {
        let joined = args
            .iter()
            .map(|arg| quote_windows_arg(arg))
            .collect::<Vec<_>>()
            .join(" ");
        OsStr::new(&joined)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };

    let verb = wstr("runas");

    unsafe {
        let result = ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(exe_wide.as_ptr()),
            if params.is_empty() { PCWSTR::null() } else { PCWSTR(params.as_ptr()) },
            PCWSTR::null(),
            windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        );

        // ShellExecuteWは成功時32より大きい値を返す
        result.0 as usize > 32
    }
}

/// ログファイルのパス（全アプリ統合ログ）
fn get_log_path() -> PathBuf {
    known_folder_path(&FOLDERID_ProgramData)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("KaptainhooK")
        .join("final")
        .join("logs")
        .join("kh-lifecycle.log")
}

/// ログに書き込み（コンポーネント識別子付き）
fn log(msg: &str) {
    let log_path = get_log_path();
    if let Some(dir) = log_path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        let line = lifecycle_line("UNINSTALL", msg);
        let _ = file.write_all(line.as_bytes());
    }
}

fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    let needs_quotes = arg.chars().any(|c| c.is_whitespace() || c == '"');
    if !needs_quotes {
        return arg.to_string();
    }
    let mut out = String::new();
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\\\".repeat(backslashes));
                out.push_str("\\\"");
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    out.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                out.push(ch);
            }
        }
    }
    if backslashes > 0 {
        out.push_str(&"\\\\".repeat(backslashes));
    }
    out.push('"');
    out
}

fn allowed_bin_dirs() -> Vec<String> {
    let mut dirs = Vec::new();
    let mut push_dir = |dir: PathBuf| {
        let raw = dir.to_string_lossy().to_string();
        if let Some(mut normalized) = normalize_local_absolute_path(&raw) {
            normalized = normalized.to_lowercase();
            if !normalized.ends_with('\\') {
                normalized.push('\\');
            }
            dirs.push(normalized);
        }
    };

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            push_dir(dir.to_path_buf());
        }
    }

    if let Some(pf) = known_folder_path(&FOLDERID_ProgramFiles) {
        push_dir(pf.join("KaptainhooK").join("bin"));
    }

    if let Some(pd) = known_folder_path(&FOLDERID_ProgramData) {
        push_dir(pd.join("KaptainhooK").join("bin"));
    }

    dirs.sort();
    dirs.dedup();
    dirs
}

fn normalize_process_path(path: &PathBuf) -> Option<String> {
    let raw = path.to_string_lossy().to_string();
    normalize_local_absolute_path(&raw).map(|s| s.to_lowercase())
}

fn is_allowed_bin_path(path: &str, allowed_dirs: &[String]) -> bool {
    allowed_dirs.iter().any(|dir| path.starts_with(dir))
}

fn query_process_path(handle: HANDLE) -> Result<PathBuf, String> {
    unsafe {
        let mut size: u32 = 260;
        loop {
            let mut buffer: Vec<u16> = vec![0u16; size as usize];
            let mut len = size;
            let result = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut len,
            );
            if result.is_ok() {
                buffer.truncate(len as usize);
                let path = String::from_utf16_lossy(&buffer);
                return Ok(PathBuf::from(path));
            }

            let err = GetLastError();
            if err == ERROR_INSUFFICIENT_BUFFER {
                size = size.saturating_mul(2).max(520);
                if size > 8192 {
                    return Err("process path too long".to_string());
                }
                continue;
            }
            if err.0 == 0 {
                return Err("QueryFullProcessImageNameW failed".to_string());
            }
            return Err(format!("QueryFullProcessImageNameW failed: {}", err.0));
        }
    }
}

struct UninstallReport {
    started_at: String,
    version: String,
    ifeo_items: Vec<ReportItem>,
    errors: Vec<String>,
}

impl UninstallReport {
    fn new() -> Self {
        Self {
            started_at: local_timestamp(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ifeo_items: Vec::new(),
            errors: Vec::new(),
        }
    }
}

fn local_timestamp() -> String {
    unsafe {
        let st = GetLocalTime();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds
        )
    }
}

fn main() {
    log("========== KaptainhooK Uninstall Started ==========");
    let options = parse_options();
    let runtime = CliRuntime::new();
    i18n::set_language(runtime.load_config_or_default().language);

    if !ensure_safe_uninstall_location(&options) {
        log("Unsafe uninstall location detected; aborting.");
        return;
    }

    // 最初に管理者権限チェック
    if !is_admin() {
        log("Not running as admin, requesting UAC elevation...");
        if relaunch_as_admin() {
            log("UAC elevation requested, exiting current process");
            return;
        } else {
            log("UAC elevation failed or was denied");
            if !options.quiet {
                msgbox(
                    uninstall_title(),
                    if is_japanese() {
                        "アンインストールには管理者権限が必要です。\n\n\
                        右クリックして「管理者として実行」を選択してください。"
                    } else {
                        "Administrator privileges are required to uninstall.\n\n\
                        Please right-click and select 'Run as administrator'."
                    },
                    MB_OK | MB_ICONERROR,
                );
            }
            if options.quiet {
                std::process::exit(1);
            }
            return;
        }
    }

    log("Running with admin privileges");

    // 確認ダイアログ表示
    if !options.quiet {
        let program_data = known_folder_path(&FOLDERID_ProgramData)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        let log_dir = PathBuf::from(&program_data).join("KaptainhooK").join("final");
        let result = msgbox(
            uninstall_title(),
            &format!(
                "{}",
                if is_japanese() {
                    format!(
                        "KaptainhooK を完全に削除します:\n\n\
                        \u{2022} IFEO レジストリエントリをすべて削除\n\
                        \u{2022} KaptainhooK のプロセスを終了\n\
                        \u{2022} Windows サービスを削除\n\
                        \u{2022} スケジュールタスクを削除\n\
                        \u{2022} スタートアップ登録を削除\n\
                        \u{2022} プログラムの追加と削除から削除\n\
                        \u{2022} 設定/データを削除\n\
                        \u{2022} プログラムファイルを削除\n\n\
                        ログは削除されます。必要なら事前にコピーしてください:\n{}\n\
                        アンインストールレポートは %WINDIR%\\Temp\\KaptainhooK に保存されます。\n\n\
                        続行しますか？",
                        log_dir.display()
                    )
                } else {
                    format!(
                        "This will COMPLETELY remove KaptainhooK:\n\n\
                        \u{2022} Remove all IFEO registry entries\n\
                        \u{2022} Kill all KaptainhooK processes\n\
                        \u{2022} Remove Windows service\n\
                        \u{2022} Delete scheduled tasks\n\
                        \u{2022} Remove startup entries\n\
                        \u{2022} Remove from Add/Remove Programs\n\
                        \u{2022} Delete all data and configuration\n\
                        \u{2022} Delete all program files\n\n\
                        Logs will be deleted. If you need them, copy before uninstall:\n{}\n\
                        A JSON report will be saved under %WINDIR%\\Temp\\KaptainhooK.\n\n\
                        Continue?",
                        log_dir.display()
                    )
                }
            ),
            MB_YESNO | MB_ICONWARNING,
        );

        if result != IDYES {
            log("User cancelled uninstall");
            return;
        }
        log("User confirmed uninstall");
    } else {
        log("Quiet uninstall: skipping confirmation dialog");
    }

    let mut errors: Vec<String> = Vec::new();
    let mut success_count = 0;
    let mut report = UninstallReport::new();
    let uninstall = UninstallService::new(UninstallDeps { port: &runtime });

    // 1. IFEO復元（プロセス終了の前に実施）
    log("Step 1: Restoring IFEO entries...");
    let mut ifeo_restore_incomplete = false;
    let mut ifeo_restore_skipped = false;
    let restore_policy = if options.quiet {
        ForeignPolicy::Error
    } else {
        ForeignPolicy::Prompt(prompt_restore_foreign)
    };
    let restore_options = RestoreOptions {
        expected_debugger_path: expected_bootstrap_path(),
        foreign_policy: restore_policy,
        logger: Some(log),
    };
    match uninstall.restore_ifeo_from_uninstall_state(&restore_options) {
        Ok(result) => {
            log(&format!(
                "Restored/removed {} IFEO entries",
                result.processed
            ));
            report.ifeo_items = result.items;
            if !result.errors.is_empty() {
                for err in result.errors {
                    errors.push(format!("IFEO: {}", err));
                }
                ifeo_restore_incomplete = true;
            } else {
                success_count += 1;
            }
            if report
                .ifeo_items
                .iter()
                .any(|item| item.outcome == "failed")
            {
                ifeo_restore_incomplete = true;
            }
            if report
                .ifeo_items
                .iter()
                .any(|item| item.outcome == "skipped")
            {
                ifeo_restore_incomplete = true;
                ifeo_restore_skipped = true;
            }
        }
        Err(e) => {
            log(&format!("IFEO restore error: {}", e));
            errors.push(format!("IFEO: {}", e));
            ifeo_restore_incomplete = true;
        }
    }

    if ifeo_restore_incomplete {
        if ifeo_restore_skipped {
            errors.push(if is_japanese() {
                "IFEO: 他製品のデバッガが検出されたため、アンインストールを中止しました。".to_string()
            } else {
                "IFEO: foreign debugger entries were skipped; uninstall halted".to_string()
            });
        } else {
            errors.push(if is_japanese() {
                "IFEO: 復元が完了しなかったため、アンインストールを中止しました。".to_string()
            } else {
                "IFEO: restore did not complete; uninstall halted".to_string()
            });
        }
        log("IFEO restore incomplete; aborting uninstall to avoid leaving blocked executables.");
        report.errors = errors.clone();
        let report_path = match write_uninstall_report(&report) {
            Ok(p) => {
                log(&format!("Uninstall report written: {}", p.display()));
                Some(p)
            }
            Err(e) => {
                log(&format!("Uninstall report write failed: {}", e));
                None
            }
        };

        if options.quiet {
            std::process::exit(1);
        }

        let mut guidance = if is_japanese() {
            "IFEO の復元が完了しませんでした。\n\n\
ブロック状態の実行ファイルが残る可能性があるため、アンインストールを停止しました。\n\n\
管理者としてアンインストーラーを再実行してください。"
                .to_string()
        } else {
            "IFEO restore did not complete.\n\n\
Uninstall has been stopped to avoid leaving blocked executables.\n\n\
Please re-run the uninstaller as Administrator."
                .to_string()
        };
        if let Some(path) = report_path {
            guidance.push_str(&format!(
                "\n\n{}:\n{}",
                if is_japanese() { "レポート保存先" } else { "Report saved to" },
                path.display()
            ));
        }
        msgbox(uninstall_title(), &guidance, MB_OK | MB_ICONWARNING);
        return;
    }

    // 2. タスク削除（強制復元を止める）
    log("Step 2: Deleting scheduled tasks...");
    for task_name in [RESTORE_TASK_NAME] {
        match delete_task(task_name) {
            Ok(_) => {
                log(&format!("Scheduled task deleted: {}", task_name));
                success_count += 1;
            }
            Err(e) => {
                log(&format!("Task deletion error ({}): {}", task_name, e));
                errors.push(format!(
                    "{} {}: {}",
                    if is_japanese() { "タスク" } else { "Task" },
                    task_name,
                    e
                ));
            }
        }
    }

    // 3. サービス削除
    log("Step 3: Removing service...");
    match system::remove_service() {
        Ok(()) => {
            log("Service removed");
            success_count += 1;
        }
        Err(e) => {
            log(&format!("Service removal error: {}", e));
            errors.push(format!(
                "{}: {}",
                if is_japanese() { "サービス" } else { "Service" },
                e
            ));
        }
    }

    // 4. 実行中プロセスを終了（IFEO削除後）
    log("Step 4: Killing processes...");
    match kill_all_processes() {
        Ok(killed) => {
            log(&format!("Killed {} processes", killed));
            success_count += 1;
        }
        Err(e) => {
            log(&format!("Process kill warning: {}", e));
            // エラーには追加せず継続
        }
    }

    // プロセス終了待ちの小休止
    std::thread::sleep(std::time::Duration::from_millis(500));

    // 5. スタートアップ削除（HKLM/HKCU）
    log("Step 5: Removing startup entries...");
    match system::remove_startup_entries() {
        Ok(_) => {
            log("Startup entries removed");
            success_count += 1;
        }
        Err(e) => {
            log(&format!("Startup removal error: {}", e));
            errors.push(format!(
                "{}: {}",
                if is_japanese() { "スタートアップ" } else { "Startup" },
                e
            ));
        }
    }

    // 5.5 スタートメニューショートカット削除
    log("Step 5.5: Removing start menu shortcut...");
    match system::remove_service_restart_shortcut() {
        Ok(_) => {
            log("Service restart shortcut removed");
            success_count += 1;
        }
        Err(e) => {
            log(&format!("Shortcut removal warning: {}", e));
        }
    }

    // 6. アプリ登録削除
    log("Step 6: Removing from Add/Remove Programs...");
    match system::remove_from_programs(system::UNINSTALL_KEY_NAME) {
        Ok(_) => {
            log("Removed from Add/Remove Programs");
            success_count += 1;
        }
        Err(e) => {
            log(&format!("Programs removal error: {}", e));
            errors.push(format!(
                "{}: {}",
                if is_japanese() { "プログラム" } else { "Programs" },
                e
            ));
        }
    }

    // 7. サービス/リストア用レジストリ削除
    log("Step 7: Removing registry state (Targets/TrustedHashes)...");
    match system::remove_registry_state() {
        Ok(_) => {
            log("Registry state removed");
        }
        Err(e) => {
            log(&format!("Registry state removal error: {}", e));
            errors.push(format!(
                "{}: {}",
                if is_japanese() { "レジストリ" } else { "Registry" },
                e
            ));
        }
    }

    let program_data = known_folder_path(&FOLDERID_ProgramData)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let program_files = known_folder_path(&FOLDERID_ProgramFiles)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));

    // 8. データ削除（ログ含む）
    log("Step 8: Deleting data directory...");
    let data_dir = PathBuf::from(&program_data).join("KaptainhooK").join("final");
    match delete_directory_contents(&data_dir, false) {
        Ok(_) => {
            log(&format!("Data directory cleaned: {:?}", data_dir));
            success_count += 1;
        }
        Err(e) => {
            log(&format!("Data deletion error: {}", e));
            errors.push(format!(
                "{}: {}",
                if is_japanese() { "データ" } else { "Data" },
                e
            ));
        }
    }

    // 9. bin削除（直ちに削除、失敗は予約）
    log("Step 9: Deleting program files...");
    let bin_dirs = [
        PathBuf::from(&program_files).join("KaptainhooK").join("bin"),
        PathBuf::from(&program_data).join("KaptainhooK").join("bin"),
    ];
    let kh_dirs = [
        PathBuf::from(&program_files).join("KaptainhooK"),
        PathBuf::from(&program_data).join("KaptainhooK"),
    ];

    // ハンドル解放待ちで少し追加待機
    std::thread::sleep(std::time::Duration::from_millis(500));

    // まず直接削除を試す
    for bin_dir in &bin_dirs {
        if bin_dir.exists() {
            if is_dir_reparse_point(bin_dir) {
                log(&format!("Skipping reparse point directory: {:?}", bin_dir));
                continue;
            }
            log(&format!("Attempting direct deletion of bin directory: {:?}", bin_dir));
            match fs::remove_dir_all(bin_dir) {
                Ok(_) => log("Bin directory deleted directly"),
                Err(e) => {
                    log(&format!("Direct deletion failed: {}, scheduling delayed deletion", e));
                    schedule_directory_deletion(bin_dir);
                }
            }
        }
    }

    // 親のKaptainhooKディレクトリ削除を試す
    for kh_dir in &kh_dirs {
        if kh_dir.exists() {
            // 先に残りのサブディレクトリ削除を試す
            if let Ok(entries) = fs::read_dir(kh_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        if is_dir_reparse_point(&path) {
                            log(&format!("Skipping reparse point directory: {:?}", path));
                            continue;
                        }
                        let _ = fs::remove_dir_all(&path);
                    } else {
                        let _ = fs::remove_file(&path);
                    }
                }
            }

            match fs::remove_dir(kh_dir) {
                Ok(_) => log("KaptainhooK directory deleted"),
                Err(e) => {
                    log(&format!("Parent directory deletion failed: {}, scheduling", e));
                    schedule_directory_deletion(kh_dir);
                }
            }
        }
    }

    log("========== Uninstall Complete ==========");
    log(&format!("Success: {}, Errors: {}", success_count, errors.len()));

    report.errors = errors.clone();
    let report_path = match write_uninstall_report(&report) {
        Ok(p) => {
            log(&format!("Uninstall report written: {}", p.display()));
            Some(p)
        }
        Err(e) => {
            log(&format!("Uninstall report write failed: {}", e));
            None
        }
    };

    if options.quiet {
        if errors.is_empty() {
            std::process::exit(0);
        } else {
            std::process::exit(1);
        }
    }

    // 結果表示
    if errors.is_empty() {
        msgbox(
            uninstall_title(),
            &format!(
                "{}",
                if is_japanese() {
                    format!(
                        "アンインストールが完了しました。\n\n\
                        KaptainhooK の全コンポーネントを削除しました。\n\n\
                        レポート保存先:\n{}\n\n\
                        プログラムフォルダは自動的に削除されます。",
                        report_path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "<レポート書き込み失敗>".to_string())
                    )
                } else {
                    format!(
                        "Uninstall complete!\n\n\
                        All KaptainhooK components have been removed.\n\n\
                        Report saved to:\n{}\n\n\
                        The program folder will be deleted automatically.",
                        report_path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "<failed to write report>".to_string())
                    )
                }
            ),
            MB_OK | MB_ICONINFORMATION,
        );
    } else {
        msgbox(
            uninstall_title(),
            &format!(
                "{}",
                if is_japanese() {
                    format!(
                        "アンインストールは {} 件のエラーで完了しました:\n\n{}\n\n\
                        {} 件の処理に成功しました。\n\n\
                        レポート保存先:\n{}",
                        errors.len(),
                        errors.join("\n"),
                        success_count,
                        report_path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "<レポート書き込み失敗>".to_string())
                    )
                } else {
                    format!(
                        "Uninstall completed with {} errors:\n\n{}\n\n\
                        {} operations succeeded.\n\n\
                        Report saved to:\n{}",
                        errors.len(),
                        errors.join("\n"),
                        success_count,
                        report_path
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "<failed to write report>".to_string())
                    )
                }
            ),
            MB_OK | MB_ICONWARNING,
        );
    }
}

/// 全KaptainhooKプロセス終了（Win32 API）
fn kill_all_processes() -> Result<u32, String> {
    let processes = [
        "kh-tray.exe",
        "kh-guard.exe",
        "kh-service.exe",
        "kh-restore.exe",
        "kh-bootstrap.exe",
        "kh-setup.exe",
        "kh-settings.exe",
        "kh-cli.exe",
    ];
    let targets: std::collections::HashSet<String> = processes
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let allowed_dirs = allowed_bin_dirs();
    if allowed_dirs.is_empty() {
        log("Allowed bin dirs not resolved; skip terminate by path");
    }

    let self_pid = unsafe { GetCurrentProcessId() };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("CreateToolhelp32Snapshot failed: {}", e.message()))?;

    let mut killed = 0u32;
    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
    while has_entry {
        let pid = entry.th32ProcessID;
        if pid != self_pid {
            let name = wide_cstr_to_string(&entry.szExeFile);
            let name_lc = name.to_ascii_lowercase();
            if targets.contains(&name_lc) {
                if terminate_process(pid, &name, &allowed_dirs) {
                    killed += 1;
                }
            }
        }
        has_entry = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }
    unsafe { let _ = CloseHandle(snapshot); }

    std::thread::sleep(std::time::Duration::from_millis(800));

    let remaining = list_remaining_processes(&targets, self_pid)?;
    if remaining.is_empty() {
        log("All KaptainhooK processes terminated");
    } else {
        log(&format!(
            "WARNING: Processes still running: {}",
            remaining.join(", ")
        ));
    }

    Ok(killed)
}

fn terminate_process(pid: u32, name: &str, allowed_dirs: &[String]) -> bool {
    unsafe {
        let handle = match OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        ) {
            Ok(h) => h,
            Err(e) => {
                log(&format!("OpenProcess failed for {} ({}): {}", name, pid, e.message()));
                return false;
            }
        };

        let exe_path = match query_process_path(handle) {
            Ok(path) => path,
            Err(err) => {
                log(&format!("Query process path failed for {} ({}): {}", name, pid, err));
                let _ = CloseHandle(handle);
                return false;
            }
        };
        let normalized = match normalize_process_path(&exe_path) {
            Some(path) => path,
            None => {
                log(&format!(
                    "Skip terminate {} ({}): non-local path {:?}",
                    name, pid, exe_path
                ));
                let _ = CloseHandle(handle);
                return false;
            }
        };
        if !is_allowed_bin_path(&normalized, allowed_dirs) {
            log(&format!(
                "Skip terminate {} ({}): outside allowed bin {}",
                name,
                pid,
                exe_path.display()
            ));
            let _ = CloseHandle(handle);
            return false;
        }

        let result = TerminateProcess(handle, 1);
        if result.is_err() {
            log(&format!("TerminateProcess failed for {} ({}): {:?}", name, pid, result));
            let _ = CloseHandle(handle);
            return false;
        }

        let wait = WaitForSingleObject(handle, 2000);
        if wait == WAIT_TIMEOUT {
            log(&format!("TerminateProcess timeout for {} ({})", name, pid));
        }
        let _ = CloseHandle(handle);
        true
    }
}

fn list_remaining_processes(
    targets: &std::collections::HashSet<String>,
    self_pid: u32,
) -> Result<Vec<String>, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| format!("CreateToolhelp32Snapshot failed: {}", e.message()))?;
    let mut entry = PROCESSENTRY32W::default();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut remaining = Vec::new();

    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();
    while has_entry {
        let pid = entry.th32ProcessID;
        if pid != self_pid {
            let name = wide_cstr_to_string(&entry.szExeFile);
            if targets.contains(&name.to_ascii_lowercase()) {
                remaining.push(name);
            }
        }
        has_entry = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }
    unsafe { let _ = CloseHandle(snapshot); }
    Ok(remaining)
}

/// スケジュールタスク削除
fn delete_task(task_name: &str) -> Result<(), String> {
    let scheduler = kh_composition::task::TaskSchedulerAdapter::new("");
    scheduler
        .delete_task(task_name)
        .map_err(|e| e.to_string())
}

// ============================================================================
// アンインストール報告
// ============================================================================

fn write_uninstall_report(report: &UninstallReport) -> Result<PathBuf, String> {
    let windir = get_windows_dir();
    let dir = windir.join("Temp").join("KaptainhooK");
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create report dir: {e}"))?;

    let ts = report
        .started_at
        .replace(['-', ':'], "")
        .replace('T', "")
        .replace('.', "");
    let file_name = format!("uninstall-report-{}.json", ts);
    let path = dir.join(file_name);

    let mut json = String::new();
    json.push('{');
    json.push_str(&format!(
        "\"timestamp\":\"{}\",",
        json_escape(&report.started_at)
    ));
    json.push_str(&format!(
        "\"version\":\"{}\",",
        json_escape(&report.version)
    ));
    json.push_str("\"ifeo_items\":[");
    for (i, item) in report.ifeo_items.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        let read_back = match item.read_back_ok {
            Some(true) => "true",
            Some(false) => "false",
            None => "null",
        };
        json.push_str(&format!(
            "{{\"target\":\"{}\",\"view\":\"{}\",\"outcome\":\"{}\",\"detail\":\"{}\",\"read_back_ok\":{}}}",
            json_escape(&item.target),
            json_escape(&item.view),
            json_escape(&item.outcome),
            json_escape(&item.detail),
            read_back
        ));
    }
    json.push_str("],\"errors\":[");
    for (i, err) in report.errors.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push('"');
        json.push_str(&json_escape(err));
        json.push('"');
    }
    json.push_str("]}");

    let mut file = fs::File::create(&path).map_err(|e| format!("Report create failed: {e}"))?;
    file.write_all(json.as_bytes())
        .map_err(|e| format!("Report write failed: {e}"))?;

    Ok(path)
}

fn get_windows_dir() -> PathBuf {
    // 環境変数 (SystemRoot/WINDIR) は起動元プロセスによって汚染され得るため、
    // まず Windows API から確定値の取得を試みる。
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::GetWindowsDirectoryW;

        let mut buf: Vec<u16> = vec![0; 260];
        loop {
            let len = unsafe { GetWindowsDirectoryW(Some(buf.as_mut_slice())) };
            if len == 0 {
                break;
            }
            let len = len as usize;
            if len < buf.len() {
                let s = String::from_utf16_lossy(&buf[..len]);
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return PathBuf::from(trimmed);
                }
                break;
            }
            buf.resize(len + 1, 0);
        }
    }

    std::env::var("WINDIR")
        .or_else(|_| std::env::var("SystemRoot"))
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ============================================================================
// IFEO復元（UninstallState）
// ============================================================================
// IFEO復元ロジックは kh-adapter-uninstall-state にある
fn expected_bootstrap_path() -> String {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for dir in expected_install_bin_dirs() {
        candidates.push(dir.join("kh-bootstrap.exe"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("kh-bootstrap.exe"));
        }
    }

    for candidate in &candidates {
        let raw = candidate.to_string_lossy().to_string();
        if let Some(normalized) = normalize_local_absolute_path(&raw) {
            if candidate.is_file() {
                return normalized;
            }
        }
    }

    for candidate in &candidates {
        let raw = candidate.to_string_lossy().to_string();
        if let Some(normalized) = normalize_local_absolute_path(&raw) {
            return normalized;
        }
    }

    PathBuf::from("C:\\Program Files")
        .join("KaptainhooK")
        .join("bin")
        .join("kh-bootstrap.exe")
        .to_string_lossy()
        .to_string()
}
fn prompt_restore_foreign(target: &str, view: &str, existing: &str) -> bool {
    let msg = if is_japanese() {
        format!(
            "他製品のデバッガが検出されました: {} ({})\n\n既存の値:\n{}\n\n元のエントリを復元しますか？",
            target, view, existing
        )
    } else {
        format!(
            "Foreign debugger detected for {} ({})\n\nExisting:\n{}\n\n\
            Restore original entry anyway?",
            target, view, existing
        )
    };
    let result = msgbox(
        uninstall_title(),
        &msg,
        MB_YESNO | MB_ICONWARNING,
    );
    result == IDYES
}
fn wide_cstr_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
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

fn known_folder_path(id: &windows::core::GUID) -> Option<PathBuf> {
    unsafe {
        let raw = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let s = pwstr_to_string(raw);
        CoTaskMemFree(Some(raw.0 as _));
        if s.is_empty() {
            None
        } else {
            Some(PathBuf::from(s))
        }
    }
}

fn normalize_local_absolute_path(path: &str) -> Option<String> {
    normalize_local_drive_absolute_path(path)
}


#[cfg(windows)]
fn is_dir_reparse_point(path: &std::path::Path) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_dir() && (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0,
        Err(_) => false,
    }
}

#[cfg(not(windows))]
fn is_dir_reparse_point(_path: &std::path::Path) -> bool {
    false
}

/// ディレクトリ内容削除、ログファイル保持オプション付き
fn delete_directory_contents(dir: &PathBuf, preserve_logs: bool) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }

    let entries = fs::read_dir(dir).map_err(|e| e.to_string())?;

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // 要求時はログファイル保持
        if preserve_logs && (file_name.ends_with(".log") || file_name.ends_with(".jsonl")) {
            log(&format!("Preserving log: {}", file_name));
            continue;
        }

        if path.is_dir() {
            if is_dir_reparse_point(&path) {
                log(&format!("Skipping reparse point directory: {:?}", path));
                continue;
            }
            let _ = fs::remove_dir_all(&path);
            log(&format!("Deleted directory: {:?}", path));
        } else {
            let _ = fs::remove_file(&path);
            log(&format!("Deleted file: {:?}", path));
        }
    }

    // ディレクトリ自体の削除試行（ログ残存時は失敗してもOK）
    let _ = fs::remove_dir(dir);

    Ok(())
}

/// MoveFileExでディレクトリ削除をスケジュール（cmdスパムなし）
fn schedule_directory_deletion(dir: &PathBuf) {
    if !dir.exists() {
        return;
    }
    if is_dir_reparse_point(dir) {
        log(&format!("Skipping reparse point directory: {:?}", dir));
        return;
    }


    // 最初にディレクトリ内全ファイルをMoveFileExで削除試行
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                // 直接削除を最初に試行
                if fs::remove_file(&path).is_err() {
                    schedule_file_deletion_on_reboot(&path);
                } else {
                    log(&format!("Deleted file: {:?}", path));
                }
            } else if path.is_dir() {
                if is_dir_reparse_point(&path) {
                    log(&format!("Skipping reparse point directory: {:?}", path));
                    continue;
                }
                // サブディレクトリ削除を再帰的に予約
                schedule_directory_deletion(&path);
            }
        }
    }

    // 直接ディレクトリ削除を最初に試行
    if fs::remove_dir(dir).is_ok() {
        log(&format!("Deleted directory: {:?}", dir));
    } else {
        // 再起動時にディレクトリ自体の削除をスケジュール
        schedule_file_deletion_on_reboot(dir);
    }
}

/// 次回再起動時の単一ファイル/ディレクトリ削除スケジュール
fn schedule_file_deletion_on_reboot(path: &PathBuf) {
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};

    let path_wide: Vec<u16> = path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let result = MoveFileExW(
            windows::core::PCWSTR(path_wide.as_ptr()),
            None,  // NULL = 再起動時に削除
            MOVEFILE_DELAY_UNTIL_REBOOT,
        );

        if result.is_ok() {
            log(&format!("Scheduled for reboot deletion: {:?}", path));
        } else {
            log(&format!("MoveFileEx failed for: {:?}", path));
        }
    }
}

fn wstr(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn msgbox(title: &str, text: &str, flags: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
    let t = wstr(title);
    let m = wstr(text);
    unsafe { MessageBoxW(None, PCWSTR(m.as_ptr()), PCWSTR(t.as_ptr()), flags) }
}
