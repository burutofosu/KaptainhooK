#![windows_subsystem = "windows"]
//! kh-setup: 初回セットアップ／アンインストール用のウィザード。
//! MessageBox（簡易ウィザード）とCLIでターゲット選択・IFEO 登録・復元専用タスク登録・設定保存・
//! アプリ登録（プログラムの追加と削除）などをまとめて行う。

use clap::Parser;
use kh_log_utils::lifecycle_line;
use std::error::Error;
use kh_composition::cli::CliRuntime;
use kh_composition::paths;
use kh_composition::guard::is_admin;
use kh_composition::system::{self, ProgramMetadata};
use kh_composition::app::admin::{AdminDeps, AdminService, ConflictAction as AdminConflictAction};
use kh_composition::ui_common::i18n;
use kh_composition::domain::model::{
    InstallConfig, Language, PathHint, PathHintKind, RegistryView, RevocationStatus, SignatureKind,
    SignatureNoticeKind, SignatureStatus, SignatureTrust,
};
use kh_composition::domain::port::driven::TaskScheduler;
use kh_composition::domain::port::driving::ConflictResolution;
use kh_composition::task::DEFAULT_RESTORE_TASK_NAME;
use std::path::PathBuf;
use std::io::Write;
use std::sync::Mutex;

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

fn setup_language() -> Language {
    CliRuntime::new().load_config_or_default().language
}

fn is_japanese() -> bool {
    matches!(i18n::current_language(), Language::Japanese)
}

fn setup_error_title() -> &'static str {
    if is_japanese() {
        "KaptainhooK セットアップ - エラー"
    } else {
        "KaptainhooK Setup - Error"
    }
}

fn setup_confirm_title() -> &'static str {
    if is_japanese() {
        "KaptainhooK セットアップ - 確認"
    } else {
        "KaptainhooK Setup - Confirm"
    }
}

fn setup_conflict_title() -> &'static str {
    if is_japanese() {
        "KaptainhooK セットアップ - 競合"
    } else {
        "KaptainhooK Setup - Conflict"
    }
}

fn setup_quarantine_title() -> &'static str {
    if is_japanese() {
        "KaptainhooK セットアップ - 隔離?"
    } else {
        "KaptainhooK Setup - Quarantine?"
    }
}

macro_rules! bail {
    ($($t:tt)*) => {
        return Err(err(format!($($t)*)));
    };
}

/// セットアップ用グローバルデバッグログ
static SETUP_LOG: Mutex<Option<std::fs::File>> = Mutex::new(None);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConflictAction {
    Respect,
    TakeOver,
    Quarantine,
}

/// セットアップログ初期化（Documentsに統合ログ）
fn init_setup_log() -> Result<()> {
    let log_path = {
        #[cfg(windows)]
        {
            use windows::Win32::UI::Shell::FOLDERID_Documents;
            known_folder_path(&FOLDERID_Documents)
                .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Users\Public\Documents"))
                .join("KaptainhooK")
                .join("kh-lifecycle.log")
        }
        #[cfg(not(windows))]
        {
            std::path::PathBuf::from("./kh-lifecycle.log")
        }
    };

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| err(format!("Failed to create log dir {:?}: {e}", parent)))?;
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| err(format!("Failed to open log {:?}: {e}", log_path)))?;

    if let Ok(mut guard) = SETUP_LOG.lock() {
        *guard = Some(file);
    }
    Ok(())
}

/// セットアップログ出力（コンポーネント識別子付き）
fn log_setup(msg: &str) {
    let line = lifecycle_line("SETUP", msg);

    if let Ok(mut guard) = SETUP_LOG.lock() {
        if let Some(ref mut file) = *guard {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
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
fn is_under_programdata(path: &std::path::Path) -> bool {
    use windows::Win32::UI::Shell::FOLDERID_ProgramData;
    known_folder_path(&FOLDERID_ProgramData)
        .is_some_and(|pd| path.starts_with(&pd))
}

#[cfg(not(windows))]
fn is_under_programdata(_path: &std::path::Path) -> bool {
    false
}

/// ポータブル配置を許可せず、通常インストール向けのbinディレクトリのみを返す。
///
/// - Windows: `%ProgramFiles%\\KaptainhooK\\bin` 固定
#[cfg(windows)]
fn secure_install_bin_dir() -> Result<PathBuf> {
    use windows::Win32::UI::Shell::FOLDERID_ProgramFiles;

    let program_files = known_folder_path(&FOLDERID_ProgramFiles)
        .ok_or_else(|| err("ProgramFiles known folder is not available"))?;
    Ok(program_files.join("KaptainhooK").join("bin"))
}

#[cfg(not(windows))]
fn secure_install_bin_dir() -> Result<PathBuf> {
    Ok(paths::preferred_bin_dir())
}

/// Windowsレジストリ用アプリケーションメタデータ
const APP_NAME: &str = "KaptainhooK";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_PUBLISHER: &str = "KaptainhooK Project";
const APP_URL: &str = "https://github.com/burutofosu/KaptainhooK";
const PROGRAM_META: ProgramMetadata<'static> = ProgramMetadata {
    name: APP_NAME,
    version: APP_VERSION,
    publisher: APP_PUBLISHER,
    url: APP_URL,
};
#[derive(Parser, Debug)]
#[command(name = "kh-setup", about = "KaptainhooK initial setup wizard")]
struct Cli {
    /// MessageBoxではなくCLIモードを使用
    #[arg(long)]
    cli: bool,
    /// デフォルト設定を使用（非対話、CLIモードのみ）
    #[arg(long)]
    defaults: bool,
    /// 変更せず実行計画のみ表示（CLIモードのみ）
    #[arg(long)]
    dry_run: bool,
    /// IFEO競合時の処理（abort|skip|overwrite）
    #[arg(long, default_value = "abort", value_parser = ["abort", "skip", "overwrite"])]
    conflict: String,
    /// KaptainhooKを完全アンインストール
    #[arg(long)]
    uninstall: bool,
    /// サイレントアンインストール（確認なし、Windowsアンインストーラ用）
    #[arg(long)]
    silent: bool,
}

fn main() {
    i18n::set_language(setup_language());
    if let Err(err) = init_setup_log() {
        let msg = if is_japanese() {
            format!("セットアップログの初期化に失敗しました: {err:#}")
        } else {
            format!("Setup log initialization failed: {err:#}")
        };
        show_error(&msg);
    }
    log_setup("========== kh-setup started ==========");
    log_setup(&format!("Args: {:?}", std::env::args().collect::<Vec<_>>()));
    log_setup(&format!("PID: {}", std::process::id()));

    let cli = Cli::parse();
    log_setup(&format!("CLI parsed: uninstall={}, cli={}, defaults={}", cli.uninstall, cli.cli, cli.defaults));

    // アンインストールモード
    if cli.uninstall {
        log_setup("Running uninstall mode");
        if let Err(err) = run_uninstall(cli.silent) {
            log_setup(&format!("Uninstall FAILED: {err:#}"));
            let msg = if is_japanese() {
                format!("アンインストールに失敗しました: {err:#}")
            } else {
                format!("Uninstall failed: {err:#}")
            };
            show_error(&msg);
            std::process::exit(1);
        }
        log_setup("Uninstall completed");
        return;
    }

    // デフォルトはMessageBoxウィザード、--cliフラグでCLIモード
    if cli.cli || cli.defaults || cli.dry_run {
        log_setup("Running CLI mode");
        if let Err(err) = run_cli(cli) {
            log_setup(&format!("CLI setup FAILED: {err:#}"));
            let msg = if is_japanese() {
                format!("セットアップに失敗しました: {err:#}")
            } else {
                format!("Setup failed: {err:#}")
            };
            show_error(&msg);
            std::process::exit(1);
        }
    } else {
        log_setup("Running MessageBox wizard mode");
        if let Err(err) = run_msgbox_wizard() {
            log_setup(&format!("MessageBox wizard FAILED: {err:#}"));
            let msg = if is_japanese() {
                format!("セットアップに失敗しました: {err:#}")
            } else {
                format!("Setup failed: {err:#}")
            };
            show_error(&msg);
            std::process::exit(1);
        }
    }
    log_setup("Setup completed successfully");
}

/// MessageBoxベースの簡易ウィザード
#[cfg(windows)]
fn run_msgbox_wizard() -> Result<()> {
    log_setup("run_msgbox_wizard() started");

    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::core::PCWSTR;

    let lang_choice = msgbox(
        "KaptainhooK Setup / セットアップ",
        "Select language / 言語を選択してください\n\nYes = 日本語\nNo = English\nCancel = Exit",
        MB_YESNOCANCEL | MB_ICONQUESTION,
    );
    match lang_choice {
        IDYES => {
            i18n::set_language(Language::Japanese);
            log_setup("Language selected: Japanese");
        }
        IDNO => {
            i18n::set_language(Language::English);
            log_setup("Language selected: English");
        }
        _ => {
            log_setup("Language selection cancelled");
            return Ok(());
        }
    }

    let notice = if is_japanese() {
        "このツールはIFEO登録を行うセキュリティツールです。\n\
kh-uninstall.exeによるインストール前への完全な復元を目指しており、手元実機でも確認済みですが、\n\
OS更新や端末相性など、なんらかの理由でアンインストールが機能しなくなった場合はレジストリエディタから手動除去していただくことになります。\n\
詳しくはREADMEを確認し、納得の上でインストールをお願いします。"
    } else {
        "This tool registers IFEO (Image File Execution Options) and acts as a security tool.\n\
It aims to fully restore your system using kh-uninstall.exe, and this has been verified on real machines.\n\
However, if uninstallation stops working due to OS updates or device compatibility, you will need to remove the IFEO entries manually using Registry Editor.\n\
Please read the README and proceed only if you understand and agree."
    };
    msgbox(
        "KaptainhooK Setup / セットアップ",
        notice,
        MB_OK | MB_ICONINFORMATION,
    );

    let t = i18n::t();
    let title_setup = t.setup_title();
    let title_error = setup_error_title();
    let title_confirm = setup_confirm_title();
    let title_conflict = setup_conflict_title();
    let title_quarantine = setup_quarantine_title();
    let jp = is_japanese();

    fn wstr(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    fn msgbox(title: &str, text: &str, flags: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
        let t = wstr(title);
        let m = wstr(text);
        unsafe { MessageBoxW(None, PCWSTR(m.as_ptr()), PCWSTR(t.as_ptr()), flags) }
    }

    // 管理者権限チェック
    log_setup("Checking admin privileges...");
    let admin = is_admin();
    log_setup(&format!("is_admin() = {}", admin));

    if !admin {
        log_setup("Not admin - showing error and returning");
        let msg = if jp {
            "管理者権限が必要です。\n\nkh-setup.exe を右クリックし、「管理者として実行」を選択してください。"
        } else {
            "Administrator privileges required.\n\nPlease right-click kh-setup.exe and select 'Run as administrator'."
        };
        msgbox(
            title_setup,
            msg,
            MB_OK | MB_ICONERROR,
        );
        return Ok(());
    }

    // インストール確認
    log_setup("Showing confirmation dialog...");
    let confirm_msg = if jp {
        "既定設定で KaptainhooK をインストールしますか？\n\n\
        この操作で:\n\
        • 一般的な LOLBins (powershell, cmd, mshta など) を保護します\n\
        • 特権昇格用のスケジュールタスクを登録します\n\
        • Windows 起動時に常駐登録します\n\n\
        はい: インストール / いいえ: キャンセル"
    } else {
        "Install KaptainhooK with default settings?\n\n\
        This will:\n\
        • Protect common LOLBins (powershell, cmd, mshta, etc.)\n\
        • Register scheduled task for privilege elevation\n\
        • Add to Windows startup\n\n\
        Click Yes to install, No to cancel."
    };
    let result = msgbox(
        title_setup,
        confirm_msg,
        MB_YESNO | MB_ICONQUESTION,
    );

    if result != IDYES {
        log_setup("User cancelled installation");
        return Ok(());
    }
    log_setup("User confirmed installation");

    let mut config = InstallConfig::default();
    config.language = i18n::current_language();
    log_setup(&format!("Config targets count: {}", config.targets.len()));

    let data_dir = paths::default_data_dir();
    let bin_dir = secure_install_bin_dir()?;
    log_setup(&format!("data_dir: {:?}", data_dir));
    log_setup(&format!("bin_dir: {:?}", bin_dir));

    // ディレクトリ作成
    log_setup("Creating data_dir...");
    match std::fs::create_dir_all(&data_dir) {
        Ok(_) => log_setup("data_dir created OK"),
        Err(e) => {
            log_setup(&format!("FAILED to create data_dir: {}", e));
            return Err(e.into());
        }
    }
    let config_dir = paths::default_config_dir();
    let log_dir = paths::default_log_dir();
    let backup_dir = paths::default_backup_dir();
    for (label, dir) in [
        ("config_dir", &config_dir),
        ("log_dir", &log_dir),
        ("backup_dir", &backup_dir),
    ] {
        log_setup(&format!("Creating {}...", label));
        match std::fs::create_dir_all(dir) {
            Ok(_) => log_setup(&format!("{} created OK", label)),
            Err(e) => {
                log_setup(&format!("FAILED to create {}: {}", label, e));
                return Err(e.into());
            }
        }
    }

    log_setup("Creating bin_dir...");
    match std::fs::create_dir_all(&bin_dir) {
        Ok(_) => log_setup("bin_dir created OK"),
        Err(e) => {
            log_setup(&format!("FAILED to create bin_dir: {}", e));
            return Err(e.into());
        }
    }

    // バイナリ配置
    log_setup("Deploying binaries...");
    match deploy_binaries(&bin_dir) {
        Ok(_) => log_setup("Binaries deployed OK"),
        Err(e) => log_setup(&format!("Binary deployment warning: {}", e)),
    }

    // ProgramData配下のbin_dirは権限昇格の典型経路なので、ACLで固定する。
    if is_under_programdata(&bin_dir) {
        log_setup("Applying bin_dir ACL (ProgramData)...");
        if let Err(e) = system::apply_locked_bin_dir_acl(&bin_dir) {
            log_setup(&format!("FAILED to apply bin_dir ACL: {}", e));
            msgbox(
                title_error,
                &if jp {
                    format!(
                        "安全な ACL を {:?} に適用できませんでした。\n\
                        このままインストールすると安全ではありません（権限昇格の可能性）。\n\n\
                        エラー: {}",
                        bin_dir, e
                    )
                } else {
                    format!(
                        "Failed to apply secure ACL to {:?}.\n\
                        This installation would be unsafe (possible privilege escalation).\n\n\
                        Error: {}",
                        bin_dir, e
                    )
                },
                MB_OK | MB_ICONERROR,
            );
            return Ok(());
        }
        log_setup("bin_dir ACL applied OK");
    }
    if is_under_programdata(&data_dir) {
        log_setup("Applying data_dir ACL (ProgramData)...");
        if let Err(e) = system::apply_locked_data_dir_acl(&data_dir) {
            log_setup(&format!("FAILED to apply data_dir ACL: {}", e));
            msgbox(
                title_error,
                &if jp {
                    format!(
                        "安全な ACL を {:?} に適用できませんでした。\n\
                        エラー: {}",
                        data_dir, e
                    )
                } else {
                    format!(
                        "Failed to apply secure ACL to {:?}.\n\
                        Error: {}",
                        data_dir, e
                    )
                },
                MB_OK | MB_ICONERROR,
            );
            return Ok(());
        }
        log_setup("data_dir ACL applied OK");
    }

    // 必須バイナリの有無を確認
    let required = [
        "kh-bootstrap.exe",
        "kh-guard.exe",
        "kh-service.exe",
        "kh-service-restart.exe",
        "kh-restore.exe",
        "kh-uninstall.exe",
    ];
    let mut missing: Vec<&str> = Vec::new();
    for bin in required {
        if !bin_dir.join(bin).exists() {
            missing.push(bin);
        }
    }
    if !missing.is_empty() {
        let msg = if jp {
            format!(
                "必要なバイナリが {:?} に見つかりません:\n{}",
                bin_dir,
                missing.join(", ")
            )
        } else {
            format!(
                "Required binaries are missing in {:?}:\n{}",
                bin_dir,
                missing.join(", ")
            )
        };
        log_setup(&format!("ERROR: {}", msg));
        msgbox(title_error, &msg, MB_OK | MB_ICONERROR);
        return Ok(());
    }

    // ランタイムを早めに作成（bin_dir 確定済み）
    log_setup("Creating CliRuntime...");
    let runtime = CliRuntime::new();

    let mut install_config = config.clone();
    let mut conflict_actions: std::collections::BTreeMap<String, ConflictAction> =
        std::collections::BTreeMap::new();
    loop {
        conflict_actions.clear();
        let mut had_conflicts = false;
        if let Ok(conflicts) = runtime.detect_conflicts(&install_config) {
            let enabled: std::collections::HashSet<String> = install_config
                .targets
                .iter()
                .filter(|t| t.enabled())
                .map(|t| t.exe_name().to_ascii_lowercase())
                .collect();
            let mut grouped: std::collections::BTreeMap<String, Vec<String>> =
                std::collections::BTreeMap::new();
            let mut seen_views: std::collections::HashSet<(String, RegistryView)> =
                std::collections::HashSet::new();
            for conflict in conflicts {
                if !enabled.contains(&conflict.target.to_ascii_lowercase()) {
                    continue;
                }
                let lines = grouped.entry(conflict.target.clone()).or_default();
                lines.push(format!(
                    "{}: {}",
                    view_label(conflict.view),
                    conflict.existing_debugger
                ));
                lines.push(format!(
                    "{}: {}",
                    t.setup_conflict_signature(),
                    format_signature_status(&conflict.signature)
                ));
                if let Some(note) = &conflict.signature_notice {
                    lines.push(format!(
                        "{}: {}",
                        t.common_note(),
                    format_signature_notice(note)
                    ));
                }
                if !conflict.path_hints.is_empty() {
                    lines.push(format!(
                        "{}: {}",
                        t.setup_conflict_path_hints(),
                        format_path_hints(&conflict.path_hints).join(", ")
                    ));
                }
                seen_views.insert((conflict.target.to_ascii_lowercase(), conflict.view));
            }

            // detect_conflictsで拾えない非文字列デバッガも追加する
            let admin = AdminService::new(AdminDeps { port: &runtime });
            let enabled_targets: Vec<String> = enabled.iter().cloned().collect();
            if let Ok(non_string) = admin.scan_non_string_conflicts(&enabled_targets) {
                for conflict in non_string {
                    let key = (conflict.target.to_ascii_lowercase(), conflict.view);
                    if seen_views.contains(&key) {
                        continue;
                    }
                    let lines = grouped.entry(conflict.target).or_default();
                    lines.push(format!(
                        "{}: {}",
                        view_label(conflict.view),
                        t.settings_conflict_non_string_debugger()
                    ));
                    lines.push(format!(
                        "{}: {}",
                        t.setup_conflict_signature(),
                        t.settings_conflict_signature_unsupported()
                    ));
                }
            }

            for (target, lines) in grouped {
                had_conflicts = true;
                let detail = lines.join("\n");
            let choice = msgbox(
                title_conflict,
                &if jp {
                    format!(
                        "{} に既存のデバッガーが検出されました。\n\n{}\n\n\
                        対応を選択してください:\n\
                        はい = 引き継ぎ（上書き）\n\
                        いいえ = 尊重（スキップ）\n\
                        キャンセル = インストール中止",
                        target, detail
                    )
                } else {
                    format!(
                        "Existing debugger detected for {}.\n\n{}\n\n\
                        Choose action:\n\
                        Yes = Take over (overwrite)\n\
                        No = Respect (skip)\n\
                        Cancel = Cancel installation",
                        target, detail
                    )
                },
                MB_YESNOCANCEL | MB_ICONWARNING,
            );
                let action = match choice {
                    IDYES => {
                    let q = msgbox(
                        title_quarantine,
                        if jp {
                            "このデバッガーを不審として隔離しますか？\n\n\
                            はい = 隔離\nいいえ = 引き継ぎ"
                        } else {
                            "Treat this debugger as suspicious and quarantine it?\n\n\
                            Yes = Quarantine\nNo = Take over"
                        },
                        MB_YESNO | MB_ICONWARNING,
                    );
                        if q == IDYES {
                            ConflictAction::Quarantine
                        } else {
                            ConflictAction::TakeOver
                        }
                    }
                    IDNO => ConflictAction::Respect,
                    _ => {
                    log_setup("User aborted due to conflict selection");
                    msgbox(
                        title_setup,
                        if jp { "インストールを中止しました。" } else { "Installation cancelled." },
                        MB_OK | MB_ICONWARNING,
                    );
                    return Ok(());
                }
                };
                conflict_actions.insert(target.to_ascii_lowercase(), action);
            }
        }

        if had_conflicts {
        let confirm = msgbox(
            title_confirm,
            if jp {
                "競合の対応内容を確定してインストールを続行しますか？\n\n\
                はい = インストール\nいいえ = 競合の選択をやり直す\nキャンセル = インストール中止"
            } else {
                "Confirm conflict handling choices and continue installation?\n\n\
                Yes = Install\nNo = Redo conflict choices\nCancel = Cancel installation"
            },
            MB_YESNOCANCEL | MB_ICONQUESTION,
        );
            match confirm {
                IDYES => break,
                IDNO => {
                    log_setup("User requested to redo conflict choices");
                    continue;
                }
                _ => {
                log_setup("User cancelled before installation");
                msgbox(
                    title_setup,
                    if jp { "インストールを中止しました。" } else { "Installation cancelled." },
                    MB_OK | MB_ICONWARNING,
                );
                return Ok(());
            }
            }
        } else {
        let confirm = msgbox(
            title_confirm,
            if jp {
                "競合は検出されませんでした。\n\nインストールを続行しますか？\n\nはい = インストール\nいいえ = キャンセル"
            } else {
                "No conflicts detected.\n\nProceed with installation?\n\nYes = Install\nNo = Cancel"
            },
            MB_YESNO | MB_ICONQUESTION,
        );
            if confirm == IDYES {
                break;
            }
        log_setup("User cancelled before installation (no conflicts)");
        msgbox(
            title_setup,
            if jp { "インストールを中止しました。" } else { "Installation cancelled." },
            MB_OK | MB_ICONWARNING,
        );
        return Ok(());
        }
    }

    if !conflict_actions.is_empty() {
        for target in install_config.targets.iter_mut() {
            let key = target.exe_name().to_ascii_lowercase();
            if let Some(action) = conflict_actions.get(&key) {
                match action {
                    ConflictAction::Respect => target.set_enabled(false),
                    _ => {}
                }
            }
        }
    }

    if install_config.targets.iter().all(|t| !t.enabled()) {
        msgbox(
            title_setup,
            if jp {
                "競合によりすべての対象がスキップされました。\n\nインストールを中止しました。"
            } else {
                "All targets were skipped due to conflicts.\n\nInstallation cancelled."
            },
            MB_OK | MB_ICONWARNING,
        );
        return Ok(());
    }

    // HKLM TargetsとTrustedHashesを登録（service/restoreが参照）
    log_setup("Writing Targets registry...");
    if let Err(e) = write_targets_registry(&install_config) {
        log_setup(&format!("FAILED to write Targets registry: {}", e));
        msgbox(
            title_error,
            &if jp {
                format!(
                    "保護対象のレジストリ書き込みに失敗しました。\n\
                    管理者としてセットアップを実行してください。\n\n\
                    エラー: {}",
                    e
                )
            } else {
                format!(
                    "Failed to write protected targets to registry.\n\
                    Please run setup as Administrator.\n\n\
                    Error: {}",
                    e
                )
            },
            MB_OK | MB_ICONERROR,
        );
        return Ok(());
    }
    log_setup("Targets registry written OK");

    log_setup("Writing TrustedHashes registry...");
    if let Err(e) = system::write_trusted_hashes(&bin_dir) {
        log_setup(&format!("FAILED to write TrustedHashes registry: {}", e));
        msgbox(
            title_error,
            &if jp {
                format!(
                    "TrustedHashes のレジストリ書き込みに失敗しました。\n\
                    管理者としてセットアップを実行してください。\n\n\
                    エラー: {}",
                    e
                )
            } else {
                format!(
                    "Failed to write trusted hashes to registry.\n\
                    Please run setup as Administrator.\n\n\
                    Error: {}",
                    e
                )
            },
            MB_OK | MB_ICONERROR,
        );
        return Ok(());
    }
    log_setup("TrustedHashes registry written OK");

    // タスク登録はIFEOより先
    let restore_exe = bin_dir.join("kh-restore.exe");
    log_setup(&format!("restore_exe path: {:?}", restore_exe));
    log_setup(&format!("restore_exe exists: {}", restore_exe.exists()));

    log_setup("Calling register_restore_task - BEFORE IFEO...");
    let restore_result = register_restore_task(&restore_exe);
    log_setup(&format!(
        "register_restore_task result: {:?}",
        restore_result.as_ref().map(|_| "OK")
    ));

    if let Err(ref e) = restore_result {
        log_setup(&format!("Restore task registration failed: {}", e));
        msgbox(
            title_error,
            &if jp {
                format!(
                    "復元タスクの登録に失敗しました:\n{}\n\n\
                    管理者としてセットアップを実行してください。",
                    e
                )
            } else {
                format!(
                    "Restore task registration failed:\n{}\n\n\
                    Please run setup as Administrator.",
                    e
                )
            },
            MB_OK | MB_ICONERROR,
        );
        // 復元タスク失敗時は中断
        return Ok(());
    } else {
        log_setup("Restore task registration succeeded!");
    }

    log_setup("Backing up IFEO state to registry...");
    let action_map = if conflict_actions.is_empty() {
        None
    } else {
        Some(&conflict_actions)
    };
    if let Err(e) = backup_uninstall_state(&runtime, &install_config, action_map) {
        log_setup(&format!("FAILED to backup IFEO state: {}", e));
        msgbox(
            title_error,
            &if jp {
                format!(
                    "IFEO 状態のバックアップに失敗しました。\n\
                    管理者としてセットアップを実行してください。\n\n\
                    エラー: {}",
                    e
                )
            } else {
                format!(
                    "Failed to back up IFEO state.\n\
                    Please run setup as Administrator.\n\n\
                    Error: {}",
                    e
                )
            },
            MB_OK | MB_ICONERROR,
        );
        return Ok(());
    }
    log_setup("IFEO backup stored OK");

    log_setup("Registering service...");
    if let Err(e) = system::ensure_service_installed(&bin_dir) {
        log_setup(&format!("FAILED to register/start service: {}", e));
        msgbox(
            title_error,
            &if jp {
                format!(
                    "KaptainhooK サービスの登録/起動に失敗しました。\n\
                    管理者としてセットアップを実行してください。\n\n\
                    エラー: {}",
                    e
                )
            } else {
                format!(
                    "Failed to register/start KaptainhooK service.\n\
                    Please run setup as Administrator.\n\n\
                    Error: {}",
                    e
                )
            },
            MB_OK | MB_ICONERROR,
        );
        return Ok(());
    }
    log_setup("Service registered/started OK");

    // IFEOインストール
    log_setup("Installing IFEO entries...");
    let resolution = if conflict_actions.values().any(|action| {
        matches!(action, ConflictAction::TakeOver | ConflictAction::Quarantine)
    }) {
        ConflictResolution::Overwrite
    } else {
        ConflictResolution::Skip
    };
    match runtime.install_with_backup(&install_config, resolution) {
        Ok(report) => {
            log_setup(&format!("IFEO registered: {:?}", report.registered));
            log_setup(&format!("IFEO unregistered: {:?}", report.unregistered));
        }
        Err(e) => {
            log_setup(&format!("IFEO installation FAILED: {}", e));
            return Err(e.into());
        }
    }

    // 設定保存
    log_setup("Saving config...");
    match runtime.save_config(&install_config) {
        Ok(_) => log_setup("Config saved OK"),
        Err(e) => log_setup(&format!("Config save warning: {}", e)),
    }

    // プログラムの追加と削除に登録
    log_setup("Registering in Add/Remove Programs...");
    match system::register_in_programs(&bin_dir, &PROGRAM_META) {
        Ok(_) => log_setup("Add/Remove Programs registration OK"),
        Err(e) => log_setup(&format!("Add/Remove Programs warning: {}", e)),
    }

    // スタートアップ登録とトレイ起動
    log_setup("Registering startup...");
    match system::register_startup(&bin_dir) {
        Ok(_) => log_setup("Startup registration OK"),
        Err(e) => log_setup(&format!("Startup registration warning: {}", e)),
    }

    let start_shortcut = msgbox(
        title_confirm,
        if jp {
            "スタートメニューに「サービス再起動」ショートカットを作成しますか？\n\nはい = 作成\nいいえ = 作成しない"
        } else {
            "Create a Start Menu shortcut for Service Restart?\n\nYes = Create\nNo = Skip"
        },
        MB_YESNO | MB_ICONQUESTION,
    );
    if start_shortcut == IDYES {
        log_setup("Creating service restart shortcut...");
        match system::create_service_restart_shortcut(&bin_dir) {
            Ok(_) => log_setup("Service restart shortcut created"),
            Err(e) => log_setup(&format!("Service restart shortcut warning: {}", e)),
        }
    } else {
        log_setup("Service restart shortcut creation skipped by user");
    }

    log_setup("Launching tray...");
    launch_tray(&bin_dir);

    // タスク作成確認
    log_setup("Verifying restore task exists...");
    let task_scheduler = kh_composition::task::TaskSchedulerAdapter::new(&restore_exe);
    let restore_exists = task_scheduler
        .task_exists(DEFAULT_RESTORE_TASK_NAME)
        .unwrap_or(false);
    log_setup(&format!(
        "Task '{}' exists: {}",
        DEFAULT_RESTORE_TASK_NAME, restore_exists
    ));

    if restore_exists {
        log_setup("Installation complete - showing success message");
        msgbox(
            title_setup,
            if jp {
                "インストールが完了しました！\n\n\
                KaptainhooK がシステムを保護しています。\n\
                トレイアイコンはシステムトレイに表示されます。\n\n\
                アンインストール: Windows 設定 > アプリ > KaptainhooK"
            } else {
                "Installation complete!\n\n\
                KaptainhooK is now protecting your system.\n\
                The tray icon is in your system tray.\n\n\
                To uninstall: Windows Settings > Apps > KaptainhooK"
            },
            MB_OK | MB_ICONINFORMATION,
        );
    } else {
        log_setup("Installation partially complete - restore task not found");
        msgbox(
            title_setup,
            if jp {
                "インストールは一部完了しました。\n\n\
                IFEO 保護は有効ですが、復元タスクを登録できませんでした。\n\
                保護が正常に動作しない可能性があります。\n\n\
                先ほど表示された手動コマンドを実行してください。"
            } else {
                "Installation partially complete.\n\n\
                IFEO protection is installed, but the restore task\n\
                could not be registered. Protection may not work.\n\n\
                Please run the manual command shown earlier."
            },
            MB_OK | MB_ICONWARNING,
        );
    }

    log_setup("run_msgbox_wizard() finished");
    Ok(())
}

#[cfg(not(windows))]
fn run_msgbox_wizard() -> Result<()> {
    bail!("MessageBox wizard is only available on Windows");
}

/// エラーメッセージ表示（WindowsはMessageBox、その他はstderr）
#[cfg(windows)]
fn show_error(msg: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    use windows::core::PCWSTR;

    let title: Vec<u16> = OsStr::new(setup_error_title())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let text: Vec<u16> = OsStr::new(msg)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(text.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

#[cfg(not(windows))]
fn show_error(msg: &str) {
    eprintln!("{}", msg);
}

// CLIモード

fn run_cli(cli: Cli) -> Result<()> {
    println!("===========================================");
    println!("  KaptainhooK Setup Wizard");
    println!("===========================================");
    println!();

    // 手順1: 管理者権限確認
    println!("[1/8] Checking administrator privileges...");
    if !is_admin() {
        bail!("This setup requires administrator privileges. Please run as Administrator.");
    }
    println!("      Administrator privileges confirmed.");
    println!();

    // 手順2: 対象選択
    println!("[2/8] Target configuration...");
    let config = if cli.defaults {
        println!("      Using default targets.");
        InstallConfig::default()
    } else {
        show_target_summary(&InstallConfig::default());
        InstallConfig::default()
    };
    println!();

    // 手順3: ディレクトリとバイナリ準備
    println!("[3/8] Preparing installation directories...");
    let data_dir = paths::default_data_dir();
    let config_dir = paths::default_config_dir();
    let log_dir = paths::default_log_dir();
    let backup_dir = paths::default_backup_dir();
    let bin_dir = secure_install_bin_dir()?;

    if cli.dry_run {
        println!("      [DRY-RUN] Would create: {:?}", data_dir);
        println!("      [DRY-RUN] Would create: {:?}", config_dir);
        println!("      [DRY-RUN] Would create: {:?}", log_dir);
        println!("      [DRY-RUN] Would create: {:?}", backup_dir);
        println!("      [DRY-RUN] Would create: {:?}", bin_dir);
    } else {
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| err(format!("Failed to create data directory {:?}: {e}", data_dir)))?;
        for dir in [&config_dir, &log_dir, &backup_dir] {
            std::fs::create_dir_all(dir)
                .map_err(|e| err(format!("Failed to create data directory {:?}: {e}", dir)))?;
        }
        std::fs::create_dir_all(&bin_dir)
            .map_err(|e| err(format!("Failed to create bin directory {:?}: {e}", bin_dir)))?;
        println!("      Created: {:?}", data_dir);
        println!("      Created: {:?}", config_dir);
        println!("      Created: {:?}", log_dir);
        println!("      Created: {:?}", backup_dir);
        println!("      Created: {:?}", bin_dir);

        // 実行ファイル位置からバイナリをコピー
        if let Err(e) = deploy_binaries(&bin_dir) {
            eprintln!("      Warning: Could not deploy binaries: {}", e);
            eprintln!("      You may need to copy them manually.");
        }

        // ProgramData配下のbin_dirはEoP/LPEの典型なので、ACLで固定する
        if is_under_programdata(&bin_dir) {
            system::apply_locked_bin_dir_acl(&bin_dir).map_err(|e| {
                err(format!(
                    "Failed to apply secure ACL to {:?} (install would be unsafe): {}",
                    bin_dir, e
                ))
            })?;
        }
        if is_under_programdata(&data_dir) {
            system::apply_locked_data_dir_acl(&data_dir).map_err(|e| {
                err(format!(
                    "Failed to apply secure ACL to {:?}: {}",
                    data_dir, e
                ))
            })?;
        }

        // 必須バイナリの有無を確認
        let required = [
            "kh-bootstrap.exe",
            "kh-guard.exe",
            "kh-service.exe",
            "kh-service-restart.exe",
            "kh-restore.exe",
            "kh-uninstall.exe",
        ];
        let mut missing: Vec<&str> = Vec::new();
        for bin in required {
            if !bin_dir.join(bin).exists() {
                missing.push(bin);
            }
        }
        if !missing.is_empty() {
            bail!(
                "Required binaries are missing in {:?}: {}",
                bin_dir,
                missing.join(", ")
            );
        }

    }

    // bin_dir が確定したので runtime を作る（デバッガパス等の誤検出を避ける）
    let runtime = CliRuntime::new();

    // 手順4: 競合確認
    println!("[4/8] Checking for IFEO conflicts...");
    let conflicts = runtime.detect_conflicts(&config)?;
    let resolution = parse_conflict_resolution(&cli.conflict);
    let mut conflict_actions: std::collections::BTreeMap<String, ConflictAction> =
        std::collections::BTreeMap::new();
    if !conflicts.is_empty() {
        println!("      Found {} conflicts:", conflicts.len());
        for c in &conflicts {
            println!("        - {} [{:?}]: {}", c.target, c.view, c.existing_debugger);
            println!("          Signature: {:?}", c.signature);
            if let Some(note) = &c.signature_notice {
                println!("          Note: {}", format_signature_notice(note));
            }
        }

        match resolution {
            ConflictResolution::Abort => {
                bail!("Conflicts detected. Use --conflict=skip or --conflict=overwrite to proceed.");
            }
            ConflictResolution::Skip => {
                println!("      Skipping conflicted targets.");
            }
            ConflictResolution::Overwrite => {
                println!("      Will overwrite existing entries (backed up).");
                for c in &conflicts {
                    conflict_actions
                        .entry(c.target.to_ascii_lowercase())
                        .or_insert(ConflictAction::TakeOver);
                }
            }
        }
    } else {
        println!("      No conflicts detected.");
    }
    println!();

    let mut install_config = config.clone();
    if matches!(resolution, ConflictResolution::Skip) && !conflicts.is_empty() {
        let conflicted: std::collections::HashSet<String> = conflicts
            .iter()
            .map(|c| c.target.to_ascii_lowercase())
            .collect();
        for target in install_config.targets.iter_mut() {
            if conflicted.contains(&target.exe_name().to_ascii_lowercase()) {
                target.set_enabled(false);
            }
        }
    }

    if install_config.targets.iter().all(|t| !t.enabled()) {
        bail!("All targets were skipped due to conflicts. Nothing to install.");
    }

    if cli.dry_run {
        println!("      [DRY-RUN] Would write HKLM Targets");
        println!("      [DRY-RUN] Would write HKLM TrustedHashes");
    } else {
        write_targets_registry(&install_config).map_err(|e| {
            err(format!(
                "Failed to write Targets registry: {e}. Aborting before IFEO install."
            ))
        })?;
        system::write_trusted_hashes(&bin_dir).map_err(|e| {
            err(format!(
                "Failed to write TrustedHashes registry: {e}. Aborting before IFEO install."
            ))
        })?;
    }
    println!();

    // 手順5: タスク登録（IFEOより先）
    println!("[5/8] Registering scheduled tasks...");
    let restore_exe = if cfg!(windows) {
        bin_dir.join("kh-restore.exe")
    } else {
        bin_dir.join("kh-restore")
    };
    if cli.dry_run {
        println!("      [DRY-RUN] Would register task: {}", DEFAULT_RESTORE_TASK_NAME);
        println!("      [DRY-RUN] Restore path: {:?}", restore_exe);
        println!(
            "      [DRY-RUN] Would register/start service: {}",
            system::SERVICE_NAME
        );
        println!("      [DRY-RUN] Would back up IFEO state to registry");
    } else {
        let restore_task_result = register_restore_task(&restore_exe);
        if let Err(e) = restore_task_result {
            return Err(err(format!(
                "Restore task registration failed: {e}. Aborting before IFEO install."
            )));
        }
        println!("      Scheduled task registered: {}", DEFAULT_RESTORE_TASK_NAME);

        system::ensure_service_installed(&bin_dir).map_err(|e| {
            err(format!(
                "Service registration failed: {e}. Aborting before IFEO install."
            ))
        })?;
        println!(
            "      Service registered/started: {}",
            system::SERVICE_NAME
        );

        let action_map = if conflict_actions.is_empty() {
            None
        } else {
            Some(&conflict_actions)
        };
        backup_uninstall_state(&runtime, &install_config, action_map)
            .map_err(|e| {
                err(format!(
                    "IFEO backup failed: {e}. Aborting before IFEO install."
                ))
            })?;
        println!("      IFEO backup stored.");
    }
    println!();

    // 手順6: IFEO登録
    println!("[6/8] Registering IFEO entries...");
    if cli.dry_run {
        let plan = runtime.app().install_plan(&config, true, &runtime.expected_debugger_path())?;
        for entry in &plan {
            println!("      [DRY-RUN] Would register: {} -> {}", entry.target, entry.debugger_path);
        }
    } else {
        let report = runtime.install_with_backup(&install_config, resolution)?;

        if !report.registered.is_empty() {
            println!("      Registered {} targets:", report.registered.len());
            for t in &report.registered {
                println!("        + {}", t);
            }
        }
        if !report.unregistered.is_empty() {
            println!("      Unregistered {} targets:", report.unregistered.len());
            for t in &report.unregistered {
                println!("        - {}", t);
            }
        }
    }
    println!();

    // 手順7: 設定保存
    if !cli.dry_run {
        runtime.save_config(&install_config)?;
        println!("Configuration saved to: {:?}", paths::default_config_path());
    }
    println!();

    // 手順8: プログラムの追加と削除に登録
    println!("[7/8] Registering in Add/Remove Programs...");
    if cli.dry_run {
        println!("      [DRY-RUN] Would register in Add/Remove Programs");
    } else {
        if let Err(e) = system::register_in_programs(&bin_dir, &PROGRAM_META) {
            eprintln!("      Warning: Could not register in Add/Remove Programs: {}", e);
        } else {
            println!("      Registered in Add/Remove Programs.");
        }
    }
    println!();

    // 手順9: スタートアップ登録とトレイ起動
    if !cli.dry_run {
        println!("[8/8] Registering startup and launching tray...");
        if let Err(e) = system::register_startup(&bin_dir) {
            eprintln!("      Warning: Could not register startup: {}", e);
        } else {
            println!("      Tray app will start automatically on login.");
        }
        if let Err(e) = system::create_service_restart_shortcut(&bin_dir) {
            eprintln!("      Warning: Could not create service shortcut: {}", e);
        } else {
            println!("      Service restart shortcut created.");
        }
        launch_tray(&bin_dir);
        println!("      Tray app launched.");
    }

    println!();
    println!("===========================================");
    if cli.dry_run {
        println!("  Setup DRY-RUN complete.");
        println!("  No changes were made.");
    } else {
        println!("  Setup complete!");
        println!();
        println!("  KaptainhooK is now protecting your system.");
        println!("  The tray icon is now in your system tray.");
        println!("  Right-click it to access Settings.");
        println!();
        println!("  To uninstall, use:");
        println!("    - Windows Settings > Apps > KaptainhooK");
        println!("    - Or run: kh-setup --uninstall");
    }
    println!("===========================================");

    Ok(())
}

fn show_target_summary(config: &InstallConfig) {
    let enabled: Vec<_> = config.targets.iter().filter(|t| t.enabled()).collect();
    let disabled: Vec<_> = config.targets.iter().filter(|t| !t.enabled()).collect();

    println!("      Enabled targets ({}):", enabled.len());
    for chunk in enabled.chunks(5) {
        let names: Vec<_> = chunk.iter().map(|t| t.exe_name()).collect();
        println!("        {}", names.join(", "));
    }

    if !disabled.is_empty() {
        println!("      Disabled targets ({}):", disabled.len());
        for t in &disabled {
            println!("        - {}", t.exe_name());
        }
    }
}

fn deploy_binaries(bin_dir: &PathBuf) -> Result<()> {
    let current_exe = std::env::current_exe()?;
    let source_dir = current_exe
        .parent()
        .ok_or_else(|| err("Could not determine source directory"))?;

    let binaries = [
        "kh-bootstrap.exe",
        "kh-guard.exe",
        "kh-service.exe",
        "kh-service-restart.exe",
        "kh-restore.exe",
        "kh-uninstall.exe",
        "kh-cli.exe",
        "kh-settings.exe",
        "kh-setup.exe",
        "kh-tray.exe",
    ];

    for bin in &binaries {
        let src = source_dir.join(bin);
        let dst = bin_dir.join(bin);

        if src.exists() && src != dst {
            std::fs::copy(&src, &dst)
                .map_err(|e| err(format!("Failed to copy {} to {:?}: {e}", bin, dst)))?;
            println!("      Deployed: {}", bin);
        }
    }

    // assets を配置（トレイアイコン/スキン）
    let assets_src = source_dir.join("assets");
    if assets_src.is_dir() {
        let assets_dst = bin_dir.join("assets");
        std::fs::create_dir_all(&assets_dst)
            .map_err(|e| err(format!("Failed to create assets dir {:?}: {e}", assets_dst)))?;
        let entries = std::fs::read_dir(&assets_src)
            .map_err(|e| err(format!("Failed to read assets dir {:?}: {e}", assets_src)))?;
        for entry in entries.flatten() {
            let src = entry.path();
            if !src.is_file() {
                continue;
            }
            let name = match src.file_name() {
                Some(n) => n,
                None => continue,
            };
            let dst = assets_dst.join(name);
            if src != dst {
                std::fs::copy(&src, &dst).map_err(|e| {
                    err(format!("Failed to copy asset {:?} to {:?}: {e}", src, dst))
                })?;
                println!("      Deployed asset: {}", dst.file_name().unwrap().to_string_lossy());
            }
        }
    }

    Ok(())
}

fn parse_conflict_resolution(flag: &str) -> ConflictResolution {
    match flag.to_ascii_lowercase().as_str() {
        "skip" => ConflictResolution::Skip,
        "overwrite" => ConflictResolution::Overwrite,
        _ => ConflictResolution::Abort,
    }
}

/// インストール後トレイアプリ起動
fn launch_tray(bin_dir: &std::path::Path) {
    let tray_exe = bin_dir.join("kh-tray.exe");
    if tray_exe.exists() {
        let _ = std::process::Command::new(&tray_exe).spawn();
    }
}

// アンインストールモード

fn run_uninstall(silent: bool) -> Result<()> {
    log_setup("Delegating uninstall to kh-uninstall.exe");

    let bin_dir = paths::default_bin_dir();
    let uninstall_exe = bin_dir.join("kh-uninstall.exe");
    if !uninstall_exe.exists() {
        bail!(
            "kh-uninstall.exe not found at {}",
            uninstall_exe.display()
        );
    }

    let mut cmd = std::process::Command::new(&uninstall_exe);
    if silent {
        cmd.arg("--quiet");
    }
    let status = cmd
        .status()
        .map_err(|e| err(format!("Failed to launch {}: {e}", uninstall_exe.display())))?;
    if !status.success() {
        bail!("kh-uninstall failed with status: {}", status);
    }

    Ok(())
}

fn format_signature_status(status: &SignatureStatus) -> String {
    let t = i18n::t();
    match status {
        SignatureStatus::Signed {
            kind,
            subject,
            issuer,
            trust,
            revocation,
        } => {
            let kind_label = match kind {
                SignatureKind::Authenticode => t.signature_kind_authenticode(),
                SignatureKind::Other { name } => name.as_str(),
            };
            let trust_label = match trust {
                SignatureTrust::Trusted => t.signature_trust_trusted().to_string(),
                SignatureTrust::Untrusted => t.signature_trust_untrusted().to_string(),
                SignatureTrust::Unknown => t.signature_trust_unknown().to_string(),
            };
            let rev_label = match revocation {
                RevocationStatus::Good => t.signature_revocation_good().to_string(),
                RevocationStatus::Revoked => t.signature_revocation_revoked().to_string(),
                RevocationStatus::NotChecked { reason } => t.signature_revocation_not_checked(reason),
                RevocationStatus::CheckFailed { reason } => t.signature_revocation_check_failed(reason),
            };
            let mut parts = vec![t.common_signature_signed(kind_label)];
            parts.push(t.common_signature_trust(&trust_label));
            parts.push(t.common_signature_revocation(&rev_label));
            if let Some(s) = subject {
                parts.push(t.common_signature_subject(s));
            }
            if let Some(i) = issuer {
                parts.push(t.common_signature_issuer(i));
            }
            parts.join(", ")
        }
        SignatureStatus::Unsigned => t.common_signature_unsigned().to_string(),
        SignatureStatus::Error { message } => t.common_signature_error(message),
        SignatureStatus::Unsupported { reason } => t.common_signature_unsupported(reason),
    }
}

fn format_signature_notice(kind: &SignatureNoticeKind) -> String {
    let t = i18n::t();
    match kind {
        SignatureNoticeKind::Unsigned => t.common_signature_notice_unsigned().to_string(),
        SignatureNoticeKind::Untrusted => t.common_signature_notice_untrusted().to_string(),
        SignatureNoticeKind::Revoked => t.common_signature_notice_revoked().to_string(),
        SignatureNoticeKind::RevocationNotChecked => {
            t.common_signature_notice_revocation_not_checked().to_string()
        }
        SignatureNoticeKind::RevocationCheckFailed => {
            t.common_signature_notice_revocation_check_failed().to_string()
        }
        SignatureNoticeKind::Error => t.common_signature_notice_error().to_string(),
        SignatureNoticeKind::Unsupported => t.common_signature_notice_unsupported().to_string(),
    }
}

fn view_label(view: RegistryView) -> &'static str {
    let t = i18n::t();
    match view {
        RegistryView::Bit64 => t.common_view_64(),
        RegistryView::Bit32 => t.common_view_32(),
    }
}

fn format_path_hints(hints: &[PathHint]) -> Vec<String> {
    let t = i18n::t();
    hints
        .iter()
        .map(|hint| {
            let label = match hint.kind {
                PathHintKind::PublicUserDir => t.common_path_hint_public_user_dir(),
                PathHintKind::TempDir => t.common_path_hint_temp_dir(),
                PathHintKind::UserTempDir => t.common_path_hint_user_temp_dir(),
                PathHintKind::DownloadsDir => t.common_path_hint_downloads_dir(),
                PathHintKind::DesktopDir => t.common_path_hint_desktop_dir(),
                PathHintKind::ProgramFilesDir => t.common_path_hint_program_files_dir(),
                PathHintKind::ProgramFilesX86Dir => t.common_path_hint_program_files_x86_dir(),
                PathHintKind::System32Dir => t.common_path_hint_system32_dir(),
                PathHintKind::SysWow64Dir => t.common_path_hint_syswow64_dir(),
            };
            format!("{} ({})", label, hint.pattern)
        })
        .collect()
}

/// 復元専用タスク登録（主要方式）
fn register_restore_task(restore_exe: &std::path::Path) -> Result<()> {
    let exe_str = restore_exe.to_string_lossy();
    log_setup(&format!("register_restore_task: exe = {}", exe_str));

    let task = kh_composition::task::TaskSchedulerAdapter::new(restore_exe);
    task.create_task(DEFAULT_RESTORE_TASK_NAME, &exe_str)
        .map_err(|e| err(format!("Failed to register restore task: {}", e)))?;
    Ok(())
}

// レジストリ状態

#[cfg(windows)]
fn write_targets_registry(config: &InstallConfig) -> Result<()> {
    let enabled: Vec<String> = config
        .targets
        .iter()
        .filter(|t| t.enabled())
        .map(|t| t.exe_name().to_string())
        .collect();
    kh_composition::targets::write_enabled_targets(&enabled)
        .map_err(|e| err(format!("Failed to write Targets registry: {e}")))
}

fn map_conflict_actions(
    conflict_actions: &std::collections::BTreeMap<String, ConflictAction>,
) -> std::collections::BTreeMap<String, AdminConflictAction> {
    conflict_actions
        .iter()
        .map(|(target, action)| {
            let mapped = match action {
                ConflictAction::Respect => AdminConflictAction::Respect,
                ConflictAction::TakeOver => AdminConflictAction::TakeOver,
                ConflictAction::Quarantine => AdminConflictAction::Quarantine,
            };
            (target.clone(), mapped)
        })
        .collect()
}

#[cfg(windows)]
fn backup_uninstall_state(
    runtime: &CliRuntime,
    config: &InstallConfig,
    conflict_actions: Option<&std::collections::BTreeMap<String, ConflictAction>>,
) -> Result<()> {
    let admin = AdminService::new(AdminDeps { port: runtime });
    let mapped = conflict_actions.map(map_conflict_actions);
    admin
        .backup_uninstall_state(config, mapped.as_ref())
        .map_err(|e| err(format!("Failed to back up IFEO state: {e}")))
}

#[cfg(not(windows))]
fn backup_uninstall_state(
    _runtime: &CliRuntime,
    _config: &InstallConfig,
    _conflict_actions: Option<&std::collections::BTreeMap<String, ConflictAction>>,
) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn write_targets_registry(_config: &InstallConfig) -> Result<()> {
    Ok(())
}
