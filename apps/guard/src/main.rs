#![windows_subsystem = "windows"]
//! kh-guard: IFEO 経由で起動されるガード本体。
//! 設定・セッション情報からポリシー判定を行い、必要なら確認ダイアログを出して
//! 対象プロセスを起動／ブロックする。

use clap::{Parser, Subcommand};
use kh_composition::guard::{
    GuardRuntime, ProcessBitness, get_session_info, normalize_target_name,
};
use kh_composition::{
    get_grandparent_process_info, get_parent_process_info,
};
use kh_composition::app::{GuardDeps, GuardService};
use kh_composition::domain::model::{
    GuardRequest, ProcessInfo, SessionInfo, SessionType,
};
use kh_composition::domain::port::driving::GuardUseCase;
use kh_composition::domain::port::driven::ConfigRepository;
use kh_composition::domain::model::Language;
use kh_composition::ui_common::i18n;
use kh_log_utils::{lifecycle_line, write_line_to_default_paths};
use std::process::ExitCode;
use std::error::Error;

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

fn log_message_box(kind: &str, title: &str, msg: &str) {
    let message = format!("{}: {} - {}", kind, title, msg.replace('\n', "\\n"));
    let line = lifecycle_line("UI", &message);
    write_line_to_default_paths(&line);
}

fn is_japanese() -> bool {
    matches!(i18n::current_language(), Language::Japanese)
}

fn guard_error_title() -> &'static str {
    if is_japanese() {
        "KaptainhooK ガード エラー"
    } else {
        "KaptainhooK Guard Error"
    }
}

fn guard_error_prefix() -> &'static str {
    if is_japanese() {
        "ガードエラー"
    } else {
        "kh-guard error"
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => {
            ExitCode::from(code)
        }
        Err(err) => {
            let msg = format!("{}: {err}", guard_error_prefix());
            eprintln!("{}", msg);
            show_error_msgbox(&msg);
            ExitCode::from(1)
        }
    }
}

/// エラーをMessageBoxで表示（windows_subsystem=windowsではコンソール非表示のため）
#[cfg(windows)]
fn show_error_msgbox(msg: &str) {
    let title = guard_error_title();
    log_message_box("error", title, msg);
    let _ = show_message_box(title, msg, win_flags::ERROR);
}

#[cfg(not(windows))]
fn show_error_msgbox(msg: &str) {
    let title = guard_error_title();
    log_message_box("error", title, msg);
    eprintln!("{}", msg);
}

#[cfg(windows)]
mod win_flags {
    use windows::Win32::UI::WindowsAndMessaging::{
        MESSAGEBOX_STYLE, MB_ICONERROR, MB_OK,
    };

    pub const ERROR: MESSAGEBOX_STYLE = MESSAGEBOX_STYLE(MB_OK.0 | MB_ICONERROR.0);
}

#[cfg(windows)]
fn show_message_box(
    title: &str,
    msg: &str,
    flags: windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE,
) -> windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::WindowsAndMessaging::MessageBoxW;
    use windows::core::PCWSTR;

    let title_w: Vec<u16> = OsStr::new(title)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let text_w: Vec<u16> = OsStr::new(msg)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe { MessageBoxW(None, PCWSTR(text_w.as_ptr()), PCWSTR(title_w.as_ptr()), flags) }
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    let mut runtime =
        GuardRuntime::new().map_err(|e| err(format!("failed to initialize guard runtime: {e}")))?;
    let lang = runtime.load().map(|c| c.language).unwrap_or_default();
    i18n::set_language(lang);

    match cli.command {
        Commands::Intercept { ifeo_view, target, args } => {
            runtime.set_ifeo_bitness(parse_ifeo_view(ifeo_view.as_deref()));
            guard_session(&runtime, &target, &args)
        }
    }
}

fn parse_ifeo_view(value: Option<&str>) -> Option<ProcessBitness> {
    match value {
        Some("32") => Some(ProcessBitness::Bit32),
        Some("64") => Some(ProcessBitness::Bit64),
        _ => None,
    }
}

/// ガードセッションのメインロジック
fn guard_session(runtime: &GuardRuntime, target: &str, args: &[String]) -> Result<u8> {
    // 親/祖父プロセス情報取得（コンテキスト変更前に早期取得）
    let parent_info = get_parent_process_info();
    let grandparent_info = get_grandparent_process_info();

    // セッション情報取得
    let session_info = get_session_info();

    // ターゲット名正規化（exe名のみ、小文字）
    let normalized = normalize_target_name(target);
    let domain_session = SessionInfo {
        session_type: if session_info.is_interactive {
            SessionType::Interactive
        } else {
            SessionType::NonInteractive
        },
        session_id: session_info.session_id,
        username: session_info.username.clone(),
        session_name: session_info.session_name.clone(),
    };

    let request = GuardRequest {
        target: target.to_string(),
        args: args.to_vec(),
        normalized_target: normalized,
        session: domain_session,
        parent: ProcessInfo {
            pid: parent_info.pid,
            name: parent_info.name.clone(),
            path: parent_info.path.clone(),
        },
        grandparent: ProcessInfo {
            pid: grandparent_info.pid,
            name: grandparent_info.name.clone(),
            path: grandparent_info.path.clone(),
        },
    };

    let deps = GuardDeps {
        config: runtime,
        targets: runtime,
        ifeo: runtime,
        launcher: runtime,
        prompt: runtime,
        notifier: runtime,
        logger: runtime,
        resolver: runtime,
        clock: runtime,
        random: runtime,
    };
    let service = GuardService::new(deps);
    let response = service.execute(request);
    Ok(response.exit_code)
}

// --- CLI定義 ---

#[derive(Parser)]
#[command(name = "kh-guard", about = "KaptainhooK guard process")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// ターゲットをインターセプトして評価（bootstrap経由）
    Intercept {
        /// IFEOビュー（32/64）
        #[arg(long, value_parser = ["32", "64"])]
        ifeo_view: Option<String>,
        /// ターゲット実行ファイル名
        target: String,
        /// 元のコマンドライン引数
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

    // targets::load_enabled_targets は kh-composition が提供
