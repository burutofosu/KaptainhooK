#![windows_subsystem = "windows"]
//! kh-bootstrap: IFEO デバッガに登録されるブートストラップ。
//! 元のターゲット exe 名と引数を受け取り、同一ディレクトリの kh-guard を
//! `kh-guard intercept <target> -- <args>` で起動する。

use std::error::Error;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

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

macro_rules! bail {
    ($($t:tt)*) => {
        return Err(err(format!($($t)*)));
    };
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            // コンソールがないのでMessageBoxでエラー表示
            show_error(&format!("kh-bootstrap error:\n{err}"));
            ExitCode::from(1)
        }
    }
}

/// エラーをMessageBoxで表示
#[cfg(windows)]
fn show_error(msg: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    let title: Vec<u16> = OsStr::new("KaptainhooK Error")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let text: Vec<u16> = OsStr::new(msg)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        windows::Win32::UI::WindowsAndMessaging::MessageBoxW(
            None,
            windows::core::PCWSTR(text.as_ptr()),
            windows::core::PCWSTR(title.as_ptr()),
            windows::Win32::UI::WindowsAndMessaging::MB_OK
                | windows::Win32::UI::WindowsAndMessaging::MB_ICONERROR,
        );
    }
    let _ = ptr::null::<()>(); // 未使用警告抑止
}

#[cfg(not(windows))]
fn show_error(msg: &str) {
    eprintln!("{}", msg);
}

fn run() -> Result<u8> {
    // IFEO形式の引数をパース: kh-bootstrap.exe <target.exe> [args...]
    let args: Vec<String> = std::env::args().collect();

    // args[0] = "kh-bootstrap.exe"（実行ファイル名）
    // args[1] = ターゲット（例: "powershell.exe"）
    // args[2..] = ターゲットの元引数

    if args.len() < 2 {
        bail!("Usage: kh-bootstrap [--ifeo-view=32|64] <target.exe> [args...]");
    }

    let mut idx = 1usize;
    let mut ifeo_view: Option<String> = None;
    if args.len() > idx {
        if let Some(value) = args[idx].strip_prefix("--ifeo-view=") {
            ifeo_view = Some(value.to_string());
            idx += 1;
        } else if args[idx] == "--ifeo-view" {
            if args.len() <= idx + 1 {
                bail!("Usage: kh-bootstrap [--ifeo-view=32|64] <target.exe> [args...]");
            }
            ifeo_view = Some(args[idx + 1].clone());
            idx += 2;
        }
    }
    if let Some(view) = ifeo_view.as_deref() {
        if view != "32" && view != "64" {
            bail!("Invalid --ifeo-view value: {}", view);
        }
    }
    if args.len() <= idx {
        bail!("Usage: kh-bootstrap [--ifeo-view=32|64] <target.exe> [args...]");
    }

    let target = &args[idx];
    let target_args: Vec<&str> = args[(idx + 1)..].iter().map(|s| s.as_str()).collect();

    // kh-bootstrap.exeと同じディレクトリからkh-guard.exeを探す
    let guard_path = find_guard_executable()?;

    // interceptサブコマンドでkh-guardを起動
    let mut cmd = Command::new(&guard_path);
    cmd.arg("intercept");
    if let Some(view) = ifeo_view {
        cmd.arg(format!("--ifeo-view={}", view));
    }
    cmd.arg(target);

    // セパレータを追加して元の引数をパススルー
    if !target_args.is_empty() {
        cmd.arg("--");
        cmd.args(&target_args);
    }

    let status = cmd
        .status()
        .map_err(|e| err(format!("Failed to launch guard: {}: {e}", guard_path.display())))?;

    let exit_code = status.code().unwrap_or(1) as u8;

    Ok(exit_code)
}

/// kh-bootstrap.exeと同じディレクトリからkh-guard.exeを探す
fn find_guard_executable() -> Result<PathBuf> {
    let current_exe = std::env::current_exe()
        .map_err(|e| err(format!("Failed to get current executable path: {e}")))?;

    let exe_dir = current_exe
        .parent()
        .ok_or_else(|| err("Failed to get executable directory"))?;

    // プラットフォーム固有の名前を試行
    #[cfg(target_os = "windows")]
    let candidates = ["kh-guard.exe", "kh-guard"];
    #[cfg(not(target_os = "windows"))]
    let candidates = ["kh-guard"];

    for name in candidates {
        let path = exe_dir.join(name);
        if path.is_file() {
            return Ok(path);
        }
    }

    // PATH は使わない
    bail!(
        "kh-guard executable not found next to kh-bootstrap: {:?}",
        exe_dir
    );
}
