//! ネイティブMessageBox補助（Windowsのみ）

use kh_log_utils::lifecycle_line;
use crate::i18n;
use kh_domain::model::Language;

#[cfg(windows)]
mod win_flags {
    use windows::Win32::UI::WindowsAndMessaging::{
        MESSAGEBOX_STYLE, MB_ICONERROR, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK, MB_YESNO,
    };

    pub const ERROR: MESSAGEBOX_STYLE = MESSAGEBOX_STYLE(MB_OK.0 | MB_ICONERROR.0);
    pub const INFO: MESSAGEBOX_STYLE = MESSAGEBOX_STYLE(MB_OK.0 | MB_ICONINFORMATION.0);
    pub const WARN: MESSAGEBOX_STYLE = MESSAGEBOX_STYLE(MB_OK.0 | MB_ICONWARNING.0);
    pub const YES_NO_WARN: MESSAGEBOX_STYLE = MESSAGEBOX_STYLE(MB_YESNO.0 | MB_ICONWARNING.0);
}

fn log_message_box(kind: &str, title: &str, msg: &str, result: Option<&str>) {
    let mut message = format!("{}: {} - {}", kind, title, msg.replace('\n', "\\n"));
    if let Some(res) = result {
        message.push_str(&format!(" result={}", res));
    }
    let line = lifecycle_line("UI", &message);
    write_log_line(&line);
}

fn write_log_line(line: &str) {
    use std::fs::OpenOptions;
    use std::io::Write;

    for path in log_paths() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
            return;
        }
    }
}

fn log_paths() -> Vec<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData")
            .unwrap_or_else(|_| "C:\\ProgramData".to_string());
        let base = std::path::PathBuf::from(base).join("KaptainhooK");
        return vec![
            base.join("final").join("logs").join("kh-lifecycle.log"),
            base.join("bin").join("kh-lifecycle.log"),
            std::env::temp_dir().join("kh-lifecycle.log"),
        ];
    }
    #[cfg(not(windows))]
    {
        return vec![std::env::temp_dir().join("kh-lifecycle.log")];
    }
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

fn service_title() -> &'static str {
    if is_japanese() {
        "KaptainhooK サービス"
    } else {
        "KaptainhooK Service"
    }
}

fn service_restart_prompt() -> &'static str {
    if is_japanese() {
        "サービスが停止しているため、許可できません。\nサービスを再起動しますか？"
    } else {
        "Service is stopped, so the request cannot be allowed.\nRestart the service now?"
    }
}

pub fn show_error_msgbox(msg: &str) {
    let title = guard_error_title();
    log_message_box("error", title, msg, None);
    #[cfg(windows)]
    {
        let _ = show_message_box(title, msg, win_flags::ERROR);
    }
}

pub fn show_info_msgbox(msg: &str) {
    log_message_box("info", "KaptainhooK", msg, None);
    #[cfg(windows)]
    {
        let _ = show_message_box("KaptainhooK", msg, win_flags::INFO);
    }
}

pub fn show_warn_msgbox(msg: &str) {
    log_message_box("warn", "KaptainhooK", msg, None);
    #[cfg(windows)]
    {
        let _ = show_message_box("KaptainhooK", msg, win_flags::WARN);
    }
}

pub fn prompt_service_restart() -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::IDYES;

        let title = service_title();
        let message = service_restart_prompt();
        let res = show_message_box(title, message, win_flags::YES_NO_WARN);
        let decision = if res == IDYES { "yes" } else { "no" };
        log_message_box(
            "prompt",
            title,
            &message.replace('\n', "\\n"),
            Some(decision),
        );
        res == IDYES
    }

    #[cfg(not(windows))]
    {
        let title = service_title();
        let message = service_restart_prompt();
        log_message_box(
            "prompt",
            title,
            message,
            Some("no"),
        );
        false
    }
}
