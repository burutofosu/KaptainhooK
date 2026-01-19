//! IFEOエントリの所有権判定サービス
//!
//! IFEOのデバッガエントリが自社製品か他製品かを判定する。
//! クリーンアップ・アンインストール時に他製品を破壊しないために必須。

use crate::path::normalize_local_drive_absolute_path;

/// デバッガコマンドラインからexeパス（argv[0]）を抽出
/// - 先頭が `"` なら次の `"` までをパスとして扱う
/// - それ以外は空白までをパスとして扱う
pub fn extract_debugger_exe(cmdline: &str) -> Option<String> {
    let mut s = cmdline.trim();
    if s.is_empty() {
        return None;
    }
    while s.starts_with("\"\"") && s.ends_with("\"\"") && s.len() >= 4 {
        s = &s[1..s.len() - 1];
    }
    if s.starts_with('"') {
        let mut backslashes = 0usize;
        for (idx, ch) in s.char_indices().skip(1) {
            if ch == '\\' {
                backslashes += 1;
                continue;
            }
            if ch == '"' && backslashes % 2 == 0 {
                return Some(s[1..idx].to_string());
            }
            backslashes = 0;
        }
        return Some(s.trim_matches('"').to_string());
    }
    let end = s.find(|c: char| c.is_whitespace()).unwrap_or(s.len());
    Some(s[..end].to_string())
}

/// デバッガコマンドラインからexeパスを正規化して取得
pub fn normalize_debugger_exe(cmdline: &str) -> Option<String> {
    let trimmed = cmdline.trim();
    if trimmed.is_empty() {
        return None;
    }
    let expanded = expand_env_vars(trimmed);
    let lower = expanded.to_ascii_lowercase();
    if let Some(pos) = lower.rfind(".exe") {
        if lower[pos + 4..].trim().is_empty() {
            if let Some(path) = normalize_local_drive_absolute_path(&expanded) {
                return Some(path);
            }
        }
    }
    extract_debugger_exe(&expanded).and_then(|s| normalize_local_drive_absolute_path(&s))
}

fn expand_env_vars(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        let mut name = String::new();
        let mut closed = false;
        while let Some(next) = chars.next() {
            if next == '%' {
                closed = true;
                break;
            }
            name.push(next);
        }
        if !closed {
            out.push('%');
            out.push_str(&name);
            break;
        }
        if name.is_empty() {
            out.push('%');
            continue;
        }
        if let Ok(value) = std::env::var(&name) {
            out.push_str(&value);
        } else {
            out.push('%');
            out.push_str(&name);
            out.push('%');
        }
    }
    out
}

/// デバッガパスが自社ブートストラップかを判定
/// Windowsパスは大文字小文字を区別しないため、比較も同様。
pub fn is_owned_debugger(debugger_path: &str, our_debugger: &str) -> bool {
    let their_exe = normalize_debugger_exe(debugger_path)
        .and_then(|s| normalize_local_drive_absolute_path(&s));
    let our_exe = normalize_local_drive_absolute_path(our_debugger)
        .or_else(|| {
            normalize_debugger_exe(our_debugger)
                .and_then(|s| normalize_local_drive_absolute_path(&s))
        });

    if let (Some(their), Some(our)) = (their_exe.as_deref(), our_exe.as_deref()) {
        if their.eq_ignore_ascii_case(our) {
            return true;
        }
    }

    if let Some(their) = their_exe.as_deref() {
        if is_known_bootstrap_path(their) {
            return true;
        }
    }

    false
}

fn is_known_bootstrap_path(path: &str) -> bool {
    let Some(normalized) = normalize_local_drive_absolute_path(path) else {
        return false;
    };

    let lower = normalized.to_ascii_lowercase();
    let is_bootstrap = lower.ends_with("\\kh-bootstrap.exe")
        || lower.ends_with("\\kaptainhook_bootstrap.exe");
    if !is_bootstrap {
        return false;
    }

    let bytes = lower.as_bytes();
    if bytes.len() < 3 || bytes[1] != b':' || bytes[2] != b'\\' {
        return false;
    }

    let after_drive = &lower[2..];
    const ALLOWED_PREFIXES: &[&str] = &[
        "\\program files\\kaptainhook\\",
        "\\program files (x86)\\kaptainhook\\",
        "\\programdata\\kaptainhook\\",
    ];
    ALLOWED_PREFIXES
        .iter()
        .any(|prefix| after_drive.starts_with(prefix))
}

/// IFEO解除時の判定結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnregisterDecision {
    /// 自社エントリ - 削除可
    Remove,
    /// 他製品エントリ - スキップ
    Skip { existing: String },
    /// 未登録
    NotRegistered,
}

impl UnregisterDecision {
    pub fn is_remove(&self) -> bool {
        matches!(self, Self::Remove)
    }

    pub fn is_skip(&self) -> bool {
        matches!(self, Self::Skip { .. })
    }
}

/// IFEOエントリを解除すべきか判定
/// 自社なら削除、他製品はスキップ、未登録はそのまま
pub fn decide_unregister(current_debugger: Option<&str>, our_debugger: &str) -> UnregisterDecision {
    match current_debugger {
        None => UnregisterDecision::NotRegistered,
        Some(dbg) if is_owned_debugger(dbg, our_debugger) => UnregisterDecision::Remove,
        Some(dbg) => UnregisterDecision::Skip {
            existing: dbg.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_owned_exact_match() {
        assert!(is_owned_debugger(
            r"C:\Program Files\KaptainhooK\kh-bootstrap.exe",
            r"C:\Program Files\KaptainhooK\kh-bootstrap.exe"
        ));
    }

    #[test]
    fn test_is_owned_case_insensitive() {
        assert!(is_owned_debugger(
            r"C:\PROGRAM FILES\KAPTAINHOOK\KH-BOOTSTRAP.EXE",
            r"C:\Program Files\KaptainhooK\kh-bootstrap.exe"
        ));
    }

    #[test]
    fn test_is_owned_with_quotes() {
        assert!(is_owned_debugger(
            r#""C:\Program Files\KaptainhooK\kh-bootstrap.exe""#,
            r"C:\Program Files\KaptainhooK\kh-bootstrap.exe"
        ));
    }

    #[test]
    fn test_extract_debugger_exe_with_args() {
        let exe = extract_debugger_exe(
            r#""C:\Program Files\KaptainhooK\kh-bootstrap.exe" -arg1 -arg2"#,
        )
        .expect("should extract exe");
        assert_eq!(
            exe,
            r"C:\Program Files\KaptainhooK\kh-bootstrap.exe"
        );
    }

    #[test]
    fn test_is_owned_with_ifeo_view_flag() {
        assert!(is_owned_debugger(
            r#""C:\Program Files\KaptainhooK\kh-bootstrap.exe" --ifeo-view=64"#,
            r"C:\Program Files\KaptainhooK\kh-bootstrap.exe"
        ));
    }

    #[test]
    fn test_is_owned_by_exe_name() {
        assert!(!is_owned_debugger(
            r"C:\Other\Path\kh-bootstrap.exe",
            r"C:\Program Files\KaptainhooK\kh-bootstrap.exe"
        ));
    }

    #[test]
    fn test_is_owned_legacy_name() {
        assert!(is_owned_debugger(
            r"C:\Program Files\KaptainhooK\kaptainhook_bootstrap.exe",
            r"C:\Program Files\KaptainhooK\kaptainhook_bootstrap.exe"
        ));
    }

    #[test]
    fn test_is_owned_programdata_path() {
        assert!(is_owned_debugger(
            r"C:\ProgramData\KaptainhooK\bin\kh-bootstrap.exe",
            r"C:\Program Files\KaptainhooK\bin\kh-bootstrap.exe"
        ));
    }

    #[test]
    fn test_is_owned_dotdot_inside_prefix() {
        assert!(is_owned_debugger(
            r"C:\Program Files\KaptainhooK\bin\..\kh-bootstrap.exe",
            r"C:\Program Files\KaptainhooK\kh-bootstrap.exe"
        ));
    }

    #[test]
    fn test_not_owned_dotdot_escape_prefix() {
        assert!(!is_owned_debugger(
            r"C:\Program Files\KaptainhooK\..\Windows\System32\kh-bootstrap.exe",
            r"C:\Program Files\KaptainhooK\kh-bootstrap.exe"
        ));
    }

    #[test]
    fn test_not_owned_dotdot_beyond_root() {
        assert!(!is_owned_debugger(
            r"C:\..\Program Files\KaptainhooK\kh-bootstrap.exe",
            r"C:\Program Files\KaptainhooK\kh-bootstrap.exe"
        ));
    }


    #[test]
    fn test_normalize_debugger_exe_expands_env_vars() {
        let key = "KH_TEST_ROOT";
        let old = std::env::var(key).ok();
        std::env::set_var(key, r"C:\Program Files");
        let normalized = normalize_debugger_exe(
            r"%KH_TEST_ROOT%\KaptainhooK\kh-bootstrap.exe",
        )
        .expect("should normalize");
        assert_eq!(
            normalized,
            r"C:\Program Files\KaptainhooK\kh-bootstrap.exe"
        );
        if let Some(value) = old {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn test_not_owned_different_product() {
        assert!(!is_owned_debugger(
            r"C:\OtherProduct\debugger.exe",
            r"C:\KaptainhooK\kh-bootstrap.exe"
        ));
    }

    #[test]
    fn test_not_owned_similar_name() {
        assert!(!is_owned_debugger(
            r"C:\Malware\kh-bootstrap-fake.exe",
            r"C:\KaptainhooK\kh-bootstrap.exe"
        ));
    }

    #[test]
    fn test_decide_not_registered() {
        let decision = decide_unregister(None, r"C:\kh-bootstrap.exe");
        assert_eq!(decision, UnregisterDecision::NotRegistered);
    }

    #[test]
    fn test_decide_remove_ours() {
        let decision = decide_unregister(
            Some(r"C:\KaptainhooK\kh-bootstrap.exe"),
            r"C:\KaptainhooK\kh-bootstrap.exe",
        );
        assert_eq!(decision, UnregisterDecision::Remove);
    }

    #[test]
    fn test_decide_skip_others() {
        let decision = decide_unregister(
            Some(r"C:\OtherProduct\debugger.exe"),
            r"C:\KaptainhooK\kh-bootstrap.exe",
        );
        assert!(decision.is_skip());
        if let UnregisterDecision::Skip { existing } = decision {
            assert_eq!(existing, r"C:\OtherProduct\debugger.exe");
        }
    }
}
