//! パス正規化ユーティリティ（stdのみ）

/// ローカルの絶対パスを正規化（UNC不可、"\\?\\C:\\" は許可）。
/// "." は無視、".." は折り畳み（root 超えは拒否）。
pub fn normalize_local_drive_absolute_path(path: &str) -> Option<String> {
    let trimmed = path.trim().trim_matches('"');
    if trimmed.is_empty() || trimmed.contains('\0') {
        return None;
    }

    let mut s = trimmed.replace('/', "\\");
    if s.starts_with(r"\\?\") {
        s = s[4..].to_string();
        if s.to_ascii_lowercase().starts_with("unc\\") {
            return None;
        }
    }
    if s.starts_with(r"\\") {
        return None;
    }

    let bytes = s.as_bytes();
    if bytes.len() < 3 || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }
    let drive = bytes[0] as char;
    if !drive.is_ascii_alphabetic() {
        return None;
    }

    let rest = &s[3..];
    let mut stack: Vec<&str> = Vec::new();
    for part in rest.split('\\') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if stack.pop().is_none() {
                return None;
            }
            continue;
        }
        stack.push(part);
    }

    let mut out = String::new();
    out.push(drive.to_ascii_uppercase());
    out.push(':');
    out.push('\\');
    if !stack.is_empty() {
        out.push_str(&stack.join("\\"));
    }
    Some(out)
}
