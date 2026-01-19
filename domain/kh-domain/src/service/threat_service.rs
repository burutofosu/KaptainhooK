//! 脅威評価サービス（純粋関数）

use crate::model::{
    PathHint, PathHintKind, RevocationStatus, SignatureNoticeKind, SignatureStatus, SignatureTrust,
};

/// ファイルパスからパスヒントを抽出
pub fn extract_path_hints(path: &str) -> Vec<PathHint> {
    let lower = path.to_lowercase();
    let mut hints = Vec::new();

    const SUSPICIOUS_PATTERNS: &[(&str, PathHintKind)] = &[
        ("\\users\\public\\", PathHintKind::PublicUserDir),
        ("\\temp\\", PathHintKind::TempDir),
        ("\\appdata\\local\\temp\\", PathHintKind::UserTempDir),
        ("\\downloads\\", PathHintKind::DownloadsDir),
        ("\\desktop\\", PathHintKind::DesktopDir),
    ];

    const SAFE_PATTERNS: &[(&str, PathHintKind)] = &[
        ("\\program files\\", PathHintKind::ProgramFilesDir),
        ("\\program files (x86)\\", PathHintKind::ProgramFilesX86Dir),
        ("\\windows\\system32\\", PathHintKind::System32Dir),
        ("\\windows\\syswow64\\", PathHintKind::SysWow64Dir),
    ];

    for (pattern, kind) in SUSPICIOUS_PATTERNS {
        if lower.contains(pattern) {
            hints.push(PathHint {
                pattern: pattern.to_string(),
                kind: kind.clone(),
                is_suspicious: true,
            });
        }
    }

    for (pattern, kind) in SAFE_PATTERNS {
        if lower.contains(pattern) {
            hints.push(PathHint {
                pattern: pattern.to_string(),
                kind: kind.clone(),
                is_suspicious: false,
            });
        }
    }

    hints
}

/// 署名情報に基づく注意メッセージ（事実ベース）
pub fn signature_notice(signature: &SignatureStatus) -> Option<SignatureNoticeKind> {
    match signature {
        SignatureStatus::Unsigned => Some(SignatureNoticeKind::Unsigned),
        SignatureStatus::Signed { trust, revocation, .. } => {
            if matches!(trust, SignatureTrust::Untrusted) {
                return Some(SignatureNoticeKind::Untrusted);
            }
            match revocation {
                RevocationStatus::Revoked => Some(SignatureNoticeKind::Revoked),
                RevocationStatus::NotChecked { .. } => {
                    Some(SignatureNoticeKind::RevocationNotChecked)
                }
                RevocationStatus::CheckFailed { .. } => {
                    Some(SignatureNoticeKind::RevocationCheckFailed)
                }
                RevocationStatus::Good => None,
            }
        }
        SignatureStatus::Error { .. } => Some(SignatureNoticeKind::Error),
        SignatureStatus::Unsupported { .. } => Some(SignatureNoticeKind::Unsupported),
    }
}

/// パスが自社ブートストラップ（kh-bootstrap等）か判定
pub fn is_our_bootstrap(debugger_path: &str) -> bool {
    let exe = crate::service::ownership_service::extract_debugger_exe(debugger_path)
        .unwrap_or_else(|| debugger_path.trim().to_string());
    let name = exe
        .trim()
        .trim_matches('"')
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    matches!(name.as_str(), "kh-bootstrap.exe" | "kaptainhook_bootstrap.exe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsigned_is_notice() {
        let sig = SignatureStatus::Unsigned;
        assert!(signature_notice(&sig).is_some());
    }

    #[test]
    fn test_signed_good_is_none() {
        let sig = SignatureStatus::Signed {
            kind: crate::model::SignatureKind::Authenticode,
            subject: None,
            issuer: None,
            trust: SignatureTrust::Trusted,
            revocation: RevocationStatus::Good,
        };
        assert!(signature_notice(&sig).is_none());
    }

    #[test]
    fn test_suspicious_path_is_dangerous() {
        let hints = vec![PathHint {
            pattern: "\\temp\\".into(),
            kind: PathHintKind::TempDir,
            is_suspicious: true,
        }];
        assert!(!hints.is_empty());
    }

    #[test]
    fn test_extract_suspicious_hints() {
        let hints = extract_path_hints("C:\\Users\\Public\\malware.exe");
        assert!(!hints.is_empty());
        assert!(hints.iter().any(|h| h.is_suspicious));
    }

    #[test]
    fn test_extract_safe_hints() {
        let hints = extract_path_hints("C:\\Program Files\\App\\app.exe");
        assert!(!hints.is_empty());
        assert!(hints.iter().all(|h| !h.is_suspicious));
    }

    #[test]
    fn test_is_our_bootstrap() {
        assert!(is_our_bootstrap(
            "C:\\Program Files\\KaptainhooK\\kh-bootstrap.exe"
        ));
        assert!(is_our_bootstrap("kaptainhook_bootstrap.exe"));
        assert!(!is_our_bootstrap("C:\\Windows\\System32\\cmd.exe"));
        assert!(!is_our_bootstrap("C:\\Temp\\kh-bootstrap-fake.exe"));
        assert!(is_our_bootstrap(
            r#""C:\Program Files\KaptainhooK\kh-bootstrap.exe" -arg"#,
        ));
    }

    #[test]
    fn test_signature_notice_revocation_unknown() {
        let sig = SignatureStatus::Signed {
            kind: crate::model::SignatureKind::Authenticode,
            subject: None,
            issuer: None,
            trust: SignatureTrust::Unknown,
            revocation: RevocationStatus::NotChecked {
                reason: "offline".into(),
            },
        };
        assert!(signature_notice(&sig).is_some());
    }
}
