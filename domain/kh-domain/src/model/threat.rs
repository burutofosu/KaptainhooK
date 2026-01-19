/// コード署名の検証結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    Signed {
        kind: SignatureKind,
        subject: Option<String>,
        issuer: Option<String>,
        trust: SignatureTrust,
        revocation: RevocationStatus,
    },
    Unsigned,
    Error { message: String },
    Unsupported { reason: String },
}

/// 署名に関する注意種別
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureNoticeKind {
    Unsigned,
    Untrusted,
    Revoked,
    RevocationNotChecked,
    RevocationCheckFailed,
    Error,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureKind {
    Authenticode,
    Other { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureTrust {
    Trusted,
    Untrusted,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    Good,
    Revoked,
    NotChecked { reason: String },
    CheckFailed { reason: String },
}

/// パスヒント種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathHintKind {
    PublicUserDir,
    TempDir,
    UserTempDir,
    DownloadsDir,
    DesktopDir,
    ProgramFilesDir,
    ProgramFilesX86Dir,
    System32Dir,
    SysWow64Dir,
}

/// パス上のヒント（危険/安全の兆候）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathHint {
    pub pattern: String,
    pub kind: PathHintKind,
    pub is_suspicious: bool,
}

// 推奨アクションは admin 側の ConflictAction を参照
