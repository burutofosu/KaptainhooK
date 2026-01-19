//! ドメインエラー型
//!
//! 標準ライブラリのみ使用（外部エラーハンドリングクレートなし）

use std::fmt;

/// ガードアプリと共有するIPCサービスのエラーコード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceErrorCode {
    ProtocolVersionMismatch,
    MessageTooLarge,
    ClientNotTrusted,
    TargetNotAllowed,
    TargetsUnavailable,
    Busy,
    ForeignDetected,
    InvalidLease,
    LeaseExpired,
    InternalError,
}

/// IPCサービスの詳細エラーメッセージID（UI側で翻訳）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceErrorMessageId {
    InvalidTargetName,
    FailedReadProtectedTargets,
    StateLockPoisoned,
    ForeignDetectedDuringRestore,
    FailedRestoreStaleLease,
    FailedReadLeaseState,
    FailedKickRestoreTask,
    FailedAcquireIfeoMutex,
    ForeignDebuggerInView,
    IfeoEntryMissingInView,
    FailedWriteLeaseState,
    FailedDisableIfeo,
    FailedParseRequest,
    MessageTooLarge,
}

impl ServiceErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProtocolVersionMismatch => "ProtocolVersionMismatch",
            Self::MessageTooLarge => "MessageTooLarge",
            Self::ClientNotTrusted => "ClientNotTrusted",
            Self::TargetNotAllowed => "TargetNotAllowed",
            Self::TargetsUnavailable => "TargetsUnavailable",
            Self::Busy => "Busy",
            Self::ForeignDetected => "ForeignDetected",
            Self::InvalidLease => "InvalidLease",
            Self::LeaseExpired => "LeaseExpired",
            Self::InternalError => "InternalError",
        }
    }

    pub fn from_str(code: &str) -> Option<Self> {
        match code {
            "ProtocolVersionMismatch" => Some(Self::ProtocolVersionMismatch),
            "MessageTooLarge" => Some(Self::MessageTooLarge),
            "ClientNotTrusted" => Some(Self::ClientNotTrusted),
            "TargetNotAllowed" => Some(Self::TargetNotAllowed),
            "TargetsUnavailable" => Some(Self::TargetsUnavailable),
            "Busy" => Some(Self::Busy),
            "ForeignDetected" => Some(Self::ForeignDetected),
            "InvalidLease" => Some(Self::InvalidLease),
            "LeaseExpired" => Some(Self::LeaseExpired),
            "InternalError" => Some(Self::InternalError),
            _ => None,
        }
    }
}

impl ServiceErrorMessageId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidTargetName => "InvalidTargetName",
            Self::FailedReadProtectedTargets => "FailedReadProtectedTargets",
            Self::StateLockPoisoned => "StateLockPoisoned",
            Self::ForeignDetectedDuringRestore => "ForeignDetectedDuringRestore",
            Self::FailedRestoreStaleLease => "FailedRestoreStaleLease",
            Self::FailedReadLeaseState => "FailedReadLeaseState",
            Self::FailedKickRestoreTask => "FailedKickRestoreTask",
            Self::FailedAcquireIfeoMutex => "FailedAcquireIfeoMutex",
            Self::ForeignDebuggerInView => "ForeignDebuggerInView",
            Self::IfeoEntryMissingInView => "IfeoEntryMissingInView",
            Self::FailedWriteLeaseState => "FailedWriteLeaseState",
            Self::FailedDisableIfeo => "FailedDisableIfeo",
            Self::FailedParseRequest => "FailedParseRequest",
            Self::MessageTooLarge => "MessageTooLarge",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "InvalidTargetName" => Some(Self::InvalidTargetName),
            "FailedReadProtectedTargets" => Some(Self::FailedReadProtectedTargets),
            "StateLockPoisoned" => Some(Self::StateLockPoisoned),
            "ForeignDetectedDuringRestore" => Some(Self::ForeignDetectedDuringRestore),
            "FailedRestoreStaleLease" => Some(Self::FailedRestoreStaleLease),
            "FailedReadLeaseState" => Some(Self::FailedReadLeaseState),
            "FailedKickRestoreTask" => Some(Self::FailedKickRestoreTask),
            "FailedAcquireIfeoMutex" => Some(Self::FailedAcquireIfeoMutex),
            "ForeignDebuggerInView" => Some(Self::ForeignDebuggerInView),
            "IfeoEntryMissingInView" => Some(Self::IfeoEntryMissingInView),
            "FailedWriteLeaseState" => Some(Self::FailedWriteLeaseState),
            "FailedDisableIfeo" => Some(Self::FailedDisableIfeo),
            "FailedParseRequest" => Some(Self::FailedParseRequest),
            "MessageTooLarge" => Some(Self::MessageTooLarge),
            _ => None,
        }
    }
}

/// ドメイン層のエラー型
/// 各バリアントは特定の失敗シナリオを表現
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// レジストリアクセス拒否（管理者権限不足）
    RegistryAccessDenied(String),

    /// 対象ターゲットが見つからない
    TargetNotFound(String),

    /// IFEOに既存のデバッガが設定済み（コンフリクト）
    Conflict { target: String, existing: String },

    /// 署名検証失敗
    SignatureVerificationFailed(String),

    /// 設定値が無効
    InvalidConfig(String),

    /// 設定ファイルの読み込み失敗
    ConfigLoadFailed(String),

    /// プロセス起動失敗
    ProcessLaunchFailed(String),

    /// バイパス完了処理の失敗（起動失敗の付帯情報）
    BypassCompletionFailed {
        cause: Box<DomainError>,
        bypass_error: String,
    },

    /// 認証失敗（HMACなど）
    AuthenticationFailed(String),

    /// プロセス間通信エラー
    IpcError(String),

    /// IPCサービスが返したエラー
    IpcServiceError {
        context: String,
        code: ServiceErrorCode,
        message_id: Option<ServiceErrorMessageId>,
    },

    /// バリデーションエラー
    ValidationError(String),

    /// ファイルI/Oエラー
    IoError(String),

    /// タイムアウト
    Timeout(String),

    /// 不明なエラー
    Unknown(String),
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistryAccessDenied(msg) => {
                write!(f, "Registry access denied: {}", msg)
            }
            Self::TargetNotFound(target) => {
                write!(f, "Target not found: {}", target)
            }
            Self::Conflict { target, existing } => {
                write!(
                    f,
                    "IFEO conflict for {}: existing debugger {}",
                    target, existing
                )
            }
            Self::SignatureVerificationFailed(msg) => {
                write!(f, "Signature verification failed: {}", msg)
            }
            Self::InvalidConfig(msg) => {
                write!(f, "Invalid configuration: {}", msg)
            }
            Self::ConfigLoadFailed(msg) => {
                write!(f, "Configuration load failed: {}", msg)
            }
            Self::ProcessLaunchFailed(msg) => {
                write!(f, "Process launch failed: {}", msg)
            }
            Self::BypassCompletionFailed { cause, bypass_error } => {
                write!(
                    f,
                    "Bypass completion failed: {}; cause: {}",
                    bypass_error, cause
                )
            }
            Self::AuthenticationFailed(msg) => {
                write!(f, "Authentication failed: {}", msg)
            }
            Self::IpcError(msg) => {
                write!(f, "IPC error: {}", msg)
            }
            Self::IpcServiceError {
                context,
                code,
                message_id,
            } => match message_id {
                Some(id) => write!(
                    f,
                    "IPC service error ({context}): {:?}: {}",
                    code,
                    id.as_str()
                ),
                None => write!(f, "IPC service error ({context}): {:?}", code),
            },
            Self::ValidationError(msg) => {
                write!(f, "Validation error: {}", msg)
            }
            Self::IoError(msg) => {
                write!(f, "IO error: {}", msg)
            }
            Self::Timeout(msg) => {
                write!(f, "Timeout: {}", msg)
            }
            Self::Unknown(msg) => {
                write!(f, "Unknown error: {}", msg)
            }
        }
    }
}

impl std::error::Error for DomainError {}
