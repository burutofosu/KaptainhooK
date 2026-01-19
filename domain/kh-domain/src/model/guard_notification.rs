//! ガード通知メッセージ（UI側で翻訳するための構造）

use crate::error::{ServiceErrorCode, ServiceErrorMessageId};
use crate::model::PathHintKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspiciousPathWarning {
    pub target: String,
    pub related: String,
    pub reasons: Vec<PathHintKind>,
}

impl SuspiciousPathWarning {
    pub fn fallback_message(&self) -> String {
        let reasons = self
            .reasons
            .iter()
            .map(|kind| path_hint_label(*kind))
            .collect::<Vec<_>>()
            .join(" / ");
        format!(
            "Notice: related paths may be in unusual locations.\nTarget: {}\nRelated: {}\nReason: {}",
            self.target, self.related, reasons
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardNotification {
    ConfigLoadFailed,
    TargetsUnavailable,
    TargetNotFoundInSearchPaths,
    LaunchFailed { detail: String },
    ServiceStopped,
    ServiceRestarting,
    ServiceCommFailed { detail: String },
    ServiceError {
        code: ServiceErrorCode,
        message_id: Option<ServiceErrorMessageId>,
    },
    SuspiciousPathWarning(SuspiciousPathWarning),
    NotifyAllowed {
        categories: Vec<String>,
        warning: Option<SuspiciousPathWarning>,
    },
}

impl GuardNotification {
    pub fn fallback_message(&self) -> String {
        match self {
            GuardNotification::ConfigLoadFailed => {
                "Failed to read the config file. Reinstall or contact your administrator."
                    .to_string()
            }
            GuardNotification::TargetsUnavailable => {
                "Failed to read the protected target list. Reinstall or contact your administrator."
                    .to_string()
            }
            GuardNotification::TargetNotFoundInSearchPaths => {
                "Target not found in allowed search paths. Add it in settings.".to_string()
            }
            GuardNotification::LaunchFailed { detail } => {
                format!("Launch failed: {}", detail)
            }
            GuardNotification::ServiceStopped => {
                "Cannot allow because the service is stopped.".to_string()
            }
            GuardNotification::ServiceRestarting => {
                "Trying to restart the service.".to_string()
            }
            GuardNotification::ServiceCommFailed { detail } => {
                format!("Failed to communicate with the service: {}", detail)
            }
            GuardNotification::ServiceError { code, message_id } => {
                if let Some(id) = message_id {
                    service_error_message_id_fallback(*id)
                } else {
                    service_error_code_fallback(*code)
                }
            }
            GuardNotification::SuspiciousPathWarning(warn) => warn.fallback_message(),
            GuardNotification::NotifyAllowed { categories, warning } => {
                let mut base = if categories.is_empty() {
                    "Warning: origin category is unknown, but it will be allowed with notification."
                        .to_string()
                } else {
                    format!(
                        "Warning: origin category ({}) - allowed with notification.",
                        categories.join(", ")
                    )
                };
                if let Some(extra) = warning {
                    base.push_str("\n\n");
                    base.push_str(&extra.fallback_message());
                }
                base
            }
        }
    }
}

fn path_hint_label(kind: PathHintKind) -> &'static str {
    match kind {
        PathHintKind::PublicUserDir => "Public user directory",
        PathHintKind::TempDir => "Temporary directory",
        PathHintKind::UserTempDir => "User temp directory",
        PathHintKind::DownloadsDir => "Downloads directory",
        PathHintKind::DesktopDir => "Desktop directory",
        PathHintKind::ProgramFilesDir => "Program Files",
        PathHintKind::ProgramFilesX86Dir => "Program Files (x86)",
        PathHintKind::System32Dir => "System32",
        PathHintKind::SysWow64Dir => "SysWOW64",
    }
}

fn service_error_code_fallback(code: ServiceErrorCode) -> String {
    match code {
        ServiceErrorCode::ProtocolVersionMismatch | ServiceErrorCode::ClientNotTrusted => {
            "Install may be corrupted or inconsistent. Reinstall, or run kh-cli trusted-hashes refresh after replacing binaries."
                .to_string()
        }
        ServiceErrorCode::TargetsUnavailable => {
            "Failed to read the protected target list. Reinstall or contact your administrator."
                .to_string()
        }
        ServiceErrorCode::TargetNotAllowed => {
            "This target is not protected (check settings).".to_string()
        }
        ServiceErrorCode::Busy => {
            "Another admin operation is running. Please wait and retry.".to_string()
        }
        ServiceErrorCode::ForeignDetected => {
            "Another product's IFEO Debugger was detected. Resolve conflicts in settings."
                .to_string()
        }
        ServiceErrorCode::InvalidLease | ServiceErrorCode::LeaseExpired => {
            "Temporary permission is expired or invalid. Try again.".to_string()
        }
        ServiceErrorCode::InternalError => {
            "Service internal error. Try restarting the service (kh-service-restart)."
                .to_string()
        }
        ServiceErrorCode::MessageTooLarge => {
            "Failed to communicate with the service.".to_string()
        }
    }
}

fn service_error_message_id_fallback(id: ServiceErrorMessageId) -> String {
    match id {
        ServiceErrorMessageId::InvalidTargetName => {
            "Invalid target name. Check settings.".to_string()
        }
        ServiceErrorMessageId::FailedReadProtectedTargets => {
            "Failed to read the protected target list. Reinstall or contact your administrator."
                .to_string()
        }
        ServiceErrorMessageId::StateLockPoisoned => {
            "Service state lock failed. Try restarting the service.".to_string()
        }
        ServiceErrorMessageId::ForeignDetectedDuringRestore => {
            "Another product's IFEO Debugger was detected during restore. Resolve conflicts in settings."
                .to_string()
        }
        ServiceErrorMessageId::FailedRestoreStaleLease => {
            "Failed to restore an expired lease. Try restarting the service.".to_string()
        }
        ServiceErrorMessageId::FailedReadLeaseState => {
            "Failed to read lease state. Try restarting the service.".to_string()
        }
        ServiceErrorMessageId::FailedKickRestoreTask => {
            "Failed to trigger the restore task. Check the setup.".to_string()
        }
        ServiceErrorMessageId::FailedAcquireIfeoMutex => {
            "Failed to acquire IFEO lock. Wait and retry.".to_string()
        }
        ServiceErrorMessageId::ForeignDebuggerInView => {
            "Another product's IFEO Debugger was detected. Resolve conflicts in settings."
                .to_string()
        }
        ServiceErrorMessageId::IfeoEntryMissingInView => {
            "IFEO entries are missing in one view. Remove via settings or repair by uninstalling."
                .to_string()
        }
        ServiceErrorMessageId::FailedWriteLeaseState => {
            "Failed to write lease state. Try restarting the service.".to_string()
        }
        ServiceErrorMessageId::FailedDisableIfeo => {
            "Failed to disable IFEO temporarily. Try restarting the service.".to_string()
        }
        ServiceErrorMessageId::FailedParseRequest => {
            "Failed to parse service request. Please retry.".to_string()
        }
        ServiceErrorMessageId::MessageTooLarge => {
            "IPC message is too large.".to_string()
        }
    }
}
