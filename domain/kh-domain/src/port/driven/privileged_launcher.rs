//! 特権起動ポート
//!
//! ガードが一連のバイパスを単一トランザクションで実行するために使用する:
//! 特権コンポーネント経由でIFEOを一時回避し、対象を起動する。

use crate::error::DomainError;

/// 特権バイパス付きで対象を起動する要求
#[derive(Debug, Clone)]
pub struct PrivilegedLaunchRequest {
    target: String,
    args: Vec<String>,
    normalized_target: String,
    is_protected: bool,
}

impl PrivilegedLaunchRequest {
    pub fn new(
        target: impl Into<String>,
        args: Vec<String>,
        normalized_target: impl Into<String>,
        is_protected: bool,
    ) -> Result<Self, DomainError> {
        let target = target.into();
        if target.trim().is_empty() {
            return Err(DomainError::ValidationError(
                "target must not be empty".into(),
            ));
        }
        let normalized_target = normalized_target.into();
        if normalized_target.trim().is_empty() {
            return Err(DomainError::ValidationError(
                "normalized_target must not be empty".into(),
            ));
        }
        Ok(Self {
            target,
            args,
            normalized_target,
            is_protected,
        })
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn normalized_target(&self) -> &str {
        &self.normalized_target
    }

    pub fn is_protected(&self) -> bool {
        self.is_protected
    }
}

/// 特権起動の結果
#[derive(Debug, Clone)]
pub struct PrivilegedLaunchResult {
    exit_code: u8,
    complete_bypass_error: Option<String>,
}

impl PrivilegedLaunchResult {
    pub fn new(exit_code: u8) -> Self {
        Self {
            exit_code,
            complete_bypass_error: None,
        }
    }

    pub fn exit_code(&self) -> u8 {
        self.exit_code
    }

    pub fn with_complete_bypass_error(mut self, error: Option<String>) -> Self {
        self.complete_bypass_error = error;
        self
    }

    pub fn complete_bypass_error(&self) -> Option<&str> {
        self.complete_bypass_error.as_deref()
    }
}

/// 特権起動ポート
pub trait PrivilegedLauncher {
    /// IFEOバイパス付きで対象を単一トランザクションで起動
    fn launch_with_bypass(
        &self,
        request: &PrivilegedLaunchRequest,
    ) -> Result<PrivilegedLaunchResult, DomainError>;
}
