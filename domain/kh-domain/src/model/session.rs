use std::time::{Duration, SystemTime};

/// セッションの種類（対話/非対話）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    /// 対話型セッション（ユーザーログイン）
    Interactive,
    /// 非対話型セッション（サービス、Session 0）
    NonInteractive,
}

impl Default for SessionType {
    fn default() -> Self {
        Self::Interactive
    }
}

/// セッション情報
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// セッションの種類
    pub session_type: SessionType,
    /// セッションID
    pub session_id: u32,
    /// ユーザー名
    pub username: String,
    /// セッション名（表示用）
    pub session_name: String,
}

impl Default for SessionInfo {
    fn default() -> Self {
        Self {
            session_type: SessionType::Interactive,
            session_id: 0,
            username: String::new(),
            session_name: String::new(),
        }
    }
}

impl SessionInfo {
    /// 新しいセッション情報を作成
    pub fn new(
        session_type: SessionType,
        session_id: u32,
        username: impl Into<String>,
        session_name: impl Into<String>,
    ) -> Self {
        Self {
            session_type,
            session_id,
            username: username.into(),
            session_name: session_name.into(),
        }
    }

    /// 非対話セッションかどうか
    pub fn is_non_interactive(&self) -> bool {
        matches!(self.session_type, SessionType::NonInteractive)
    }

    /// 対話セッションかどうか
    pub fn is_interactive(&self) -> bool {
        matches!(self.session_type, SessionType::Interactive)
    }

    /// Session 0（サービスセッション）かどうか
    pub fn is_session_zero(&self) -> bool {
        self.session_id == 0
    }
}

/// IFEO 一時無効化などに使うセッショントークン。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken {
    pub value: String,
    pub expires_at: SystemTime,
}

impl SessionToken {
    pub fn new<S: Into<String>>(value: S, ttl: Duration) -> Self {
        Self {
            value: value.into(),
            expires_at: SystemTime::now() + ttl,
        }
    }

    pub fn is_expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }

    pub fn remaining(&self, now: SystemTime) -> Option<Duration> {
        self.expires_at.duration_since(now).ok()
    }
}
