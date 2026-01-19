//! ポリシー設定

/// 競合発生時のアクション（ユーザー設定・システム推奨で共通）
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConflictAction {
    /// 既存を尊重（上書きしない）
    Respect,
    /// 警告して許可
    WarnAndAllow,
    /// 強制ブロック
    ForceBlock,
}

/// 非対話モードでの扱い。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonInteractivePolicy {
    Deny,
    AllowWithToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub conflict: ConflictAction,
    pub non_interactive: NonInteractivePolicy,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            conflict: ConflictAction::WarnAndAllow,
            non_interactive: NonInteractivePolicy::Deny,
        }
    }
}
