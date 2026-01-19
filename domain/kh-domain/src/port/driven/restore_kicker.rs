//! 復元専用タスク起動ポート

use crate::error::DomainError;

/// 一定時間後に復元専用タスクを起動
pub trait RestoreKicker {
    fn kick_restore_after(&self, delay_ms: u32) -> Result<(), DomainError>;
}
