//! 対象リポジトリポート（読み取り専用）

use crate::error::DomainError;
use std::collections::HashSet;

/// 信頼ストアから有効対象を読み取る
pub trait TargetsRepository {
    fn load_enabled_targets(&self) -> Result<HashSet<String>, DomainError>;
}
