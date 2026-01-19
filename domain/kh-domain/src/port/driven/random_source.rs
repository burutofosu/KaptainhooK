//! 乱数ポート

use crate::error::DomainError;

/// 乱数生成ポート（アダプタ実装）
pub trait RandomSource {
    /// 次の乱数値を返す
    fn next_u64(&self) -> Result<u64, DomainError>;
}
