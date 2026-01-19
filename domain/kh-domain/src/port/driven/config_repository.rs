//! 設定リポジトリポート

use crate::error::DomainError;
use crate::model::InstallConfig;

/// 設定ストレージポート
pub trait ConfigRepository {
    /// 設定を読込
    fn load(&self) -> Result<InstallConfig, DomainError>;

    /// 設定を保存
    fn save(&self, config: &InstallConfig) -> Result<(), DomainError>;

    /// 設定ファイルの存在確認
    fn exists(&self) -> bool;
}
