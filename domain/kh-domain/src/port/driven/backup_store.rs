//! バックアップストアポート

use crate::error::DomainError;
use crate::model::RegistryView;

/// IFEO登録のバックアップエントリ
#[derive(Debug, Clone)]
pub struct BackupEntry {
    /// ターゲットexe名
    pub target: String,
    /// レジストリビュー
    pub view: RegistryView,
    /// 元のデバッガ値（なければNone）
    pub original_debugger: Option<String>,
    /// 設定したデバッガ値
    pub our_debugger: String,
    /// ISO 8601タイムスタンプ
    pub timestamp: String,
}

/// IFEOバックアップ用ストアポート
pub trait BackupStore {
    /// エントリを保存
    fn save_entry(&self, entry: &BackupEntry) -> Result<(), DomainError>;

    /// エントリを読込
    fn load_entry(
        &self,
        target: &str,
        view: RegistryView,
    ) -> Result<Option<BackupEntry>, DomainError>;

    /// エントリを削除
    fn remove_entry(&self, target: &str, view: RegistryView) -> Result<(), DomainError>;

    /// 全エントリを列挙
    fn list_entries(&self) -> Result<Vec<BackupEntry>, DomainError>;

    /// 整合性を検証（読み出し可能か確認）
    fn verify_integrity(&self) -> Result<bool, DomainError>;

    /// 全エントリをクリア
    fn clear(&self) -> Result<(), DomainError>;
}
