//! 管理用ユースケースポート

use crate::error::DomainError;
use crate::model::InstallConfig;

/// ヘルスチェック結果
#[derive(Debug, Clone)]
pub struct DoctorResult {
    /// 実行したチェック一覧
    pub checks: Vec<DoctorCheck>,
    /// 全体の健全性
    pub healthy: bool,
}

/// 個別チェック
#[derive(Debug, Clone)]
pub struct DoctorCheck {
    /// チェック名
    pub name: String,
    /// 合否
    pub passed: bool,
    /// 詳細またはエラーメッセージ
    pub message: String,
}

/// 管理用ユースケース（管理操作）
pub trait AdminUseCase {
    /// 現在の設定を読み込む
    fn load_config(&self) -> Result<InstallConfig, DomainError>;

    /// 設定を保存する
    fn save_config(&self, config: &InstallConfig) -> Result<(), DomainError>;

    /// 自己診断を実行
    fn doctor(&self) -> Result<DoctorResult, DomainError>;

    /// 監査ログを取得
    fn audit(&self, limit: usize) -> Result<Vec<String>, DomainError>;
}
