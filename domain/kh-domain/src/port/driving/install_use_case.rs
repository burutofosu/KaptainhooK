//! インストール用ユースケースポート

use crate::error::DomainError;
use crate::model::{ConflictInfo, InstallConfig, Target, TargetStatus};

/// インストール要求
#[derive(Debug, Clone)]
pub struct InstallRequest {
    /// 適用する設定
    pub config: InstallConfig,
    /// ブートストラップ実行ファイルのパス
    pub bootstrap_path: String,
    /// 競合時の処理
    pub conflict_resolution: ConflictResolution,
}

/// インストール時の競合処理
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictResolution {
    /// 競合対象をスキップ
    #[default]
    Skip,
    /// 既存デバッガを上書き
    Overwrite,
    /// 競合があれば中止
    Abort,
}

/// インストール結果
#[derive(Debug, Clone)]
pub struct InstallResult {
    /// 登録成功した対象
    pub succeeded: Vec<String>,
    /// 失敗した対象と理由
    pub failed: Vec<(String, String)>,
    /// スキップした対象（競合）
    pub skipped: Vec<String>,
}

impl InstallResult {
    /// すべて成功したか
    pub fn is_success(&self) -> bool {
        self.failed.is_empty()
    }

    /// 登録が1件以上あるか
    pub fn any_registered(&self) -> bool {
        !self.succeeded.is_empty()
    }
}

/// 状態レスポンス
#[derive(Debug, Clone)]
pub struct StatusResponse {
    /// 対象ごとの状態
    pub targets: Vec<(Target, TargetStatus)>,
    /// ブートストラップパス（取得できる場合）
    pub bootstrap_path: Option<String>,
}

/// インストール用ユースケース（インストールと状態取得）
pub trait InstallUseCase {
    /// IFEOフックをインストール
    fn install(&self, request: InstallRequest) -> Result<InstallResult, DomainError>;

    /// IFEOフックをアンインストール
    fn uninstall(&self) -> Result<InstallResult, DomainError>;

    /// IFEOフックを全削除（強制）
    fn cleanup(&self) -> Result<InstallResult, DomainError>;

    /// 現在の状態を取得
    fn get_status(&self) -> Result<StatusResponse, DomainError>;

    /// 競合を検出
    fn detect_conflicts(&self) -> Result<Vec<ConflictInfo>, DomainError>;
}
