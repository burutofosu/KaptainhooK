//! ログライターポート

use crate::error::DomainError;

/// ガードログレコード
#[derive(Debug, Clone)]
pub struct GuardLogRecord {
    /// ISO8601タイムスタンプ
    pub timestamp: String,
    /// 正規化されたターゲット名
    pub normalized_target: String,
    /// コマンドライン引数
    pub args: Vec<String>,
    /// ユーザー名
    pub username: String,
    /// セッション情報
    pub session: String,
    /// 判定理由
    pub reason: String,
    /// 実行アクション（allowed/blocked等）
    pub action: String,
    /// 反応種別（log/notify/friction）
    pub reaction: String,
    /// 起動元カテゴリ
    pub origin_categories: Vec<String>,
    /// 許可されたか
    pub allowed: bool,
    /// 緊急バイパス使用有無
    pub emergency: bool,
    /// 表示されたナッジメッセージID
    pub nudge_message_id: Option<String>,
    /// 子プロセス終了コード
    pub exit_code: Option<i32>,
    /// 処理時間（ミリ秒）
    pub duration_ms: u128,
    /// 有効ターゲット数
    pub enabled_targets: u32,
    /// 親プロセスPID
    pub parent_pid: Option<u32>,
    /// 親プロセス名
    pub parent_process: Option<String>,
    /// 親プロセスパス
    pub parent_path: Option<String>,
    /// 祖父プロセスPID
    pub grandparent_pid: Option<u32>,
    /// 祖父プロセス名
    pub grandparent_process: Option<String>,
    /// 祖父プロセスパス
    pub grandparent_path: Option<String>,
}

/// 操作ログレコード
#[derive(Debug, Clone)]
pub struct OperationLogRecord {
    /// 操作種別（install/uninstall等）
    pub operation: String,
    /// 成功有無
    pub success: bool,
    /// 詳細またはエラーメッセージ
    pub details: String,
    /// 対象ターゲット
    pub targets: Vec<String>,
}

/// ログライターポート
pub trait LogWriter {
    /// ガードログを書込
    fn write_guard_log(&self, record: &GuardLogRecord) -> Result<(), DomainError>;

    /// 操作ログを書込
    fn write_operation_log(&self, record: &OperationLogRecord) -> Result<(), DomainError>;

    /// 必要に応じてローテーション
    fn rotate_if_needed(&self) -> Result<(), DomainError>;
}
