//! ガードの終了コード定義

/// 正常終了（プロセス許可・起動成功）
pub const SUCCESS: u8 = 0;
/// ユーザーがダイアログで拒否
pub const DENIED_BY_USER: u8 = 5;
/// ポリシーによりブロック（非対話セッション等）
pub const POLICY_BLOCKED: u8 = 10;
/// タイムアウト
pub const TIMEOUT: u8 = 15;
/// 管理者権限なし
pub const NO_PRIVILEGES: u8 = 21;
/// ダイアログ表示失敗（フェイルクローズ）
pub const DIALOG_FAILED: u8 = 22;
