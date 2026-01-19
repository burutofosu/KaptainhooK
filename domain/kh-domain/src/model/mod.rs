//! ドメインモデル
//!
//! 標準ライブラリのみ使用（外部依存なし）
//! 値オブジェクト、エンティティ、設定型を定義

mod config;     // インストール設定、ガード設定
pub mod exit_codes; // ガード終了コード
mod friction;   // フリクション（摩擦）設定 - ユーザー確認UI用
mod guard_notification; // ガード通知メッセージ
mod language;   // 言語設定（日本語/英語）
mod nudge;      // ナッジメッセージ（啓発的メッセージ）
mod policy;     // ポリシー設定
mod prompt;     // プロンプトUI用コンテキスト/結果
mod reaction;   // 反応/通知ルール
mod session;    // セッション情報
mod target;     // 監視対象（powershell.exe等）
mod threat;     // 脅威評価（署名状態、パスヒント）

pub use config::*;
pub use friction::*;
pub use guard_notification::*;
pub use language::*;
pub use nudge::*;
pub use policy::*;
pub use prompt::*;
pub use reaction::*;
pub use session::*;
pub use target::*;
pub use threat::*;
