//! KaptainhooK ガードUIライブラリ
//!
//! LOLBin実行確認用のフリクションダイアログを提供。
//! ユーザーに意図確認（ホールド/マウス移動）を要求して誤操作を防ぐ。

pub mod error;
pub mod dialog; // ダイアログ実装
pub mod hello; // Windows Hello対応

pub use dialog::{PromptContext, PromptOutcome, show_prompt};
pub use hello::verify_hello;
pub use error::Result;
