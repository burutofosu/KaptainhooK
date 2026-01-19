//! 認証プロンプトの駆動ポート（フリクション／Windows Hello）

use crate::error::DomainError;
use crate::model::{FrictionSettings, PromptContext, PromptOutcome};

/// ユーザー確認プロンプトのアダプタ
pub trait AuthPrompt {
    fn show_friction(
        &self,
        settings: &FrictionSettings,
        ctx: &PromptContext,
    ) -> Result<PromptOutcome, DomainError>;

    fn verify_hello(&self, ctx: &PromptContext) -> Result<PromptOutcome, DomainError>;
}
