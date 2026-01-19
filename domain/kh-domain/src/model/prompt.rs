//! ガード確認用のプロンプト情報と結果

use crate::model::Language;

/// プロンプトダイアログの文脈（UI非依存）
#[derive(Debug, Clone)]
pub struct PromptContext {
    pub target: String,
    pub args: Vec<String>,
    pub resolved_path: Option<String>,
    pub username: String,
    pub session_name: String,
    pub nudge_text: Option<String>,
    pub timeout_seconds: Option<u32>,
    pub language: Language,
}

/// プロンプト結果
#[derive(Debug, Clone)]
pub struct PromptOutcome {
    pub allowed: bool,
    pub reason: String,
    pub emergency: bool,
}
