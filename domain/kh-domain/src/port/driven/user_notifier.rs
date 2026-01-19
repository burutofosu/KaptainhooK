//! ガードフロー向けユーザー通知ポート

use crate::model::GuardNotification;

/// UI通知と確認
pub trait UserNotifier {
    fn show_error(&self, msg: &str);
    fn show_warn(&self, msg: &str);
    fn show_info(&self, msg: &str);

    /// 翻訳用メッセージ（既定は英語のフォールバックを表示）
    fn show_error_message(&self, msg: &GuardNotification) {
        self.show_error(&msg.fallback_message());
    }
    fn show_warn_message(&self, msg: &GuardNotification) {
        self.show_warn(&msg.fallback_message());
    }
    fn show_info_message(&self, msg: &GuardNotification) {
        self.show_info(&msg.fallback_message());
    }

    /// サービス再起動を確認（対話時のみ）
    fn prompt_service_restart(&self) -> bool;

    /// サービス再起動ツールを実行（要求時）
    fn run_service_restart_tool(&self) -> Result<(), String>;
}
