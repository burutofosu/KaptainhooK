//! タスクスケジューラ用アダプタポート（登録/実行APIをラップ）

use crate::error::DomainError;

pub trait TaskScheduler {
    /// タスク作成/登録（冪等）
    fn create_task(&self, task_name: &str, exe_path: &str) -> Result<(), DomainError>;

    /// タスク削除
    fn delete_task(&self, task_name: &str) -> Result<(), DomainError>;

    /// タスク存在確認
    fn task_exists(&self, task_name: &str) -> Result<bool, DomainError>;

    /// タスクを即時実行
    fn run_task(&self, task_name: &str) -> Result<(), DomainError>;
}
