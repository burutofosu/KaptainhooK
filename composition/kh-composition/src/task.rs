//! タスクスケジューラのアダプタ再公開。
//!
//! apps/* からの直接依存を避けるための再公開。

pub use kh_adapter_task::TaskSchedulerAdapter;
pub use kh_adapter_task::ensure_task_runnable_by_authenticated_users;
pub use kh_adapter_task::TaskInfo;
pub use kh_adapter_task::{DEFAULT_RESTORE_TASK_NAME, RestoreTaskRunner};

#[cfg(windows)]
pub use kh_adapter_task::query_task_details;
