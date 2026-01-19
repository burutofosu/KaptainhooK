//! 駆動ポート（出力インターフェース）。
//!
//! ドメインが外部に求める機能を定義する。
//! インフラ層のアダプタが実装する。

mod backup_store;
mod auth_prompt;
mod clock;
mod config_repository;
mod ifeo_repository;
mod lease_store;
mod log_writer;
mod privileged_launcher;
mod random_source;
mod registry_port;
mod restore_kicker;
mod signature_verifier;
mod task_scheduler;
mod target_path_resolver;
mod targets_repository;
mod user_notifier;

pub use backup_store::*;
pub use auth_prompt::*;
pub use clock::*;
pub use config_repository::*;
pub use ifeo_repository::*;
pub use lease_store::*;
pub use log_writer::*;
pub use privileged_launcher::*;
pub use random_source::*;
pub use registry_port::*;
pub use restore_kicker::*;
pub use signature_verifier::*;
pub use task_scheduler::*;
pub use target_path_resolver::*;
pub use targets_repository::*;
pub use user_notifier::*;
