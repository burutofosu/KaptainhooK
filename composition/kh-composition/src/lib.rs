//! kh-composition: 各実行ファイル向けのランタイムを組み立てるコンポジションルート。
//! ドメイン／アプリケーション／各種アダプタをここで配線し、apps/* はこのクレートだけに依存する。

pub mod cli;
pub mod error;
pub mod guard;
pub mod paths;
pub mod task;
pub mod service;
pub mod restore;
pub mod targets;
pub mod system;

// apps/* が内側レイヤーの型に触れる必要がある場合は、ここから辿れるようにする。
// （apps が kh-domain等を直接依存しないため）
pub use kh_app as app;
pub use kh_domain as domain;
pub use kh_engine as engine;

// 利便性のための再エクスポート（appsはアダプタクレートではなくこれらを使用）
pub use kh_app::AppService;
pub use kh_domain::model::{FrictionSettings, InstallConfig};
pub use kh_domain::port::driven::{GuardLogRecord, OperationLogRecord};

// ガード用UIタイプ再エクスポート
pub use kh_ui_guard::PromptContext;
pub use kh_ui_guard as ui_guard;
pub use kh_ui_common as ui_common;

// 親プロセス情報タイプ再エクスポート
pub use guard::{ParentProcessInfo, get_grandparent_process_info, get_parent_process_info};
