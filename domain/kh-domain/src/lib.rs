//! KaptainhooK ドメイン層
//!
//! ビジネスロジックの中核。外部依存ゼロでRust標準ライブラリのみ使用。
//! ヘキサゴナルアーキテクチャの最内層。

pub mod error;   // ドメインエラー定義
pub mod model;   // ドメインモデル（値オブジェクト、エンティティ）
pub mod path;    // パス正規化ユーティリティ
pub mod port;    // ポート（driving/driven）
pub mod service; // ドメインサービス

pub use error::DomainError; // エラー型を再エクスポート
