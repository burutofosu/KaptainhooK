//! ガード用ユースケースポート

use crate::model::{GuardRequest, GuardResponse};

/// ガード用ユースケース（インターセプト処理）
pub trait GuardUseCase {
    /// ガードフローを実行
    ///
    /// 処理内容:
    /// 1. ポリシー評価
    /// 2. ユーザー確認（必要時）
    /// 3. IFEO一時無効化
    /// 4. プロセス起動
    /// 5. IFEO再有効化
    fn execute(&self, request: GuardRequest) -> GuardResponse;
}
