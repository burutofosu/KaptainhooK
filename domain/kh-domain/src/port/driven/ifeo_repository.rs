//! IFEOリポジトリポート

use crate::error::DomainError;
use crate::model::{IfeoSnapshot, RegistryView};

/// IFEOレジストリ操作ポート
pub trait IfeoRepository {
    /// ターゲットのデバッガ値を取得
    fn get_debugger(&self, target: &str, view: RegistryView)
    -> Result<Option<String>, DomainError>;

    /// ターゲットのデバッガ値を設定
    fn set_debugger(&self, target: &str, view: RegistryView, path: &str)
    -> Result<(), DomainError>;

    /// ターゲットのデバッガ値を削除
    fn remove_debugger(&self, target: &str, view: RegistryView) -> Result<(), DomainError>;

    /// 指定ビューの全ターゲットを列挙
    /// (ターゲット名, デバッガパス) のリストを返す
    fn list_all_targets(&self, view: RegistryView) -> Result<Vec<(String, String)>, DomainError>;

    /// デバッガ値の存在確認
    fn has_debugger(&self, target: &str, view: RegistryView) -> Result<bool, DomainError> {
        Ok(self.get_debugger(target, view)?.is_some())
    }

    /// 両ビューの状態を一度にスナップショットとして取得。
    /// IFEO一時無効化時に現在の状態を保存するために使用。
    fn snapshot(&self, target: &str) -> Result<IfeoSnapshot, DomainError> {
        let mut snap = IfeoSnapshot::new(target);
        for view in RegistryView::all() {
            snap = snap.with_debugger(*view, self.get_debugger(target, *view)?);
        }
        Ok(snap)
    }

    /// スナップショットから両ビューの状態を復元。
    /// 各ビューを元の状態に個別に復元し、他製品のIFEOを壊さない。
    fn restore_snapshot(&self, snapshot: &IfeoSnapshot) -> Result<(), DomainError> {
        for view in RegistryView::all() {
            match snapshot.get(*view) {
                Some(debugger) => {
                    self.set_debugger(&snapshot.target, *view, debugger)?;
                }
                None => {
                    let _ = self.remove_debugger(&snapshot.target, *view);
                }
            }
        }
        Ok(())
    }
}
