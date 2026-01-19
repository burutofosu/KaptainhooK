//! 時刻・入力トラッキングポート

/// 時刻ポート
pub trait Clock {
    /// エポックからのミリ秒を取得
    fn now_ms(&self) -> u64;

    /// ISO 8601形式のタイムスタンプを取得
    fn now_iso8601(&self) -> String;
}

/// マウストラッカーポート
pub trait MouseTracker {
    /// 現在のマウス座標 (x, y) を取得
    fn position(&self) -> (i32, i32);
}

/// キーボードトラッカーポート
pub trait KeyboardTracker {
    /// Ctrl+Shift+Alt同時押し中か
    fn is_emergency_combo_held(&self) -> bool;
}
