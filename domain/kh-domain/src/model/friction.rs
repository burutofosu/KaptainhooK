//! フリクション（摩擦）設定
//!
//! ユーザー確認ダイアログでの「意図確認」操作を定義。
//! 誤クリック防止のためのホールド要求やマウス移動要求を設定。

use crate::DomainError;

/// フリクション設定値オブジェクト
///
/// ユーザーに「意図的な操作」を要求することで、
/// マルウェアによる自動クリックや誤操作を防ぐ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrictionSettings {
    require_hold: bool,               // ボタン長押しを要求するか
    hold_ms: u32,                     // 長押し必要時間(ミリ秒)
    require_pointer_movement: bool,   // マウス移動を要求するか
    pointer_move_threshold_px: u32,   // マウス移動必要距離(ピクセル)
    emergency_bypass: bool,           // 緊急バイパス機能の有効化
    emergency_hold_ms: u32,           // 緊急バイパス発動に必要なホールド時間
}

impl Default for FrictionSettings {
    /// デフォルト設定: 1.5秒ホールド、80px移動、5秒緊急バイパス
    fn default() -> Self {
        Self::new(true, 1_500, true, 80, true, 5_000)
            .expect("default friction settings should be valid")
    }
}

impl FrictionSettings {
    /// 新しいフリクション設定を作成（バリデーション付き）
    pub fn new(
        require_hold: bool,
        hold_ms: u32,
        require_pointer_movement: bool,
        pointer_move_threshold_px: u32,
        emergency_bypass: bool,
        emergency_hold_ms: u32,
    ) -> Result<Self, DomainError> {
        let settings = Self {
            require_hold,
            hold_ms,
            require_pointer_movement,
            pointer_move_threshold_px,
            emergency_bypass,
            emergency_hold_ms,
        };
        settings.validate()?;
        Ok(settings)
    }

    /// 設定値の範囲チェック
    pub fn validate(&self) -> Result<(), DomainError> {
        ensure_range(self.hold_ms, 500, 30_000, "hold_ms")?;
        ensure_range(
            self.pointer_move_threshold_px,
            10,
            500,
            "pointer_move_threshold_px",
        )?;
        ensure_range(self.emergency_hold_ms, 1_000, 10_000, "emergency_hold_ms")?;
        Ok(())
    }

    /// ボタン長押しを要求するか
    pub fn require_hold(&self) -> bool {
        self.require_hold
    }

    /// 長押し必要時間(ミリ秒)
    pub fn hold_ms(&self) -> u32 {
        self.hold_ms
    }

    /// マウス移動を要求するか
    pub fn require_pointer_movement(&self) -> bool {
        self.require_pointer_movement
    }

    /// マウス移動必要距離(ピクセル)
    pub fn pointer_move_threshold_px(&self) -> u32 {
        self.pointer_move_threshold_px
    }

    /// 緊急バイパス機能が有効か
    pub fn emergency_bypass(&self) -> bool {
        self.emergency_bypass
    }

    /// 緊急バイパス発動に必要なホールド時間(ミリ秒)
    pub fn emergency_hold_ms(&self) -> u32 {
        self.emergency_hold_ms
    }
}

/// 値が指定範囲内かチェックするヘルパー
fn ensure_range(value: u32, min: u32, max: u32, field: &str) -> Result<(), DomainError> {
    if value < min || value > max {
        return Err(DomainError::ValidationError(format!(
            "{} は {}-{} の範囲内である必要があります (現在 {})",
            field, min, max, value
        )));
    }
    Ok(())
}
