use super::{
    FrictionSettings, Language, NudgeMessage, ReactionConfig, Target, default_nudges, default_targets,
};
use crate::{DomainError, path::normalize_local_drive_absolute_path};
use std::collections::{BTreeMap, BTreeSet};

const DEFAULT_AUTO_RESTORE_SECONDS: u32 = 2;
const MAX_AUTO_RESTORE_SECONDS: u32 = 300;

/// ユーザー設定から導出されるガード設定。
#[derive(Debug, Clone)]
pub struct GuardConfig {
    pub targets: Vec<Target>,
    pub friction: FrictionSettings,
    pub nudge_messages: Vec<NudgeMessage>,
    pub auto_restore_seconds: u32,
}

impl GuardConfig {
    pub fn new(targets: Vec<Target>) -> Self {
        Self {
            targets,
            friction: FrictionSettings::default(),
            nudge_messages: default_nudges(),
            // Watchdog のタイムアウト（デフォルト 2 秒）
            auto_restore_seconds: DEFAULT_AUTO_RESTORE_SECONDS,
        }
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        self.friction.validate()?;
        if self.nudge_messages.is_empty() {
            return Err(DomainError::ValidationError(
                "nudge_messages must contain at least one entry".into(),
            ));
        }
        if self.targets.is_empty() {
            return Err(DomainError::ValidationError(
                "targets must not be empty".into(),
            ));
        }
        for msg in &self.nudge_messages {
            // コンストラクタ経由で不変条件を再検証
            let _ = NudgeMessage::new(msg.message_id().clone(), msg.text().to_string())?;
        }
        if self.auto_restore_seconds == 0 || self.auto_restore_seconds > MAX_AUTO_RESTORE_SECONDS {
            return Err(DomainError::ValidationError(format!(
                "auto_restore_seconds は 1-{} の範囲である必要があります (現在 {})",
                MAX_AUTO_RESTORE_SECONDS,
                self.auto_restore_seconds
            )));
        }
        for target in &self.targets {
            target.validate()?;
        }
        Ok(())
    }

    /// 正規化して重複を取り除く（exe 名を正規化してソート）。
    /// 同一 exe が複数回指定された場合は「最後に指定された enabled」を採用する。
    pub fn normalize(&mut self) {
        self.auto_restore_seconds = normalize_auto_restore_seconds(self.auto_restore_seconds);
        // 同じ exe が複数回指定された場合に「有効/無効が2件残る」状態は、
        // install/uninstall の順序依存や UI 表示の混乱を招くため、ここで一意化する。
        // 仕様: 末尾（最後に出てきた値）を採用。
        let mut map: BTreeMap<String, bool> = BTreeMap::new();
        for target in self.targets.drain(..) {
            let (exe_name, enabled) = target.into_parts();
            map.insert(exe_name, enabled);
        }
        self.targets = map
            .into_iter()
            .map(|(exe_name, enabled)| {
                Target::from_parts(exe_name, enabled).expect("normalized target should be valid")
            })
            .collect();
    }

    /// ターゲットが空の場合のみプリセットを補う。
    pub fn ensure_defaults(&mut self) {
        self.normalize();
        if self.targets.is_empty() {
            self.targets = default_targets();
            self.targets.sort_by(|a, b| a.exe_name().cmp(b.exe_name()));
        }
        if self.nudge_messages.is_empty() {
            self.nudge_messages = default_nudges();
        }
    }
}

impl Default for GuardConfig {
    fn default() -> Self {
        let mut cfg = Self::new(default_targets());
        cfg.normalize();
        cfg
    }
}

/// ガード動作のポリシー設定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyConfig {
    /// 非対話セッション（Session 0、リモートデスクトップ切断時等）での実行を許可するか
    pub allow_non_interactive: bool,
    /// ダイアログのタイムアウト秒数（0で無効）
    pub timeout_seconds: u32,
    /// 認証方式（摩擦UI or Windows Hello）
    pub auth_mode: AuthMode,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            allow_non_interactive: false, // デフォルトは拒否（安全側）
            timeout_seconds: 60,          // デフォルトは60秒でタイムアウト
            auth_mode: AuthMode::default(),
        }
    }
}

/// UI背景設定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackgroundConfig {
    /// 背景画像キー（例: "none", "k_hook"）
    pub image: String,
    /// 透明度（0-100）
    pub opacity: u8,
}

impl BackgroundConfig {
    pub fn normalize(&mut self) {
        if self.image.trim().is_empty() {
            self.image = "none".into();
        }
        if self.opacity > 100 {
            self.opacity = 100;
        }
    }
}

impl Default for BackgroundConfig {
    fn default() -> Self {
        Self {
            image: "Kaptain-hook.png".into(),
            opacity: 30,
        }
    }
}

/// 認証方式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// 摩擦UI（長押し/マウス移動）
    Friction,
    /// Windows Hello 認証
    Hello,
}

impl Default for AuthMode {
    fn default() -> Self {
        AuthMode::Friction
    }
}

impl AuthMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMode::Friction => "friction",
            AuthMode::Hello => "hello",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "hello" => Some(AuthMode::Hello),
            "friction" => Some(AuthMode::Friction),
            _ => None,
        }
    }
}

/// インストール設定（永続化対象）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallConfig {
    pub version: String,
    pub targets: Vec<Target>,
    pub friction: FrictionSettings,
    pub nudge_messages: Vec<NudgeMessage>,
    pub auto_restore_seconds: u32,
    /// 検索許可パス（ユーザー追加分）
    pub search_paths: Vec<String>,
    /// ポリシー設定
    pub policy: PolicyConfig,
    /// UI言語設定
    pub language: Language,
    /// 反応/通知ルール設定
    pub reaction: ReactionConfig,
    /// 背景設定
    pub background: BackgroundConfig,
}

impl Default for InstallConfig {
    fn default() -> Self {
        Self {
            version: "0.95.0".into(),
            targets: default_targets(),
            friction: FrictionSettings::default(),
            nudge_messages: default_nudges(),
            // Watchdog のタイムアウト（デフォルト 2 秒）
            auto_restore_seconds: DEFAULT_AUTO_RESTORE_SECONDS,
            search_paths: Vec::new(),
            policy: PolicyConfig::default(),
            language: Language::default(),
            reaction: ReactionConfig::default(),
            background: BackgroundConfig::default(),
        }
    }
}

impl InstallConfig {
    pub fn validate(&self) -> Result<(), DomainError> {
        self.friction.validate()?;
        self.reaction.validate()?;
        if self.nudge_messages.is_empty() {
            return Err(DomainError::ValidationError(
                "nudge_messages must not be empty".into(),
            ));
        }
        if self.targets.is_empty() {
            return Err(DomainError::ValidationError(
                "targets must not be empty".into(),
            ));
        }
        if self.auto_restore_seconds == 0 || self.auto_restore_seconds > MAX_AUTO_RESTORE_SECONDS {
            return Err(DomainError::ValidationError(format!(
                "auto_restore_seconds は 1-{} の範囲である必要があります (現在 {})",
                MAX_AUTO_RESTORE_SECONDS,
                self.auto_restore_seconds
            )));
        }
        if self.background.opacity > 100 {
            return Err(DomainError::ValidationError(format!(
                "background.opacity は 0-100 の範囲である必要があります (現在 {})",
                self.background.opacity
            )));
        }
        if self.background.image.trim().is_empty() {
            return Err(DomainError::ValidationError(
                "background.image must not be empty".into(),
            ));
        }
        for path in &self.search_paths {
            let trimmed = path.trim();
            if trimmed.is_empty() {
                return Err(DomainError::ValidationError(
                    "search_paths must not be empty".into(),
                ));
            }
            if normalize_local_drive_absolute_path(trimmed).is_none() {
                return Err(DomainError::ValidationError(format!(
                    "search_paths はローカルドライブの絶対パスである必要があります (例: C:\\Program Files\\Tool) (現在 {})",
                    trimmed
                )));
            }
        }
        for target in &self.targets {
            target.validate()?;
        }
        for msg in &self.nudge_messages {
            let _ = NudgeMessage::new(msg.message_id().clone(), msg.text().to_string())?;
        }
        Ok(())
    }

    pub fn normalize(&mut self) {
        self.auto_restore_seconds = normalize_auto_restore_seconds(self.auto_restore_seconds);
        let mut guard = GuardConfig {
            targets: self.targets.clone(),
            friction: self.friction,
            nudge_messages: self.nudge_messages.clone(),
            auto_restore_seconds: self.auto_restore_seconds,
        };
        guard.normalize();
        self.targets = guard.targets;
        self.nudge_messages = guard.nudge_messages;
        self.search_paths = normalize_search_paths(&self.search_paths);
        self.reaction.normalize();
        self.background.normalize();
    }
}

fn normalize_auto_restore_seconds(value: u32) -> u32 {
    // 0 は「即時復元」で begin→spawn→complete の競合を起こし得るため、
    // 設定が 0 / 範囲外の場合はデフォルト値に戻す。
    if value == 0 || value > MAX_AUTO_RESTORE_SECONDS {
        DEFAULT_AUTO_RESTORE_SECONDS
    } else {
        value
    }
}

fn normalize_search_paths(paths: &[String]) -> Vec<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    for raw in paths {
        let Some(normalized) = normalize_local_drive_absolute_path(raw) else {
            continue;
        };
        let key = normalized.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(normalized);
        }
    }
    out
}

/// ガード実行リクエスト/レスポンス（UI/サービス間の汎用データ）。
#[derive(Debug, Clone)]
pub struct GuardRequest {
    /// 元のターゲット（引数で渡された文字列）
    pub target: String,
    pub args: Vec<String>,
    /// 正規化済みターゲット名（exe名・小文字）
    pub normalized_target: String,
    pub session: super::SessionInfo,
    pub parent: ProcessInfo,
    pub grandparent: ProcessInfo,
}

/// プロセス情報（ログ用）
#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GuardResponse {
    pub allowed: bool,
    pub reason: Option<String>,
    pub emergency_used: bool,
    pub duration_ms: u128,
    pub exit_code: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_config_normalize_dedups_by_exe_last_wins() {
        let targets = vec![
            Target::new("cmd.exe", false).unwrap(),
            Target::new("cmd.exe", true).unwrap(),
            Target::new("powershell.exe", true).unwrap(),
        ];
        let mut cfg = GuardConfig::new(targets);
        cfg.normalize();
        assert_eq!(cfg.targets.len(), 2);
        let cmd = cfg
            .targets
            .iter()
            .find(|t| t.exe_name() == "cmd.exe")
            .expect("cmd.exe should remain");
        assert!(cmd.enabled(), "last setting should win");
    }

    #[test]
    fn guard_config_normalize_last_wins_can_disable() {
        let targets = vec![
            Target::new("cmd.exe", true).unwrap(),
            Target::new("cmd.exe", false).unwrap(),
        ];
        let mut cfg = GuardConfig::new(targets);
        cfg.normalize();
        assert_eq!(cfg.targets.len(), 1);
        assert!(!cfg.targets[0].enabled());
    }

    #[test]
    fn background_normalize_applies_defaults() {
        let mut config = BackgroundConfig {
            image: "   ".into(),
            opacity: 150,
        };
        config.normalize();
        assert_eq!(config.image, "none");
        assert_eq!(config.opacity, 100);
    }

    #[test]
    fn install_config_rejects_invalid_background_opacity() {
        let mut config = InstallConfig::default();
        config.background.opacity = 101;
        assert!(config.validate().is_err());
    }

    #[test]
    fn install_config_rejects_empty_background_image() {
        let mut config = InstallConfig::default();
        config.background.image = "   ".into();
        assert!(config.validate().is_err());
    }
    #[test]
    fn install_config_normalize_clamps_auto_restore_seconds_zero_to_default() {
        let mut cfg = InstallConfig::default();
        cfg.auto_restore_seconds = 0;
        cfg.normalize();
        assert_eq!(cfg.auto_restore_seconds, DEFAULT_AUTO_RESTORE_SECONDS);
    }

    #[test]
    fn install_config_normalize_filters_unc_search_paths() {
        let mut cfg = InstallConfig::default();
        cfg.search_paths = vec![
            r"\\server\\share".to_string(),
            r"\\?\UNC\server\share".to_string(),
            r"C:\Tools".to_string(),
            r"c:\tools\".to_string(),
        ];
        cfg.normalize();
        assert_eq!(cfg.search_paths.len(), 1);
        assert!(cfg.search_paths[0].to_ascii_lowercase().starts_with("c:\\"));
    }

}
