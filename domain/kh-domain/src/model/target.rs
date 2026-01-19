use crate::DomainError;

/// 監視対象となる実行ファイル。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target {
    exe_name: String,
    enabled: bool,
}

impl Target {
    /// 作成時に正規化とバリデーションを実施する。
    pub fn new<S: Into<String>>(exe_name: S, enabled: bool) -> Result<Self, DomainError> {
        let raw: String = exe_name.into();
        if raw.contains('\0') {
            return Err(DomainError::ValidationError(
                "ターゲットにNUL文字を含めることはできません".into(),
            ));
        }
        let exe_name = normalize_exe_name(raw);
        validate_exe_name(&exe_name)?;
        Ok(Self { exe_name, enabled })
    }

    /// `.exe` で終わるかなどのチェックを行う。
    pub fn validate(&self) -> Result<(), DomainError> {
        validate_exe_name(&self.exe_name)
    }

    /// exe 名を取得する。
    pub fn exe_name(&self) -> &str {
        &self.exe_name
    }

    /// 有効かどうか。
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// 有効/無効を更新する。
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// 有効にするショートカット。
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// 無効にするショートカット。
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// 所有するデータを取り出す。
    pub fn into_parts(self) -> (String, bool) {
        (self.exe_name, self.enabled)
    }

    /// 既存データから構築するためのヘルパー。
    pub fn from_parts<S: Into<String>>(exe_name: S, enabled: bool) -> Result<Self, DomainError> {
        Target::new(exe_name, enabled)
    }
}

/// exe名の入力揺れを吸収して正規化する
/// - 前後の `"` を除去
/// - パス入力なら file name に縮退
/// - 小文字化
pub fn normalize_exe_name<S: Into<String>>(name: S) -> String {
    let raw: String = name.into();
    let trimmed = raw.trim().trim_matches('"');

    let base = trimmed
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(trimmed);

    base.to_ascii_lowercase()
}

fn validate_exe_name(name: &str) -> Result<(), DomainError> {
    if name.contains('\0') {
        return Err(DomainError::ValidationError(
            "ターゲットにNUL文字を含めることはできません".into(),
        ));
    }
    if !name.ends_with(".exe") {
        return Err(DomainError::ValidationError(format!(
            "ターゲット '{}' は .exe で終わる必要があります",
            name
        )));
    }
    if name.contains('\\') || name.contains('/') {
        return Err(DomainError::ValidationError(format!(
            "ターゲット '{}' にパス区切り文字を含めることはできません",
            name
        )));
    }
    Ok(())
}

/// `.exe` で終わることを確認するヘルパー（静的利用用）。
impl Target {
    pub fn validate_name(name: &str) -> Result<(), DomainError> {
        validate_exe_name(name)
    }
}

/// 設計書に記載された既定ターゲット 15 種。
pub fn default_targets() -> Vec<Target> {
    const PRESET: [(&str, bool); 15] = [
        ("powershell.exe", true),
        ("pwsh.exe", true),
        ("cmd.exe", true),
        ("wscript.exe", true),
        ("cscript.exe", true),
        ("mshta.exe", true),
        ("rundll32.exe", true),
        ("regsvr32.exe", true),
        ("certutil.exe", true),
        ("bitsadmin.exe", true),
        ("wmic.exe", true),
        ("installutil.exe", true),
        ("msdt.exe", true),
        ("powershell_ise.exe", true),
        ("wt.exe", false),
    ];

    PRESET
        .iter()
        .map(|(name, enabled)| Target::new(*name, *enabled).expect("preset target should be valid"))
        .collect()
}

/// レジストリのビュー（32/64bit）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistryView {
    Bit64,
    Bit32,
}

impl RegistryView {
    /// 全レジストリビューを返す（64bit/32bit WOW6432）
    pub fn all() -> &'static [RegistryView] {
        &[RegistryView::Bit64, RegistryView::Bit32]
    }
}

/// ターゲットの現在状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStatus {
    Registered,
    NotRegistered,
    Conflict,
}

/// IFEO 競合情報（必要最小限）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictInfo {
    pub target: Target,
    pub view: RegistryView,
    pub reason: String,
}

/// 外部呼び出し向けのヘルパー
pub fn normalize_target(name: &str) -> String {
    normalize_exe_name(name)
}

// ============================================================================
// IFEOスナップショット - 両ビューの状態を保持する値オブジェクト
// ============================================================================

/// 両ビュー（64bit/32bit）のデバッガ状態を保持する値オブジェクト。
/// IFEO一時無効化時の復元に使用し、各ビューを個別に復元できるようにする。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfeoSnapshot {
    /// ターゲット実行ファイル名
    pub target: String,
    /// 64bit ビューのデバッガ値（None = 未登録）
    pub bit64: Option<String>,
    /// 32bit ビューのデバッガ値（None = 未登録）
    pub bit32: Option<String>,
}

impl IfeoSnapshot {
    /// 空のスナップショットを作成
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            bit64: None,
            bit32: None,
        }
    }

    /// 指定ビューにデバッガ値を設定（ビルダーパターン）
    pub fn with_debugger(mut self, view: RegistryView, debugger: Option<String>) -> Self {
        match view {
            RegistryView::Bit64 => self.bit64 = debugger,
            RegistryView::Bit32 => self.bit32 = debugger,
        }
        self
    }

    /// 指定ビューのデバッガ値を取得
    pub fn get(&self, view: RegistryView) -> Option<&str> {
        match view {
            RegistryView::Bit64 => self.bit64.as_deref(),
            RegistryView::Bit32 => self.bit32.as_deref(),
        }
    }

    /// 両ビューとも未登録かどうか
    pub fn is_empty(&self) -> bool {
        self.bit64.is_none() && self.bit32.is_none()
    }

    /// いずれかのビューに登録があるかどうか
    pub fn has_any(&self) -> bool {
        !self.is_empty()
    }
}


#[cfg(test)]
mod target_normalize_tests {
    use super::*;

    #[test]
    fn normalize_exe_name_accepts_quotes_and_path() {
        assert_eq!(normalize_exe_name("cmd.exe"), "cmd.exe");
        assert_eq!(normalize_exe_name("\"cmd.exe\""), "cmd.exe");
        assert_eq!(
            normalize_exe_name(r"C:\Windows\System32\cmd.exe"),
            "cmd.exe"
        );
    }

    #[test]
    fn validate_rejects_nul() {
        assert!(Target::new("cmd.exe\0evil", true).is_err());
        assert!(Target::validate_name("cmd.exe\0evil").is_err());
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    #[test]
    fn new_snapshot_is_empty() {
        let snap = IfeoSnapshot::new("test.exe");
        assert!(snap.is_empty());
        assert!(!snap.has_any());
        assert_eq!(snap.get(RegistryView::Bit64), None);
        assert_eq!(snap.get(RegistryView::Bit32), None);
    }

    #[test]
    fn with_debugger_sets_value() {
        let snap = IfeoSnapshot::new("test.exe")
            .with_debugger(RegistryView::Bit64, Some("dbg64.exe".into()))
            .with_debugger(RegistryView::Bit32, Some("dbg32.exe".into()));

        assert!(!snap.is_empty());
        assert!(snap.has_any());
        assert_eq!(snap.get(RegistryView::Bit64), Some("dbg64.exe"));
        assert_eq!(snap.get(RegistryView::Bit32), Some("dbg32.exe"));
    }

    #[test]
    fn partial_snapshot() {
        let snap = IfeoSnapshot::new("test.exe")
            .with_debugger(RegistryView::Bit64, Some("dbg.exe".into()));

        assert!(!snap.is_empty());
        assert_eq!(snap.get(RegistryView::Bit64), Some("dbg.exe"));
        assert_eq!(snap.get(RegistryView::Bit32), None);
    }
}
