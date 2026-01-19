//! ファイルシステムアダプター（設定/バックアップ/ログ永続化）
//! JSONファイル＋JSONLログで実装。後でローテーション等を拡張可能。
use kh_domain::error::DomainError;
use kh_domain::model::{
    AuthMode, BackgroundConfig, ForcedCategory, FrictionSettings, InstallConfig, Language, MessageId,
    NudgeMessage, PolicyConfig, ReactionConfig, ReactionKind, ReactionPreset, ReactionRule,
    RegistryView, Target, TargetReaction, default_nudges,
};
use kh_domain::port::driven::{
    BackupEntry, BackupStore, ConfigRepository, GuardLogRecord, LogWriter, OperationLogRecord,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct FsAdapter {
    guard_log_path: PathBuf,
    op_log_path: PathBuf,
    config_path: PathBuf,
    backup_path: PathBuf,
    max_log_bytes: u64,
}

#[cfg(windows)]
const LOG_MUTEX_NAME: &str = r"Global\KaptainhooKLogMutex";
#[cfg(windows)]
const LOG_MUTEX_NAME_LOCAL: &str = r"Local\KaptainhooKLogMutex";

#[cfg(windows)]
struct LogMutexGuard {
    handle: windows::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl Drop for LogMutexGuard {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::ReleaseMutex;
        unsafe {
            let _ = ReleaseMutex(self.handle);
            let _ = CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
fn try_acquire_log_mutex(timeout_ms: u32) -> Option<LogMutexGuard> {
    use windows::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
    use windows::core::PCWSTR;

    fn to_wide(s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }

    enum AcquireError {
        CreateFailed,
        WaitTimeout,
        WaitFailed,
    }

    fn acquire_named_mutex(name: &str, timeout_ms: u32) -> Result<LogMutexGuard, AcquireError> {
        let name = to_wide(name);
        let handle = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) }
            .map_err(|_| AcquireError::CreateFailed)?;
        let wait = unsafe { WaitForSingleObject(handle, timeout_ms) };
        match wait {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(LogMutexGuard { handle }),
            WAIT_TIMEOUT => {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(handle);
                }
                Err(AcquireError::WaitTimeout)
            }
            _ => {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(handle);
                }
                Err(AcquireError::WaitFailed)
            }
        }
    }

    match acquire_named_mutex(LOG_MUTEX_NAME, timeout_ms) {
        Ok(guard) => Some(guard),
        Err(AcquireError::CreateFailed) => {
            acquire_named_mutex(LOG_MUTEX_NAME_LOCAL, timeout_ms).ok()
        }
        Err(_) => None,
    }
}

#[cfg(not(windows))]
struct LogMutexGuard;

#[cfg(not(windows))]
fn try_acquire_log_mutex(_timeout_ms: u32) -> Option<LogMutexGuard> {
    Some(LogMutexGuard)
}

impl FsAdapter {
    /// 指定ルートディレクトリでアダプターを作成。ファイルは遅延作成。
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        let config_dir = root.join("config");
        let log_dir = root.join("logs");
        let backup_dir = root.join("backups");
        Self {
            guard_log_path: log_dir.join("guard.log.jsonl"),
            op_log_path: log_dir.join("operation.log.jsonl"),
            config_path: config_dir.join("config.json"),
            backup_path: backup_dir.join("backups.json"),
            max_log_bytes: 5 * 1024 * 1024, // 5MB上限
        }
    }

    /// システム領域とユーザー領域を分けて作成する（ガードログのみユーザー側）
    pub fn new_with_user_logs(system_root: impl AsRef<Path>, user_root: impl AsRef<Path>) -> Self {
        let system_root = system_root.as_ref().to_path_buf();
        let user_root = user_root.as_ref().to_path_buf();

        let config_dir = system_root.join("config");
        let system_log_dir = system_root.join("logs");
        let user_log_dir = user_root.join("logs");
        let backup_dir = system_root.join("backups");

        Self {
            guard_log_path: user_log_dir.join("guard.log.jsonl"),
            op_log_path: system_log_dir.join("operation.log.jsonl"),
            config_path: config_dir.join("config.json"),
            backup_path: backup_dir.join("backups.json"),
            max_log_bytes: 5 * 1024 * 1024, // 5MB上限
        }
    }


    fn ensure_parent_dir(&self, path: &Path) -> Result<(), DomainError> {
        let Some(dir) = path.parent() else {
            return Ok(());
        };
        fs::create_dir_all(dir)
            .map_err(|e| DomainError::IoError(format!("create_dir_all: {e}")))
    }

    fn write_atomic(&self, path: &Path, data: &[u8]) -> Result<(), DomainError> {
        self.ensure_parent_dir(path)?;
        let suffix = unique_suffix();
        let tmp_path = path.with_extension(format!("tmp.{suffix}"));
        {
            let mut f = fs::File::create(&tmp_path)
                .map_err(|e| DomainError::IoError(format!("create temp file: {e}")))?;
            f.write_all(data)
                .map_err(|e| DomainError::IoError(format!("write temp file: {e}")))?;
            let _ = f.sync_all();
        }
        if path.exists() {
            #[cfg(windows)]
            {
                if let Err(e) = replace_file(&tmp_path, path) {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(e);
                }
                return Ok(());
            }
        }
        fs::rename(&tmp_path, path)
            .map_err(|e| DomainError::IoError(format!("rename temp file: {e}")))?;
        Ok(())
    }
}

impl ConfigRepository for FsAdapter {
    fn load(&self) -> Result<InstallConfig, DomainError> {
        let mut buf = String::new();
        let mut f = fs::File::open(&self.config_path)
            .map_err(|e| DomainError::ConfigLoadFailed(format!("open config: {e}")))?;
        f.read_to_string(&mut buf)
            .map_err(|e| DomainError::ConfigLoadFailed(format!("read config: {e}")))?;
        let dto: ConfigDto =
            serde_json::from_str(&buf).map_err(|e| DomainError::ConfigLoadFailed(e.to_string()))?;
        InstallConfig::try_from(dto).map_err(|e| DomainError::ConfigLoadFailed(e.to_string()))
    }

    fn save(&self, config: &InstallConfig) -> Result<(), DomainError> {
        let dto = ConfigDto::from(config);
        let data = serde_json::to_string_pretty(&dto)
            .map_err(|e| DomainError::IoError(format!("serialize config: {e}")))?;
        self.write_atomic(&self.config_path, data.as_bytes())
            .map_err(|e| DomainError::IoError(format!("write config: {e}")))?;
        Ok(())
    }

    fn exists(&self) -> bool {
        self.config_path.exists()
    }
}

impl BackupStore for FsAdapter {
    fn save_entry(&self, entry: &BackupEntry) -> Result<(), DomainError> {
        let mut list = self.list_entries()?;
        list.retain(|e| !(e.target == entry.target && e.view == entry.view));
        list.push(entry.clone());
        self.write_backups(&list)
    }

    fn load_entry(
        &self,
        target: &str,
        view: RegistryView,
    ) -> Result<Option<BackupEntry>, DomainError> {
        let list = self.list_entries()?;
        Ok(list
            .into_iter()
            .find(|e| e.target == target && e.view == view))
    }

    fn remove_entry(&self, target: &str, view: RegistryView) -> Result<(), DomainError> {
        let mut list = self.list_entries()?;
        list.retain(|e| !(e.target == target && e.view == view));
        self.write_backups(&list)
    }

    fn list_entries(&self) -> Result<Vec<BackupEntry>, DomainError> {
        if !self.backup_path.exists() {
            return Ok(vec![]);
        }
        let data = fs::read_to_string(&self.backup_path)
            .map_err(|e| DomainError::IoError(format!("read backups: {e}")))?;
        let dtos: Vec<BackupDto> =
            serde_json::from_str(&data).map_err(|e| DomainError::IoError(e.to_string()))?;
        Ok(dtos.into_iter().map(BackupEntry::from).collect())
    }

    fn verify_integrity(&self) -> Result<bool, DomainError> {
        self.list_entries().map(|_| true)
    }

    fn clear(&self) -> Result<(), DomainError> {
        if self.backup_path.exists() {
            fs::remove_file(&self.backup_path)
                .map_err(|e| DomainError::IoError(format!("remove backups: {e}")))?;
        }
        Ok(())
    }
}

impl LogWriter for FsAdapter {
    fn write_guard_log(&self, record: &GuardLogRecord) -> Result<(), DomainError> {
        let value = serde_json::json!({
            "timestamp": record.timestamp,
            "normalized_target": record.normalized_target,
            "args": record.args,
            "username": record.username,
            "session": record.session,
            "reason": record.reason,
            "action": record.action,
            "reaction": record.reaction,
            "origin_categories": record.origin_categories,
            "allowed": record.allowed,
            "emergency": record.emergency,
            "nudge_message_id": record.nudge_message_id,
            "exit_code": record.exit_code,
            "duration_ms": record.duration_ms,
            "enabled_targets": record.enabled_targets,
            "parent_pid": record.parent_pid,
            "parent_process": record.parent_process,
            "parent_path": record.parent_path,
            "grandparent_pid": record.grandparent_pid,
            "grandparent_process": record.grandparent_process,
            "grandparent_path": record.grandparent_path,
        });
        self.append_json_value(&self.guard_log_path, &value)?;
        let _ = self.rotate_if_large(&self.guard_log_path);
        Ok(())
    }

    fn write_operation_log(&self, record: &OperationLogRecord) -> Result<(), DomainError> {
        let value = serde_json::json!({
            "operation": record.operation,
            "success": record.success,
            "details": record.details,
            "targets": record.targets,
        });
        self.append_json_value(&self.op_log_path, &value)?;
        let _ = self.rotate_if_large(&self.op_log_path);
        Ok(())
    }

    fn rotate_if_needed(&self) -> Result<(), DomainError> {
        self.rotate_if_large(&self.guard_log_path)?;
        self.rotate_if_large(&self.op_log_path)?;
        Ok(())
    }
}

// ---------- 内部ヘルパー ----------

impl FsAdapter {
    fn write_backups(&self, list: &[BackupEntry]) -> Result<(), DomainError> {
        self.ensure_parent_dir(&self.backup_path)?;
        let data: Vec<BackupDto> = list.iter().cloned().map(BackupDto::from).collect();
        let s =
            serde_json::to_string_pretty(&data).map_err(|e| DomainError::IoError(e.to_string()))?;
        self.write_atomic(&self.backup_path, s.as_bytes())?;
        Ok(())
    }

    fn append_json_value(&self, path: &Path, value: &serde_json::Value) -> Result<(), DomainError> {
        let mut lock = None;
        for _ in 0..3 {
            if let Some(guard) = try_acquire_log_mutex(50) {
                lock = Some(guard);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _lock = match lock {
            Some(guard) => guard,
            None => {
                return Err(DomainError::IoError(
                    "log mutex busy; failed to write log".into(),
                ))
            }
        };
        self.ensure_parent_dir(path)?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| DomainError::IoError(format!("open log {:?}: {e}", path)))?;
        let line = serde_json::to_string(value)
            .map_err(|e| DomainError::IoError(format!("serialize log: {e}")))?;
        f.write_all(line.as_bytes())
            .and_then(|_| f.write_all(b"\n"))
            .map_err(|e| DomainError::IoError(format!("write log: {e}")))?;
        Ok(())
    }

    fn rotate_if_large(&self, path: &Path) -> Result<(), DomainError> {
        let _lock = match try_acquire_log_mutex(50) {
            Some(guard) => guard,
            None => return Ok(()),
        };
        if let Ok(meta) = fs::metadata(path) {
            if meta.len() > self.max_log_bytes {
                let ts = utc_compact_timestamp();
                let rotated = path.with_extension(format!("{}.jsonl", ts));
                fs::rename(path, rotated)
                    .map_err(|e| DomainError::IoError(format!("rotate log: {e}")))?;
            }
        }
        Ok(())
    }
}

fn utc_compact_timestamp() -> String {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::GetSystemTime;
        let st = unsafe { GetSystemTime() };
        format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond
        )
    }
    #[cfg(not(windows))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs();
        let (year, month, day, hour, minute, second) = unix_seconds_to_utc_components(secs);
        format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            year, month, day, hour, minute, second
        )
    }
}

#[cfg(not(windows))]
fn unix_seconds_to_utc_components(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let hour = (rem / 3_600) as u32;
    let minute = ((rem % 3_600) / 60) as u32;
    let second = (rem % 60) as u32;
    let (year, month, day) = civil_from_days(days);
    (year, month, day, hour, minute, second)
}

#[cfg(not(windows))]
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    // Howard Hinnantの変換アルゴリズム
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = mp + if mp < 10 { 3 } else { -9 }; // [1, 12]
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}.{}", std::process::id(), nanos)
}

#[cfg(windows)]
fn replace_file(src: &Path, dst: &Path) -> Result<(), DomainError> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::{ReplaceFileW, REPLACE_FILE_FLAGS};
    use windows::core::PCWSTR;

    fn to_wide(path: &Path) -> Vec<u16> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        wide
    }

    let src_w = to_wide(src);
    let dst_w = to_wide(dst);
    unsafe {
        ReplaceFileW(
            PCWSTR(dst_w.as_ptr()),
            PCWSTR(src_w.as_ptr()),
            PCWSTR::null(),
            REPLACE_FILE_FLAGS(0),
            None,
            None,
        )
        .map_err(|e| DomainError::IoError(format!("ReplaceFileW failed: {}", e.message())))?;
    }
    Ok(())
}

// ---------- DTO 定義 ----------

#[derive(Serialize, Deserialize)]
struct ConfigDto {
    version: String,
    targets: Vec<TargetDto>,
    friction: FrictionDto,
    #[serde(default)]
    nudge_messages: Vec<NudgeDto>,
    auto_restore_seconds: u32,
    #[serde(default)]
    search_paths: Vec<String>,
    #[serde(default)]
    policy: PolicyDto,
    /// UI言語（"ja" または "en"）
    #[serde(default)]
    language: String,
    #[serde(default)]
    reaction: ReactionDto,
    #[serde(default)]
    background: BackgroundDto,
}

#[derive(Serialize, Deserialize)]
struct BackgroundDto {
    image: String,
    opacity: u8,
}

impl Default for BackgroundDto {
    fn default() -> Self {
        Self {
            image: "Kaptain-hook.png".into(),
            opacity: 30,
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct PolicyDto {
    #[serde(default)]
    allow_non_interactive: bool,
    #[serde(default)]
    timeout_seconds: u32,
    #[serde(default)]
    auth_mode: String,
}

#[derive(Serialize, Deserialize)]
struct ReactionDto {
    preset: String,
    default_rule: ReactionRuleDto,
    #[serde(default)]
    overrides: Vec<TargetReactionDto>,
}

impl Default for ReactionDto {
    fn default() -> Self {
        let preset = ReactionPreset::AllLog;
        Self {
            preset: preset.as_str().to_string(),
            default_rule: ReactionRuleDto::from_rule(ReactionRule::from_preset(preset)),
            overrides: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ReactionRuleDto {
    mail: String,
    #[serde(rename = "macro")]
    macro_: String,
    relay: String,
    always: String,
}

impl Default for ReactionRuleDto {
    fn default() -> Self {
        Self {
            mail: ReactionKind::Log.as_str().to_string(),
            macro_: ReactionKind::Log.as_str().to_string(),
            relay: ReactionKind::Log.as_str().to_string(),
            always: ReactionKind::Log.as_str().to_string(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TargetReactionDto {
    target: String,
    #[serde(default)]
    forced: String,
    rule: ReactionRuleDto,
}

#[derive(Serialize, Deserialize)]
struct TargetDto {
    exe_name: String,
    enabled: bool,
}

#[derive(Serialize, Deserialize)]
struct FrictionDto {
    require_hold: bool,
    hold_ms: u32,
    require_pointer_movement: bool,
    pointer_move_threshold_px: u32,
    emergency_bypass: bool,
    emergency_hold_ms: u32,
}

#[derive(Serialize, Deserialize, Default)]
struct NudgeDto {
    message_id: String,
    text: String,
}

impl From<&NudgeMessage> for NudgeDto {
    fn from(message: &NudgeMessage) -> Self {
        Self {
            message_id: message.message_id().as_str().to_string(),
            text: message.text().to_string(),
        }
    }
}

impl NudgeDto {
    fn try_into_message(self) -> Result<NudgeMessage, DomainError> {
        let id = MessageId::new(self.message_id)?;
        NudgeMessage::new(id, self.text)
    }
}

impl From<&ReactionConfig> for ReactionDto {
    fn from(cfg: &ReactionConfig) -> Self {
        Self {
            preset: cfg.preset.as_str().to_string(),
            default_rule: ReactionRuleDto::from_rule(cfg.default_rule),
            overrides: cfg.overrides.iter().map(TargetReactionDto::from).collect(),
        }
    }
}

impl ReactionRuleDto {
    fn from_rule(rule: ReactionRule) -> Self {
        Self {
            mail: rule.mail.as_str().to_string(),
            macro_: rule.macro_.as_str().to_string(),
            relay: rule.relay.as_str().to_string(),
            always: rule.always.as_str().to_string(),
        }
    }

    fn to_rule(&self) -> ReactionRule {
        ReactionRule {
            mail: ReactionKind::from_str(&self.mail),
            macro_: ReactionKind::from_str(&self.macro_),
            relay: ReactionKind::from_str(&self.relay),
            always: ReactionKind::from_str(&self.always),
        }
    }
}

impl From<&TargetReaction> for TargetReactionDto {
    fn from(target: &TargetReaction) -> Self {
        Self {
            target: target.target.clone(),
            forced: target.forced.as_str().to_string(),
            rule: ReactionRuleDto::from_rule(target.rule),
        }
    }
}

impl TargetReactionDto {
    fn to_domain(&self) -> TargetReaction {
        TargetReaction {
            target: self.target.clone(),
            forced: ForcedCategory::from_str(&self.forced),
            rule: self.rule.to_rule(),
        }
    }
}

impl TryFrom<ReactionDto> for ReactionConfig {
    type Error = DomainError;

    fn try_from(dto: ReactionDto) -> Result<Self, Self::Error> {
        let mut cfg = ReactionConfig {
            preset: ReactionPreset::from_str(&dto.preset),
            default_rule: dto.default_rule.to_rule(),
            overrides: dto.overrides.into_iter().map(|o| o.to_domain()).collect(),
        };
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }
}

impl From<&InstallConfig> for ConfigDto {
    fn from(cfg: &InstallConfig) -> Self {
        Self {
            version: cfg.version.clone(),
            targets: cfg
                .targets
                .iter()
                .map(|t| TargetDto {
                    exe_name: t.exe_name().to_string(),
                    enabled: t.enabled(),
                })
                .collect(),
            friction: FrictionDto {
                require_hold: cfg.friction.require_hold(),
                hold_ms: cfg.friction.hold_ms(),
                require_pointer_movement: cfg.friction.require_pointer_movement(),
                pointer_move_threshold_px: cfg.friction.pointer_move_threshold_px(),
                emergency_bypass: cfg.friction.emergency_bypass(),
                emergency_hold_ms: cfg.friction.emergency_hold_ms(),
            },
            nudge_messages: cfg.nudge_messages.iter().map(NudgeDto::from).collect(),
            auto_restore_seconds: cfg.auto_restore_seconds,
            search_paths: cfg.search_paths.clone(),
            policy: PolicyDto {
                allow_non_interactive: cfg.policy.allow_non_interactive,
                timeout_seconds: cfg.policy.timeout_seconds,
                auth_mode: cfg.policy.auth_mode.as_str().to_string(),
            },
            language: cfg.language.to_code().to_string(),
            reaction: ReactionDto::from(&cfg.reaction),
            background: BackgroundDto {
                image: cfg.background.image.clone(),
                opacity: cfg.background.opacity,
            },
        }
    }
}

impl TryFrom<ConfigDto> for InstallConfig {
    type Error = DomainError;

    fn try_from(dto: ConfigDto) -> Result<Self, Self::Error> {
        let targets: Result<Vec<Target>, DomainError> = dto
            .targets
            .into_iter()
            .map(|t| Target::new(t.exe_name, t.enabled))
            .collect();

        let nudges = if dto.nudge_messages.is_empty() {
            default_nudges()
        } else {
            dto.nudge_messages
                .into_iter()
                .map(NudgeDto::try_into_message)
                .collect::<Result<Vec<_>, _>>()?
        };

        let friction = FrictionSettings::new(
            dto.friction.require_hold,
            dto.friction.hold_ms,
            dto.friction.require_pointer_movement,
            dto.friction.pointer_move_threshold_px,
            dto.friction.emergency_bypass,
            dto.friction.emergency_hold_ms,
        )?;

        let language = if dto.language.is_empty() {
            Language::default()
        } else {
            Language::from_code(&dto.language)
        };

        let reaction = ReactionConfig::try_from(dto.reaction)?;
        let mut background = BackgroundConfig {
            image: dto.background.image,
            opacity: dto.background.opacity,
        };
        background.normalize();

        let mut cfg = InstallConfig {
            version: dto.version,
            targets: targets?,
            friction,
            nudge_messages: nudges,
            auto_restore_seconds: dto.auto_restore_seconds,
            search_paths: dto.search_paths,
            policy: PolicyConfig {
                allow_non_interactive: dto.policy.allow_non_interactive,
                timeout_seconds: dto.policy.timeout_seconds,
                auth_mode: AuthMode::from_str(&dto.policy.auth_mode)
                    .unwrap_or_default(),
            },
            language,
            reaction,
            background,
        };
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }
}

#[derive(Serialize, Deserialize)]
struct BackupDto {
    target: String,
    view: String,
    original_debugger: Option<String>,
    our_debugger: String,
    timestamp: String,
}

impl From<BackupEntry> for BackupDto {
    fn from(e: BackupEntry) -> Self {
        Self {
            target: e.target,
            view: view_to_str(e.view).to_string(),
            original_debugger: e.original_debugger,
            our_debugger: e.our_debugger,
            timestamp: e.timestamp,
        }
    }
}

impl From<BackupDto> for BackupEntry {
    fn from(dto: BackupDto) -> Self {
        Self {
            target: dto.target,
            view: str_to_view(&dto.view),
            original_debugger: dto.original_debugger,
            our_debugger: dto.our_debugger,
            timestamp: dto.timestamp,
        }
    }
}

fn view_to_str(view: RegistryView) -> &'static str {
    match view {
        RegistryView::Bit64 => "Bit64",
        RegistryView::Bit32 => "Bit32",
    }
}

fn str_to_view(s: &str) -> RegistryView {
    match s {
        "Bit32" => RegistryView::Bit32,
        _ => RegistryView::Bit64,
    }
}
