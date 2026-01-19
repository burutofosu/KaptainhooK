//! ガード用ランタイム配線。
//!
//! ガード実行の構成ルート。

use crate::error::Result as AppResult;
use kh_adapter_guard::{resolve_target_path_with_bitness, run_service_restart_tool};
use kh_adapter_clock::ClockAdapter;
use kh_adapter_paths as paths;
use kh_adapter_fs::FsAdapter;
use kh_adapter_registry::{RegistryAdapter, TargetsRegistry};
use kh_adapter_service_ipc::{ServiceErrorCode, ServiceIpcClient};
use kh_domain::error::DomainError;
use kh_domain::model::{
    FrictionSettings, GuardNotification, InstallConfig, PathHintKind,
    PromptContext as DomainPromptContext, PromptOutcome as DomainPromptOutcome,
    SuspiciousPathWarning,
};
use kh_domain::port::driven::{
    AuthPrompt, Clock, ConfigRepository, GuardLogRecord, IfeoRepository, LogWriter,
    OperationLogRecord, PrivilegedLaunchRequest, PrivilegedLaunchResult, PrivilegedLauncher,
    RandomSource, TargetPathResolver, TargetsRepository, UserNotifier,
};
use kh_ui_common::message_box::{
    prompt_service_restart, show_error_msgbox, show_info_msgbox, show_warn_msgbox,
};
use kh_ui_common::i18n;
use kh_ui_guard::{
    PromptContext as UiPromptContext, PromptOutcome as UiPromptOutcome, show_prompt, verify_hello,
};
use std::collections::HashSet;
use std::sync::RwLock;

pub use kh_adapter_guard::ProcessBitness;
pub use kh_adapter_guard::{
    GrandparentProcessInfo, ParentProcessInfo, SessionInfo, get_grandparent_process_info,
    get_parent_process_info, get_session_info, is_admin, is_process_running, normalize_target_name,
};

/// ガード実行ファイル用の依存関係
///
/// 具象アダプタインスタンスをカプセル化。
/// ガードはトレイトメソッド経由で使用し、具象型を知らない。
pub struct GuardRuntime {
    registry: RegistryAdapter,
    fs: FsAdapter,
    service_client: ServiceIpcClient,
    clock: ClockAdapter,
    config_cache: RwLock<Option<InstallConfig>>,
    ifeo_bitness: Option<ProcessBitness>,
}

impl GuardRuntime {
    /// デフォルト設定で新規作成
    pub fn new() -> AppResult<Self> {
        let system_root = paths::default_data_dir();
        let user_root = paths::default_user_data_dir();
        Ok(Self {
            registry: RegistryAdapter::new(),
            fs: FsAdapter::new_with_user_logs(&system_root, &user_root),
            service_client: ServiceIpcClient::default(),
            clock: ClockAdapter::new(),
            config_cache: RwLock::new(None),
            ifeo_bitness: None,
        })
    }

    /// IFEOビュー由来のビット数を指定
    pub fn set_ifeo_bitness(&mut self, bitness: Option<ProcessBitness>) {
        self.ifeo_bitness = bitness;
    }

    fn cached_search_paths(&self) -> Option<Vec<String>> {
        self.config_cache
            .read()
            .ok()
            .and_then(|cache| cache.as_ref().map(|cfg| cfg.search_paths.clone()))
    }

    fn update_cached_config(&self, config: &InstallConfig) {
        if let Ok(mut cache) = self.config_cache.write() {
            *cache = Some(config.clone());
        }
    }

    fn spawn_target(
        &self,
        target: &str,
        args: &[String],
    ) -> std::result::Result<std::process::Child, DomainError> {
        let launch_target =
            <Self as TargetPathResolver>::resolve_target_path(self, target, args)
                .ok_or_else(|| DomainError::TargetNotFound(target.to_string()))?;
        let mut cmd = std::process::Command::new(launch_target);
        cmd.args(args);

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NEW_CONSOLE: u32 = 0x00000010;
            cmd.creation_flags(CREATE_NEW_CONSOLE);
        }

        cmd.spawn()
            .map_err(|e| DomainError::ProcessLaunchFailed(e.to_string()))
    }
}

impl PrivilegedLauncher for GuardRuntime {
    fn launch_with_bypass(
        &self,
        request: &PrivilegedLaunchRequest,
    ) -> std::result::Result<PrivilegedLaunchResult, DomainError> {
        if !request.is_protected() {
            let mut child = self.spawn_target(request.target(), request.args())?;
            let status = child
                .wait()
                .map_err(|e| DomainError::ProcessLaunchFailed(e.to_string()))?;
            let exit_code = status
                .code()
                .map(|code| code.clamp(0, 255) as u8)
                .unwrap_or(1);
            return Ok(PrivilegedLaunchResult::new(exit_code));
        }

        let begin = self
            .service_client
            .begin_bypass(request.normalized_target())?;
        let lease_id = begin.lease_id;

        let mut child = match self.spawn_target(request.target(), request.args()) {
            Ok(child) => child,
            Err(e) => {
                let complete_result = self.service_client.complete_bypass(
                    &lease_id,
                    None,
                    Some(ServiceErrorCode::InternalError),
                );
                if let Err(complete_err) = complete_result {
                    return Err(DomainError::BypassCompletionFailed {
                        cause: Box::new(e),
                        bypass_error: complete_err.to_string(),
                    });
                }
                return Err(e);
            }
        };

        let pid = child.id();
        let complete_error = self
            .service_client
            .complete_bypass(&lease_id, Some(pid), None)
            .err()
            .map(|e| e.to_string());

        let status = child
            .wait()
            .map_err(|e| DomainError::ProcessLaunchFailed(e.to_string()))?;
        let exit_code = status
            .code()
            .map(|code| code.clamp(0, 255) as u8)
            .unwrap_or(1);
        Ok(
            PrivilegedLaunchResult::new(exit_code)
                .with_complete_bypass_error(complete_error),
        )
    }
}

impl ConfigRepository for GuardRuntime {
    fn load(&self) -> std::result::Result<InstallConfig, DomainError> {
        let config = self.fs.load()?;
        self.update_cached_config(&config);
        Ok(config)
    }

    fn save(&self, config: &InstallConfig) -> std::result::Result<(), DomainError> {
        self.fs.save(config)?;
        self.update_cached_config(config);
        Ok(())
    }

    fn exists(&self) -> bool {
        self.fs.exists()
    }
}

impl LogWriter for GuardRuntime {
    fn write_guard_log(&self, record: &GuardLogRecord) -> std::result::Result<(), DomainError> {
        self.fs.write_guard_log(record)
    }

    fn write_operation_log(
        &self,
        record: &OperationLogRecord,
    ) -> std::result::Result<(), DomainError> {
        self.fs.write_operation_log(record)
    }

    fn rotate_if_needed(&self) -> std::result::Result<(), DomainError> {
        self.fs.rotate_if_needed()
    }
}

impl Clock for GuardRuntime {
    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    fn now_iso8601(&self) -> String {
        self.clock.now_iso8601()
    }
}

impl RandomSource for GuardRuntime {
    fn next_u64(&self) -> std::result::Result<u64, DomainError> {
        self.clock.next_u64()
    }
}

impl IfeoRepository for GuardRuntime {
    fn get_debugger(
        &self,
        target: &str,
        view: kh_domain::model::RegistryView,
    ) -> std::result::Result<Option<String>, DomainError> {
        self.registry.get_debugger(target, view)
    }

    fn set_debugger(
        &self,
        target: &str,
        view: kh_domain::model::RegistryView,
        path: &str,
    ) -> std::result::Result<(), DomainError> {
        self.registry.set_debugger(target, view, path)
    }

    fn remove_debugger(
        &self,
        target: &str,
        view: kh_domain::model::RegistryView,
    ) -> std::result::Result<(), DomainError> {
        self.registry.remove_debugger(target, view)
    }

    fn list_all_targets(
        &self,
        view: kh_domain::model::RegistryView,
    ) -> std::result::Result<Vec<(String, String)>, DomainError> {
        self.registry.list_all_targets(view)
    }
}

impl TargetsRepository for GuardRuntime {
    fn load_enabled_targets(&self) -> std::result::Result<HashSet<String>, DomainError> {
        TargetsRegistry::new().read_enabled_targets()
    }
}

impl TargetPathResolver for GuardRuntime {
    fn resolve_target_path(&self, target: &str, args: &[String]) -> Option<String> {
        let _ = args;
        let search_paths = if let Some(cached) = self.cached_search_paths() {
            cached
        } else {
            let config = self.fs.load().ok();
            let search_paths = config
                .as_ref()
                .map(|cfg| cfg.search_paths.clone())
                .unwrap_or_default();
            if let Some(config) = config {
                self.update_cached_config(&config);
            }
            search_paths
        };
        resolve_target_path_with_bitness(target, &search_paths, self.ifeo_bitness)
    }
}

impl AuthPrompt for GuardRuntime {
    fn show_friction(
        &self,
        settings: &FrictionSettings,
        ctx: &DomainPromptContext,
    ) -> std::result::Result<DomainPromptOutcome, DomainError> {
        let ui_ctx = to_ui_prompt_context(ctx);
        let outcome = show_prompt(settings, &ui_ctx)
            .map_err(|e| DomainError::Unknown(e.to_string()))?;
        Ok(from_ui_outcome(outcome))
    }

    fn verify_hello(
        &self,
        ctx: &DomainPromptContext,
    ) -> std::result::Result<DomainPromptOutcome, DomainError> {
        let ui_ctx = to_ui_prompt_context(ctx);
        let outcome = verify_hello(&ui_ctx)
            .map_err(|e| DomainError::Unknown(e.to_string()))?;
        Ok(from_ui_outcome(outcome))
    }
}

impl UserNotifier for GuardRuntime {
    fn show_error(&self, msg: &str) {
        show_error_msgbox(msg);
    }

    fn show_warn(&self, msg: &str) {
        show_warn_msgbox(msg);
    }

    fn show_info(&self, msg: &str) {
        show_info_msgbox(msg);
    }

    fn show_error_message(&self, msg: &GuardNotification) {
        show_error_msgbox(&format_guard_notification(msg));
    }

    fn show_warn_message(&self, msg: &GuardNotification) {
        show_warn_msgbox(&format_guard_notification(msg));
    }

    fn show_info_message(&self, msg: &GuardNotification) {
        show_info_msgbox(&format_guard_notification(msg));
    }

    fn prompt_service_restart(&self) -> bool {
        prompt_service_restart()
    }

    fn run_service_restart_tool(&self) -> std::result::Result<(), String> {
        run_service_restart_tool()
    }
}

fn format_guard_notification(msg: &GuardNotification) -> String {
    let t = i18n::t();
    match msg {
        GuardNotification::ConfigLoadFailed => {
            t.guard_error_config_load_failed().to_string()
        }
        GuardNotification::TargetsUnavailable => {
            t.guard_error_targets_unavailable().to_string()
        }
        GuardNotification::TargetNotFoundInSearchPaths => {
            t.guard_error_target_not_found().to_string()
        }
        GuardNotification::LaunchFailed { detail } => {
            t.guard_error_launch_failed(detail)
        }
        GuardNotification::ServiceStopped => {
            t.guard_error_service_stopped().to_string()
        }
        GuardNotification::ServiceRestarting => {
            t.guard_info_service_restart().to_string()
        }
        GuardNotification::ServiceCommFailed { detail } => {
            t.guard_error_service_comm_failed(detail)
        }
        GuardNotification::ServiceError { code, message_id } => {
            match message_id {
                Some(id) => t.guard_service_error_message_id(*id),
                None => t.guard_service_error_code(*code),
            }
        }
        GuardNotification::SuspiciousPathWarning(warn) => {
            format_suspicious_warning(t, warn)
        }
        GuardNotification::NotifyAllowed { categories, warning } => {
            let mut base = if categories.is_empty() {
                t.guard_warn_notify_unknown_origin().to_string()
            } else {
                t.guard_warn_notify_origin(&categories.join(", "))
            };
            if let Some(extra) = warning {
                base.push_str("\n\n");
                base.push_str(&format_suspicious_warning(t, extra));
            }
            base
        }
    }
}

fn format_suspicious_warning(t: &dyn i18n::Translations, warn: &SuspiciousPathWarning) -> String {
    let reasons = warn
        .reasons
        .iter()
        .map(|kind| path_hint_label(t, *kind))
        .collect::<Vec<_>>()
        .join(" / ");
    t.guard_warn_suspicious_paths(&warn.target, &warn.related, &reasons)
}

fn path_hint_label(t: &dyn i18n::Translations, kind: PathHintKind) -> &'static str {
    match kind {
        PathHintKind::PublicUserDir => t.common_path_hint_public_user_dir(),
        PathHintKind::TempDir => t.common_path_hint_temp_dir(),
        PathHintKind::UserTempDir => t.common_path_hint_user_temp_dir(),
        PathHintKind::DownloadsDir => t.common_path_hint_downloads_dir(),
        PathHintKind::DesktopDir => t.common_path_hint_desktop_dir(),
        PathHintKind::ProgramFilesDir => t.common_path_hint_program_files_dir(),
        PathHintKind::ProgramFilesX86Dir => t.common_path_hint_program_files_x86_dir(),
        PathHintKind::System32Dir => t.common_path_hint_system32_dir(),
        PathHintKind::SysWow64Dir => t.common_path_hint_syswow64_dir(),
    }
}

fn to_ui_prompt_context(ctx: &DomainPromptContext) -> UiPromptContext {
    UiPromptContext {
        target: ctx.target.clone(),
        args: ctx.args.clone(),
        resolved_path: ctx.resolved_path.clone(),
        username: ctx.username.clone(),
        session_name: ctx.session_name.clone(),
        nudge_text: ctx.nudge_text.clone(),
        timeout_seconds: ctx.timeout_seconds,
        language: ctx.language,
    }
}

fn from_ui_outcome(outcome: UiPromptOutcome) -> DomainPromptOutcome {
    DomainPromptOutcome {
        allowed: outcome.allowed,
        reason: outcome.reason,
        emergency: outcome.emergency,
    }
}
