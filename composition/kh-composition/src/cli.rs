//! CLI 用ランタイム配線。
//! CLI ユースケースの構成ルート。

use kh_adapter_paths as paths;
use kh_adapter_clock::ClockAdapter;
use kh_adapter_fs::FsAdapter;
use kh_adapter_registry::RegistryAdapter;
#[cfg(windows)]
use kh_adapter_registry::DebuggerValue;
use kh_adapter_signature::SignatureAdapter;
use kh_adapter_task::{DEFAULT_RESTORE_TASK_NAME, TaskSchedulerAdapter};
use kh_app::{AppService, admin, uninstall};
use kh_domain::model::InstallConfig;
#[cfg(windows)]
use kh_domain::model::{RegistryView, Target};
use kh_domain::DomainError;

#[cfg(windows)]
use kh_adapter_uninstall_state as uninstall_state_adapter;
use kh_domain::port::driven::{
    BackupStore, ConfigRepository, IfeoRepository, RegistryPort, SignatureVerifier, TaskScheduler,
};
use kh_domain::port::driving::ConflictResolution;
use kh_engine::{ConflictEntry, InstallReport, SafeCleanupReport, StatusEntry};

/// CLI実行ファイル用の依存関係
pub struct CliRuntime {
    app: AppService,
    registry: RegistryAdapter,
    fs: FsAdapter,
    signature: SignatureAdapter,
    clock: ClockAdapter,
    task_scheduler: TaskSchedulerAdapter,
}

/// 復元専用タスクのデフォルト名
pub const RESTORE_TASK_NAME: &str = DEFAULT_RESTORE_TASK_NAME;

impl CliRuntime {
    /// デフォルト設定で新規作成
    pub fn new() -> Self {
        let data_dir = paths::default_data_dir();
        let bin_dir = paths::default_bin_dir();
        let restore_exe = if cfg!(windows) {
            bin_dir.join("kh-restore.exe")
        } else {
            bin_dir.join("kh-restore")
        };
        Self {
            app: AppService::new(),
            registry: RegistryAdapter::new(),
            fs: FsAdapter::new(&data_dir),
            signature: SignatureAdapter::new(),
            clock: ClockAdapter::new(),
            task_scheduler: TaskSchedulerAdapter::new(&restore_exe),
        }
    }

    /// アプリケーションサービス取得
    pub fn app(&self) -> &AppService {
        &self.app
    }

    /// レジストリポート取得
    pub fn registry(&self) -> &dyn RegistryPort {
        &self.registry
    }

    /// IFEOリポジトリ取得
    pub fn ifeo_repository(&self) -> &dyn IfeoRepository {
        &self.registry
    }

    /// 署名検証器取得
    pub fn signature_verifier(&self) -> &dyn SignatureVerifier {
        &self.signature
    }

    /// 設定リポジトリ取得
    pub fn config_repository(&self) -> &dyn ConfigRepository {
        &self.fs
    }

    /// 設定読込
    pub fn load_config(&self) -> Result<InstallConfig, DomainError> {
        self.fs.load()
    }

    /// 設定読込（失敗時はデフォルト）
    pub fn load_config_or_default(&self) -> InstallConfig {
        self.fs.load().unwrap_or_default()
    }

    /// 設定保存
    pub fn save_config(&self, config: &InstallConfig) -> Result<(), kh_domain::DomainError> {
        self.fs.save(config)
    }

    pub fn apply_targets_and_save_config(
        &self,
        request: admin::ApplyTargetsRequest,
        config: &InstallConfig,
        previous_enabled_targets: &[String],
    ) -> Result<(), DomainError> {
        let plan = admin::build_apply_targets_plan(request)?;
        if plan.to_enable.is_empty()
            && plan.to_disable.is_empty()
            && plan.enabled_targets.is_empty()
        {
            return self.save_config(config);
        }
        #[cfg(windows)]
        {
            return apply_targets_and_save_config_windows(
                self,
                &plan,
                config,
                previous_enabled_targets,
            );
        }
        #[cfg(not(windows))]
        {
            let _ = previous_enabled_targets;
            self.save_config(config)?;
            Ok(())
        }
    }

    /// 競合検出用のデバッガパス取得
    pub fn expected_debugger_path(&self) -> String {
        self.registry.debugger_path().to_string()
    }

    fn ensure_debugger_path(&self) -> Result<String, kh_domain::DomainError> {
        let path = self.expected_debugger_path();
        let is_abs = std::path::Path::new(&path).is_absolute();
        let exists = std::path::Path::new(&path).exists();
        if is_abs && exists {
            Ok(path)
        } else {
            Err(kh_domain::DomainError::InvalidConfig(format!(
                "debugger path is not valid: {}",
                path
            )))
        }
    }

    // ========================================================================
    // 高レベル操作（engine層に委譲）
    // ========================================================================

    /// 有効なターゲットにIFEOエントリをインストール
    pub fn install(&self, config: &InstallConfig) -> Result<InstallReport, kh_domain::DomainError> {
        let _ = self.ensure_debugger_path()?;
        kh_engine::apply_install(config, &self.registry)
    }

    /// バックアップ・競合解決付きインストール
    pub fn install_with_backup(
        &self,
        config: &InstallConfig,
        conflict_resolution: ConflictResolution,
    ) -> Result<InstallReport, kh_domain::DomainError> {
        let _ = self.ensure_debugger_path()?;
        let _ifeo_lock = kh_adapter_registry::acquire_ifeo_mutex(5000)?;
        let report = self.app.install_with_backup_and_conflict(
            config,
            &self.registry,
            &self.fs,
            &self.clock,
            &self.signature,
            &self.expected_debugger_path(),
            conflict_resolution,
        )?;
        Ok(report)
    }

    /// 全ターゲットの状態取得
    pub fn status(
        &self,
        config: &InstallConfig,
    ) -> Result<Vec<StatusEntry>, kh_domain::DomainError> {
        kh_engine::status(config, &self.registry)
    }

    /// 他製品との競合検出
    pub fn detect_conflicts(
        &self,
        config: &InstallConfig,
    ) -> Result<Vec<ConflictEntry>, kh_domain::DomainError> {
        let expected = self.expected_debugger_path();
        kh_engine::detect_conflicts(config, &self.registry, &self.signature, &expected)
    }

    /// 自社エントリのみ安全にクリーンアップ（推奨）
    /// 削除前に所有権をチェックし、他製品のエントリはスキップ。
    pub fn safe_cleanup(
        &self,
        config: &InstallConfig,
    ) -> Result<SafeCleanupReport, kh_domain::DomainError> {
        let our_debugger = self.expected_debugger_path();
        kh_engine::safe_cleanup(&config.targets, &self.registry, &our_debugger)
    }

    /// レジストリをスキャンして自社IFEOエントリを取得
    /// 64bit/32bit両ビューをスキャンし、自社デバッガパスに一致するターゲットを返す。
    /// 設定ファイルが欠損/不完全な場合に有用。
    pub fn scan_registry_for_our_entries(&self) -> Result<Vec<String>, kh_domain::DomainError> {
        use kh_domain::model::RegistryView;
        use kh_adapter_registry::{DebuggerOwnership, classify_debugger_value};

        let our_debugger = self.expected_debugger_path();
        let mut our_targets = std::collections::HashSet::new();

        for view in [RegistryView::Bit64, RegistryView::Bit32] {
            let entries = self.registry.list_all_targets(view)?;
            for (target, _debugger) in entries {
                let value = self.registry.get_debugger_value(&target, view)?;
                if matches!(classify_debugger_value(value, &our_debugger), DebuggerOwnership::Owned) {
                    our_targets.insert(target);
                }
            }
        }

        Ok(our_targets.into_iter().collect())
    }

    /// 包括的クリーンアップ: レジストリスキャンで自社エントリを削除
    /// safe_cleanupは設定ファイルのターゲットのみだが、
    /// これはIFEOレジストリ全体をスキャンして自社デバッガパスに一致するものを削除。
    /// 設定ファイルが欠損/不完全な場合に使用。
    pub fn comprehensive_cleanup(&self) -> Result<SafeCleanupReport, kh_domain::DomainError> {
        use kh_domain::model::RegistryView;
        use kh_adapter_registry::{DebuggerOwnership, classify_debugger_value};

        let our_debugger = self.expected_debugger_path();
        let mut removed = Vec::new();
        let skipped = Vec::new();
        let not_registered = Vec::new();

        // 両ビューをスキャン
        for view in [RegistryView::Bit64, RegistryView::Bit32] {
            let entries = self.registry.list_all_targets(view)?;
            for (target, _debugger) in entries {
                let value = self.registry.get_debugger_value(&target, view)?;
                if matches!(classify_debugger_value(value, &our_debugger), DebuggerOwnership::Owned) {
                    // 自社エントリを削除
                    self.registry.remove_debugger(&target, view)?;
                    if !removed.contains(&target) {
                        removed.push(target);
                    }
                }
                // 自社デバッガに一致しないエントリは対象外
            }
        }

        Ok(SafeCleanupReport {
            removed,
            skipped,
            not_registered,
        })
    }

    /// 設定ファイルの存在確認
    pub fn config_exists(&self) -> bool {
        paths::default_config_path().exists()
    }

    /// ロールバック用バックアップの有無確認
    pub fn has_backup(&self) -> bool {
        use kh_domain::port::driven::BackupStore;
        self.fs
            .list_entries()
            .map(|e| !e.is_empty())
            .unwrap_or(false)
    }

    /// バックアップからロールバック
    pub fn rollback(&self) -> Result<Vec<String>, kh_domain::DomainError> {
        self.app.rollback_from_backup(&self.fs, &self.registry)
    }

    /// IFEOクリーンアップ + タスク削除 + ファイル削除
    ///
    /// 処理内容:
    /// 1. IFEOエントリの包括的クリーンアップ（設定ではなくレジストリスキャン）
    /// 2. スケジュールタスク削除
    /// 3. バックアップストアクリア
    /// 4. オプションでKaptainhooKディレクトリ全削除
    pub fn uninstall(
        &self,
        _config: &InstallConfig, // API互換のため残すが、包括スキャンを使用
        remove_data: bool,
    ) -> Result<UninstallReport, kh_domain::DomainError> {
        let mut report = UninstallReport::default();

        // 1. 包括的クリーンアップ: 全自社エントリをレジストリスキャン
        // 設定が欠損/不完全でもエントリを削除できる
        let cleanup = self.comprehensive_cleanup()?;
        report.ifeo_removed = cleanup.removed;
        report.ifeo_skipped = cleanup.skipped;

        // 2. スケジュールタスク削除
        if self
            .task_scheduler
            .task_exists(RESTORE_TASK_NAME)
            .unwrap_or(false)
        {
            match self.task_scheduler.delete_task(RESTORE_TASK_NAME) {
                Ok(()) => report.task_deleted = true,
                Err(e) => report.task_error = Some(e.to_string()),
            }
        }

        // 3. バックアップストアクリア
        if let Err(e) = self.fs.clear() {
            report.backup_error = Some(e.to_string());
        } else {
            report.backup_cleared = true;
        }

        // 4. 要求があればKaptainhooKディレクトリ全削除
        if remove_data {
            // ディレクトリ構造（Windows）:
            // 例: %PROGRAMDATA%\\KaptainhooK\\
            //   └── final\\（データ）
            //       ├── config\\     (設定)
            //       ├── logs\\       (ログ)
            //       └── backups\\    (バックアップ)
            // 例: %ProgramFiles%\\KaptainhooK\\bin\\
            //   └── kh-*.exe        (実行ファイル一式)

            let data_dir = paths::default_data_dir();

            // binディレクトリ削除（複数候補を試行）
            let mut bin_errors: Vec<String> = Vec::new();
            let mut tried = std::collections::HashSet::new();

            let mut candidates = Vec::new();
            candidates.push(paths::default_bin_dir());
            if let Ok(pf) = std::env::var("ProgramFiles") {
                candidates.push(std::path::PathBuf::from(pf).join("KaptainhooK").join("bin"));
            }
            if let Ok(pd) = std::env::var("PROGRAMDATA") {
                candidates.push(std::path::PathBuf::from(pd).join("KaptainhooK").join("bin"));
            }

            for bin_dir in candidates {
                let key = bin_dir.to_string_lossy().to_string();
                if !tried.insert(key) {
                    continue;
                }
                if !bin_dir.exists() {
                    continue;
                }
                match std::fs::remove_dir_all(&bin_dir) {
                    Ok(()) => report.bin_removed = true,
                    Err(e) => bin_errors.push(format!("{:?}: {}", bin_dir, e)),
                }
            }

            if !bin_errors.is_empty() && !report.bin_removed {
                report.bin_error = Some(bin_errors.join(" | "));
            }

            // dataディレクトリ削除（設定/ログ/バックアップ）
            if data_dir.exists() {
                match std::fs::remove_dir_all(&data_dir) {
                    Ok(()) => report.data_removed = true,
                    Err(e) => report.data_error = Some(e.to_string()),
                }
            }
        }

        Ok(report)
    }

    /// データディレクトリパス取得
    pub fn data_dir(&self) -> std::path::PathBuf {
        paths::default_data_dir()
    }

    /// IFEOを元に戻してアンインストールを補助（Windowsのみ）
    #[cfg(windows)]
    pub fn restore_ifeo_from_uninstall_state(&self) -> Result<u32, kh_domain::DomainError> {
        let options = uninstall::RestoreOptions {
            expected_debugger_path: self.expected_debugger_path(),
            foreign_policy: uninstall::ForeignPolicy::Skip,
            logger: None,
        };
        let service = uninstall::UninstallService::new(uninstall::UninstallDeps { port: self });
        service
            .restore_ifeo_from_uninstall_state(&options)
            .map(|report| report.processed)
    }

}

/// アンインストール結果レポート
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct UninstallReport {
    /// 削除した自社IFEOエントリ
    pub ifeo_removed: Vec<String>,
    /// スキップしたIFEOエントリ（他製品）
    pub ifeo_skipped: Vec<(String, String)>,
    /// 復元したIFEOエントリ (アンインストール状態から)
    pub ifeo_restored: Vec<String>,
    /// 復元時のエラー
    pub ifeo_restore_errors: Vec<String>,
    /// スケジュールタスク削除済み
    pub task_deleted: bool,
    /// タスク削除エラー
    pub task_error: Option<String>,
    /// バックアップストアクリア済み
    pub backup_cleared: bool,
    /// バックアップクリアエラー
    pub backup_error: Option<String>,
    /// binディレクトリ削除済み
    pub bin_removed: bool,
    /// binディレクトリ削除エラー
    pub bin_error: Option<String>,
    /// dataディレクトリ削除済み
    pub data_removed: bool,
    /// dataディレクトリ削除エラー
    pub data_error: Option<String>,
}

impl Default for CliRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl admin::AdminPort for CliRuntime {
    fn apply_targets(&self, plan: &admin::ApplyTargetsPlan) -> Result<(), DomainError> {
        #[cfg(windows)]
        {
            apply_targets_windows(self, plan)?;
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            let _ = plan;
            Ok(())
        }
    }

    fn scan_non_string_conflicts(
        &self,
        targets: &[String],
    ) -> Result<Vec<admin::NonStringConflict>, DomainError> {
        #[cfg(windows)]
        {
            return scan_non_string_conflicts_windows(self, targets);
        }
        #[cfg(not(windows))]
        {
            let _ = targets;
            Ok(Vec::new())
        }
    }

    fn backup_uninstall_state(
        &self,
        enabled_targets: &[String],
        actions: &std::collections::BTreeMap<String, admin::BackupAction>,
    ) -> Result<(), DomainError> {
        #[cfg(windows)]
        {
            backup_uninstall_state_windows(self, enabled_targets, actions)?;
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            let _ = enabled_targets;
            let _ = actions;
            Ok(())
        }
    }
}

impl uninstall::UninstallPort for CliRuntime {
    fn restore_ifeo_from_uninstall_state(
        &self,
        options: &uninstall::RestoreOptions,
    ) -> Result<uninstall::RestoreReport, DomainError> {
        #[cfg(windows)]
        {
            let foreign_policy = match options.foreign_policy {
                uninstall::ForeignPolicy::Skip => uninstall_state_adapter::ForeignPolicy::Skip,
                uninstall::ForeignPolicy::Force => uninstall_state_adapter::ForeignPolicy::Force,
                uninstall::ForeignPolicy::Error => uninstall_state_adapter::ForeignPolicy::Error,
                uninstall::ForeignPolicy::Prompt(callback) => {
                    uninstall_state_adapter::ForeignPolicy::Prompt(callback)
                }
            };
            let adapter_options = uninstall_state_adapter::RestoreOptions {
                expected_debugger_path: options.expected_debugger_path.clone(),
                foreign_policy,
                logger: options.logger,
            };
            let report = uninstall_state_adapter::restore_ifeo_from_uninstall_state(&adapter_options)
                .map_err(|e| DomainError::Unknown(e.to_string()))?;
            let items = report
                .items
                .into_iter()
                .map(|item| uninstall::RestoreReportItem {
                    target: item.target,
                    view: item.view,
                    outcome: item.outcome,
                    detail: item.detail,
                    read_back_ok: item.read_back_ok,
                })
                .collect();
            Ok(uninstall::RestoreReport {
                processed: report.processed,
                items,
                errors: report.errors,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = options;
            Ok(uninstall::RestoreReport::default())
        }
    }
}

#[cfg(windows)]
struct ApplyTargetsRollbackState {
    snapshots: Vec<kh_domain::model::IfeoSnapshot>,
    previous_enabled_targets: Vec<String>,
    debugger: String,
    _ifeo_lock: kh_adapter_registry::IfeoMutexGuard,
}

#[cfg(windows)]
fn apply_targets_windows(
    runtime: &CliRuntime,
    plan: &admin::ApplyTargetsPlan,
) -> Result<(), DomainError> {
    let state = apply_targets_windows_begin(runtime, plan, &[])?;
    finalize_targets_windows(runtime, &plan.enabled_targets, &state.debugger)?;
    Ok(())
}

#[cfg(windows)]
fn apply_targets_and_save_config_windows(
    runtime: &CliRuntime,
    plan: &admin::ApplyTargetsPlan,
    config: &InstallConfig,
    previous_enabled_targets: &[String],
) -> Result<(), DomainError> {
    let state = apply_targets_windows_begin(runtime, plan, previous_enabled_targets)?;
    if let Err(save_err) = runtime.save_config(config) {
        if let Err(rollback_err) = rollback_apply_targets_windows(runtime, &state) {
            return Err(DomainError::Unknown(format!(
                "save failed: {save_err}; rollback failed: {rollback_err}"
            )));
        }
        return Err(save_err);
    }
    finalize_targets_windows(runtime, &plan.enabled_targets, &state.debugger)?;
    Ok(())
}

#[cfg(windows)]
fn apply_targets_windows_begin(
    runtime: &CliRuntime,
    plan: &admin::ApplyTargetsPlan,
    previous_enabled_targets: &[String],
) -> Result<ApplyTargetsRollbackState, DomainError> {
    use kh_adapter_registry::{TargetsRegistry, acquire_ifeo_mutex};
    use kh_domain::port::driven::IfeoRepository;

    let mut to_enable = plan.to_enable.clone();
    let mut to_disable = plan.to_disable.clone();
    to_enable.sort();
    to_enable.dedup();
    to_disable.sort();
    to_disable.dedup();

    let enabled_targets = plan.enabled_targets.clone();
    let ifeo_lock = acquire_ifeo_mutex(5000)?;

    let registry = &runtime.registry;
    let mut snapshots: Vec<kh_domain::model::IfeoSnapshot> = Vec::new();
    let mut seen_snapshots = std::collections::HashSet::new();
    for target in to_disable.iter().chain(to_enable.iter()) {
        let name = target.to_ascii_lowercase();
        if seen_snapshots.insert(name.clone()) {
            snapshots.push(registry.snapshot(&name)?);
        }
    }
    let debugger = runtime.expected_debugger_path();
    let debugger_path = std::path::Path::new(&debugger);
    if !debugger_path.is_absolute() || !debugger_path.exists() {
        return Err(DomainError::InvalidConfig(format!(
            "debugger path is invalid: {}",
            debugger
        )));
    }

    let mut backup_map: std::collections::BTreeMap<String, admin::BackupAction> =
        std::collections::BTreeMap::new();
    for entry in &plan.backups {
        backup_map.insert(entry.target.to_ascii_lowercase(), entry.action);
    }

    let apply_result = (|| -> Result<(), DomainError> {
        for target in &to_disable {
            apply_disable(registry, target, &debugger)?;
        }
        for target in &to_enable {
            if let Some(action) = backup_map.get(&target.to_ascii_lowercase()) {
                backup_uninstall_state_for_target(runtime, target, *action)?;
                apply_enable(registry, target, &debugger, true)?;
            } else {
                apply_enable(registry, target, &debugger, false)?;
            }
        }
        TargetsRegistry::new().write_enabled_targets(&enabled_targets)?;
        Ok(())
    })();

    if let Err(err) = apply_result {
        let mut rollback_error: Option<DomainError> = None;
        for snapshot in &snapshots {
            if let Err(e) = registry.restore_snapshot(snapshot) {
                if rollback_error.is_none() {
                    rollback_error = Some(e);
                }
            }
        }
        if let Some(rollback_err) = rollback_error {
            return Err(DomainError::Unknown(format!(
                "apply targets failed: {err}; rollback failed: {rollback_err}"
            )));
        }
        return Err(err);
    }

    Ok(ApplyTargetsRollbackState {
        snapshots,
        previous_enabled_targets: normalize_enabled_targets(previous_enabled_targets),
        debugger,
        _ifeo_lock: ifeo_lock,
    })
}

#[cfg(windows)]
fn rollback_apply_targets_windows(
    runtime: &CliRuntime,
    state: &ApplyTargetsRollbackState,
) -> Result<(), DomainError> {
    use kh_adapter_registry::TargetsRegistry;
    let registry = &runtime.registry;
    let mut rollback_error: Option<DomainError> = None;
    for snapshot in &state.snapshots {
        if let Err(e) = registry.restore_snapshot(snapshot) {
            if rollback_error.is_none() {
                rollback_error = Some(e);
            }
        }
    }
    if let Err(err) = TargetsRegistry::new().write_enabled_targets(&state.previous_enabled_targets) {
        if let Some(existing) = rollback_error {
            return Err(DomainError::Unknown(format!(
                "rollback failed: {existing}; targets restore failed: {err}"
            )));
        }
        return Err(DomainError::Unknown(format!(
            "targets restore failed: {err}"
        )));
    }
    if let Some(rollback_err) = rollback_error {
        return Err(DomainError::Unknown(format!(
            "rollback failed: {rollback_err}"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn finalize_targets_windows(
    runtime: &CliRuntime,
    enabled_targets: &[String],
    debugger: &str,
) -> Result<(), DomainError> {
    let registry = &runtime.registry;
    cleanup_owned_ifeo(registry, enabled_targets, debugger)?;
    kh_engine::reconcile_enabled_targets(enabled_targets, registry, debugger)?;
    Ok(())
}

#[cfg(windows)]
fn normalize_enabled_targets(list: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = list
        .iter()
        .map(|t| t.to_ascii_lowercase())
        .filter(|t| Target::validate_name(t).is_ok())
        .collect();
    normalized.sort();
    normalized.dedup();
    normalized
}

#[cfg(windows)]
fn scan_non_string_conflicts_windows(
    runtime: &CliRuntime,
    targets: &[String],
) -> Result<Vec<admin::NonStringConflict>, DomainError> {
    use kh_adapter_registry::{
        DebuggerOwnership, DebuggerValue, classify_debugger_value,
    };
    let mut out = Vec::new();
    let our_debugger = runtime.expected_debugger_path();

    for target in targets {
        for view in RegistryView::all() {
            let current = match runtime.registry.get_debugger_value(target, *view) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let ownership = classify_debugger_value(current.clone(), &our_debugger);
            if matches!(ownership, DebuggerOwnership::Foreign)
                && matches!(current, Some(DebuggerValue::Other { .. }))
            {
                out.push(admin::NonStringConflict {
                    target: target.to_ascii_lowercase(),
                    view: *view,
                });
            }
        }
    }

    Ok(out)
}

#[cfg(windows)]
fn backup_uninstall_state_windows(
    runtime: &CliRuntime,
    enabled_targets: &[String],
    actions: &std::collections::BTreeMap<String, admin::BackupAction>,
) -> Result<(), DomainError> {
    use kh_adapter_registry::DebuggerValue;
    use windows::Win32::System::Registry::REG_EXPAND_SZ;

    let hkey_root = create_hklm_key(UNINSTALL_STATE_REG_PATH)?;
    apply_registry_key_acl(hkey_root, SDDL_REG_ADMIN_ONLY)?;
    unsafe { let _ = windows::Win32::System::Registry::RegCloseKey(hkey_root); }

    let hkey_backups = create_hklm_key(UNINSTALL_IFEO_BACKUPS_REG_PATH)?;
    apply_registry_key_acl(hkey_backups, SDDL_REG_ADMIN_ONLY)?;
    unsafe { let _ = windows::Win32::System::Registry::RegCloseKey(hkey_backups); }

    let registry = &runtime.registry;
    for target in enabled_targets {
        let name = target.to_ascii_lowercase();
        if Target::validate_name(&name).is_err() {
            continue;
        }
        let action_code = actions
            .get(&name)
            .map(|action| match action {
                admin::BackupAction::TakeOver => 1u32,
                admin::BackupAction::Quarantine => 2u32,
            })
            .unwrap_or(0u32);
        for view in RegistryView::all() {
            let view_name = uninstall_view_name(*view);
            let key_path = format!(r"{}\\{}\\{}", UNINSTALL_IFEO_BACKUPS_REG_PATH, name, view_name);
            let hkey = create_hklm_key(&key_path)?;

            let value = registry.get_debugger_value(&name, *view)?;
            match value {
                None => {
                    set_reg_dword(hkey, "OriginalKind", 0)?;
                    set_reg_dword(hkey, "InstallAction", action_code)?;
                    delete_reg_value(hkey, "OriginalDebuggerRaw");
                    delete_reg_value(hkey, "OriginalRegType");
                    delete_reg_value(hkey, "OriginalBytes");
                }
                Some(DebuggerValue::String { raw, value_type, .. }) => {
                    let kind = if value_type == REG_EXPAND_SZ.0 { 2 } else { 1 };
                    set_reg_dword(hkey, "OriginalKind", kind)?;
                    set_reg_dword(hkey, "InstallAction", action_code)?;
                    set_reg_sz(hkey, "OriginalDebuggerRaw", &raw)?;
                    delete_reg_value(hkey, "OriginalRegType");
                    delete_reg_value(hkey, "OriginalBytes");
                }
                Some(DebuggerValue::Other { value_type, bytes }) => {
                    set_reg_dword(hkey, "OriginalKind", 3)?;
                    set_reg_dword(hkey, "InstallAction", action_code)?;
                    set_reg_dword(hkey, "OriginalRegType", value_type)?;
                    set_reg_binary(hkey, "OriginalBytes", &bytes)?;
                    delete_reg_value(hkey, "OriginalDebuggerRaw");
                }
            }

            apply_registry_key_acl(hkey, SDDL_REG_ADMIN_ONLY)?;
            unsafe { let _ = windows::Win32::System::Registry::RegCloseKey(hkey); }
        }
    }

    Ok(())
}

#[cfg(windows)]
fn apply_disable(
    registry: &RegistryAdapter,
    target: &str,
    our_debugger: &str,
) -> Result<(), DomainError> {
    use kh_adapter_registry::{DebuggerOwnership, classify_debugger_value};

    Target::validate_name(target)?;

    let mut current_per_view: Vec<(RegistryView, Option<DebuggerValue>, DebuggerOwnership)> =
        Vec::new();
    for view in RegistryView::all() {
        let view = *view;
        let current = registry.get_debugger_value(target, view)?;
        let ownership = classify_debugger_value(current.clone(), our_debugger);
        current_per_view.push((view, current, ownership));
    }

    for (view, _current, ownership) in current_per_view {
        if !matches!(ownership, DebuggerOwnership::Owned) {
            continue;
        }
        registry.remove_debugger(target, view)?;
        let after = registry.get_debugger_value(target, view)?;
        if after.is_some() {
            return Err(DomainError::Unknown(format!(
                "Debugger still present after disable for {} in {:?} view",
                target, view
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn apply_enable(
    registry: &RegistryAdapter,
    target: &str,
    our_debugger: &str,
    allow_foreign: bool,
) -> Result<(), DomainError> {
    use kh_adapter_registry::{DebuggerOwnership, classify_debugger_value};

    Target::validate_name(target)?;

    let mut current_per_view: Vec<(RegistryView, Option<DebuggerValue>, DebuggerOwnership)> =
        Vec::new();
    for view in RegistryView::all() {
        let view = *view;
        let current = registry.get_debugger_value(target, view)?;
        let ownership = classify_debugger_value(current.clone(), our_debugger);
        current_per_view.push((view, current, ownership));
    }

    for (view, _current, ownership) in current_per_view {
        match ownership {
            DebuggerOwnership::Owned => continue,
            DebuggerOwnership::Foreign if !allow_foreign => {
                return Err(DomainError::Conflict {
                    target: target.to_string(),
                    existing: "foreign debugger".to_string(),
                });
            }
            _ => {}
        }
        registry.set_debugger(target, view, our_debugger)?;
        let after = registry.get_debugger_value(target, view)?;
        match classify_debugger_value(after, our_debugger) {
            DebuggerOwnership::Owned => {}
            DebuggerOwnership::Disabled => {
                return Err(DomainError::Unknown(format!(
                    "Debugger missing after enable for {} in {:?} view",
                    target, view
                )));
            }
            DebuggerOwnership::Foreign => {
                return Err(DomainError::Unknown(format!(
                    "Debugger mismatch after enable for {} in {:?} view (expected {})",
                    target, view, our_debugger
                )));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn cleanup_owned_ifeo(
    registry: &RegistryAdapter,
    enabled_targets: &[String],
    our_debugger: &str,
) -> Result<(), DomainError> {
    use kh_adapter_registry::{DebuggerOwnership, classify_debugger_value};
    let enabled_set: std::collections::HashSet<String> = enabled_targets
        .iter()
        .map(|t| t.to_ascii_lowercase())
        .collect();
    let mut candidates: std::collections::HashSet<String> = std::collections::HashSet::new();
    for view in RegistryView::all() {
        let entries = registry.list_all_targets(*view)?;
        for (target, _debugger) in entries {
            candidates.insert(target.to_ascii_lowercase());
        }
    }

    for target in candidates {
        if enabled_set.contains(&target) {
            continue;
        }
        for view in RegistryView::all() {
            let current = registry.get_debugger_value(&target, *view)?;
            if !matches!(
                classify_debugger_value(current.clone(), our_debugger),
                DebuggerOwnership::Owned
            ) {
                continue;
            }
            registry.remove_debugger(&target, *view)?;
            let after = registry.get_debugger_value(&target, *view)?;
            if matches!(
                classify_debugger_value(after, our_debugger),
                DebuggerOwnership::Owned
            ) {
                return Err(DomainError::Unknown(format!(
                    "Debugger still present after cleanup for {} in {:?} view",
                    target, view
                )));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn backup_uninstall_state_for_target(
    runtime: &CliRuntime,
    target: &str,
    action: admin::BackupAction,
) -> Result<(), DomainError> {
    let mut map = std::collections::BTreeMap::new();
    map.insert(target.to_ascii_lowercase(), action);
    backup_uninstall_state_windows(runtime, &[target.to_string()], &map)
}

#[cfg(windows)]
const UNINSTALL_STATE_REG_PATH: &str = r"SOFTWARE\\KaptainhooK\\UninstallState";
#[cfg(windows)]
const UNINSTALL_IFEO_BACKUPS_REG_PATH: &str = r"SOFTWARE\\KaptainhooK\\UninstallState\\IfeoBackups";
#[cfg(windows)]
const SDDL_REG_ADMIN_ONLY: &str = "D:P(A;;KA;;;SY)(A;;KA;;;BA)";

#[cfg(windows)]
fn uninstall_view_name(view: RegistryView) -> &'static str {
    match view {
        // アンインストール状態パーサに合わせる（64/32/bit64/bit32/x64/x86）。
        RegistryView::Bit64 => "64",
        RegistryView::Bit32 => "32",
    }
}

#[cfg(windows)]
fn create_hklm_key(path: &str) -> Result<windows::Win32::System::Registry::HKEY, DomainError> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::Storage::FileSystem::WRITE_DAC;
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, HKEY_LOCAL_MACHINE, KEY_CREATE_SUB_KEY, KEY_SET_VALUE, KEY_WOW64_64KEY,
        REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS,
    };
    use windows::core::PCWSTR;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let key_path: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(key_path.as_ptr()),
            Some(0),
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY | REG_SAM_FLAGS(WRITE_DAC.0),
            None,
            &mut hkey,
            None,
        );
        if status != ERROR_SUCCESS {
            return Err(DomainError::RegistryAccessDenied(format!(
                "RegCreateKeyExW failed: status={}",
                status.0
            )));
        }
        Ok(hkey)
    }
}

#[cfg(windows)]
fn set_reg_dword(
    hkey: windows::Win32::System::Registry::HKEY,
    name: &str,
    value: u32,
) -> Result<(), DomainError> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegSetValueExW, REG_DWORD};
    use windows::core::PCWSTR;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let key_name: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let bytes = value.to_le_bytes();
    let status = unsafe {
        RegSetValueExW(hkey, PCWSTR(key_name.as_ptr()), Some(0), REG_DWORD, Some(&bytes))
    };
    if status != ERROR_SUCCESS {
        return Err(DomainError::Unknown(format!(
            "RegSetValueExW failed for {}: status={}",
            name, status.0
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn set_reg_sz(
    hkey: windows::Win32::System::Registry::HKEY,
    name: &str,
    value: &str,
) -> Result<(), DomainError> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegSetValueExW, REG_SZ};
    use windows::core::PCWSTR;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let key_name: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let value_w: Vec<u16> = OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let bytes = unsafe { &value_w.align_to::<u8>().1[..value_w.len() * 2] };
    let status = unsafe {
        RegSetValueExW(hkey, PCWSTR(key_name.as_ptr()), Some(0), REG_SZ, Some(bytes))
    };
    if status != ERROR_SUCCESS {
        return Err(DomainError::Unknown(format!(
            "RegSetValueExW failed for {}: status={}",
            name, status.0
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn set_reg_binary(
    hkey: windows::Win32::System::Registry::HKEY,
    name: &str,
    bytes: &[u8],
) -> Result<(), DomainError> {
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegSetValueExW, REG_BINARY};
    use windows::core::PCWSTR;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let key_name: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let status = unsafe {
        RegSetValueExW(hkey, PCWSTR(key_name.as_ptr()), Some(0), REG_BINARY, Some(bytes))
    };
    if status != ERROR_SUCCESS {
        return Err(DomainError::Unknown(format!(
            "RegSetValueExW failed for {}: status={}",
            name, status.0
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn delete_reg_value(hkey: windows::Win32::System::Registry::HKEY, name: &str) {
    use windows::Win32::System::Registry::RegDeleteValueW;
    use windows::core::PCWSTR;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let key_name: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        let _ = RegDeleteValueW(hkey, PCWSTR(key_name.as_ptr()));
    }
}

#[cfg(windows)]
fn apply_registry_key_acl(
    hkey: windows::Win32::System::Registry::HKEY,
    sddl: &str,
) -> Result<(), DomainError> {
    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::System::Registry::RegSetKeySecurity;
    use windows::core::PCWSTR;

    fn to_wide(s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }

    let sddl_w = to_wide(sddl);
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1 as u32,
            &mut sd,
            None,
        )
        .map_err(|e| DomainError::Unknown(format!("SDDL parse failed: {}", e.message())))?;

        let info: OBJECT_SECURITY_INFORMATION =
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        let status = RegSetKeySecurity(hkey, info, sd);

        let _ = LocalFree(Some(HLOCAL(sd.0)));
        if status != ERROR_SUCCESS {
            return Err(DomainError::Unknown(format!(
                "RegSetKeySecurity failed: status={}",
                status.0
            )));
        }
    }
    Ok(())
}
