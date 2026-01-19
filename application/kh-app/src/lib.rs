//! kh-app: アプリケーション層のファサード。
//! Engine 層とドメインポートを組み合わせて、インストールやクリーンアップなど
//! のユースケースを実装する。

use kh_domain::DomainError;
use kh_domain::model::{GuardConfig, InstallConfig};
use kh_domain::port::driven::{
    BackupStore, Clock, IfeoRepository, RegistryPort, SignatureVerifier,
};
use kh_domain::port::driving::ConflictResolution;
use kh_engine::{
    InstallReport, apply_install, cleanup, detect_conflicts, install_with_backup,
    rollback_from_backup, status,
};

pub mod guard;
pub mod admin;
pub mod uninstall;
pub use guard::{GuardDeps, GuardService};

#[derive(Debug, Default)]
pub struct AppService;

impl AppService {
    pub fn new() -> Self {
        Self::default()
    }

    /// 検証してプランを返す（表示責務はプレゼン層）
    pub fn plan(&self, cfg: &InstallConfig) -> Result<InstallConfig, DomainError> {
        cfg.validate()?;
        Ok(cfg.clone())
    }

    /// レジストリポート経由でIFEO登録（バックアップなし）
    pub fn install(
        &self,
        cfg: &InstallConfig,
        registry: &impl RegistryPort,
        repo: &impl IfeoRepository,
        sig: &impl SignatureVerifier,
        expected_debugger: &str,
    ) -> Result<(), DomainError> {
        let mut guard_cfg = GuardConfig {
            targets: cfg.targets.clone(),
            friction: cfg.friction,
            nudge_messages: cfg.nudge_messages.clone(),
            auto_restore_seconds: cfg.auto_restore_seconds,
        };
        guard_cfg.ensure_defaults();
        guard_cfg.validate()?;

        // フェイルセーフ: 書き込み前にIFEO競合を検出
        let conflicts = self.conflicts(
            &InstallConfig {
                version: cfg.version.clone(),
                targets: guard_cfg.targets.clone(),
                friction: guard_cfg.friction,
                nudge_messages: guard_cfg.nudge_messages.clone(),
                auto_restore_seconds: guard_cfg.auto_restore_seconds,
                search_paths: cfg.search_paths.clone(),
                policy: Default::default(),
                language: cfg.language,
                reaction: cfg.reaction.clone(),
                background: cfg.background.clone(),
            },
            repo,
            sig,
            expected_debugger,
        )?;

        if let Some(c) = conflicts.first() {
            return Err(DomainError::Conflict {
                target: c.target.clone(),
                existing: c.existing_debugger.clone(),
            });
        }

        apply_install(
            &InstallConfig {
                version: cfg.version.clone(),
                targets: guard_cfg.targets,
                friction: guard_cfg.friction,
                nudge_messages: guard_cfg.nudge_messages,
                auto_restore_seconds: guard_cfg.auto_restore_seconds,
                search_paths: cfg.search_paths.clone(),
                policy: Default::default(),
                language: cfg.language,
                reaction: cfg.reaction.clone(),
                background: cfg.background.clone(),
            },
            registry,
        )?;
        Ok(())
    }

    /// バックアップ＋競合解決付きIFEO登録
    ///
    /// 競合処理:
    /// - 中止: 競合ならエラーを返す
    /// - スキップ: 競合ターゲットを無効化
    /// - 上書き: 元の値をバックアップして上書き
    pub fn install_with_backup_and_conflict(
        &self,
        cfg: &InstallConfig,
        repo: &impl IfeoRepository,
        backup: &impl BackupStore,
        clock: &impl Clock,
        sig: &impl SignatureVerifier,
        expected_debugger: &str,
        conflict_resolution: ConflictResolution,
    ) -> Result<InstallReport, DomainError> {
        let mut guard_cfg = GuardConfig {
            targets: cfg.targets.clone(),
            friction: cfg.friction,
            nudge_messages: cfg.nudge_messages.clone(),
            auto_restore_seconds: cfg.auto_restore_seconds,
        };
        guard_cfg.ensure_defaults();
        guard_cfg.validate()?;

        // 書き込み前に競合検出
        let conflicts = self.conflicts(
            &InstallConfig {
                version: cfg.version.clone(),
                targets: guard_cfg.targets.clone(),
                friction: guard_cfg.friction,
                nudge_messages: guard_cfg.nudge_messages.clone(),
                auto_restore_seconds: guard_cfg.auto_restore_seconds,
                search_paths: cfg.search_paths.clone(),
                policy: cfg.policy,
                language: cfg.language,
                reaction: cfg.reaction.clone(),
                background: cfg.background.clone(),
            },
            repo,
            sig,
            expected_debugger,
        )?;

        if !conflicts.is_empty() {
            match conflict_resolution {
                ConflictResolution::Abort => {
                    let c = &conflicts[0];
                    return Err(DomainError::Conflict {
                        target: c.target.clone(),
                        existing: c.existing_debugger.clone(),
                    });
                }
                ConflictResolution::Skip => {
                    for t in guard_cfg.targets.iter_mut() {
                        if conflicts
                            .iter()
                            .any(|c| c.target.eq_ignore_ascii_case(t.exe_name()))
                        {
                            t.set_enabled(false);
                        }
                    }
                }
                ConflictResolution::Overwrite => {
                    // 続行; バックアップが復元を担当
                }
            }
        }

        let install_cfg = InstallConfig {
            version: cfg.version.clone(),
            targets: guard_cfg.targets,
            friction: guard_cfg.friction,
            nudge_messages: guard_cfg.nudge_messages,
            auto_restore_seconds: guard_cfg.auto_restore_seconds,
            search_paths: cfg.search_paths.clone(),
            policy: cfg.policy,
            language: cfg.language,
            reaction: cfg.reaction.clone(),
            background: cfg.background.clone(),
        };

        let previous_entries = backup.list_entries()?;
        backup.clear()?;
        let restore_previous = || -> Result<(), DomainError> {
            if previous_entries.is_empty() {
                return Ok(());
            }
            backup.clear()?;
            for entry in &previous_entries {
                backup.save_entry(entry)?;
            }
            Ok(())
        };

        match install_with_backup(&install_cfg, repo, backup, clock, expected_debugger) {
            Ok(report) => Ok(report),
            Err(err) => match rollback_from_backup(backup, repo) {
                Ok(_) => {
                    if let Err(restore_err) = restore_previous() {
                        Err(DomainError::Unknown(format!(
                            "install failed: {}; restore backup failed: {}",
                            err, restore_err
                        )))
                    } else {
                        Err(err)
                    }
                }
                Err(rb) => {
                    if let Err(restore_err) = restore_previous() {
                        Err(DomainError::Unknown(format!(
                            "install failed: {}; rollback failed: {}; restore backup failed: {}",
                            err, rb, restore_err
                        )))
                    } else {
                        Err(DomainError::Unknown(format!(
                            "install failed: {}; rollback failed: {}",
                            err, rb
                        )))
                    }
                }
            },
        }
    }

    /// バックアップストアからIFEOエントリをロールバック
    pub fn rollback_from_backup(
        &self,
        backup: &impl BackupStore,
        repo: &impl IfeoRepository,
    ) -> Result<Vec<String>, DomainError> {
        rollback_from_backup(backup, repo)
    }

    /// IFEOステータス（ビュー付き）を返す
    pub fn status(
        &self,
        cfg: &InstallConfig,
        repo: &impl kh_domain::port::driven::IfeoRepository,
    ) -> Result<Vec<kh_engine::StatusEntry>, DomainError> {
        status(cfg, repo)
    }

    /// IFEO競合エントリを返す
    pub fn conflicts(
        &self,
        cfg: &InstallConfig,
        repo: &impl kh_domain::port::driven::IfeoRepository,
        sig: &impl kh_domain::port::driven::SignatureVerifier,
        expected_debugger: &str,
    ) -> Result<Vec<kh_engine::ConflictEntry>, DomainError> {
        detect_conflicts(cfg, repo, sig, expected_debugger)
    }

    /// クリーンアップ結果を返す
    pub fn cleanup_report(
        &self,
        cfg: &InstallConfig,
        registry: &impl RegistryPort,
    ) -> Result<kh_engine::CleanupReport, DomainError> {
        cleanup(&cfg.targets, registry)
    }

    /// インストールプランを返す（表示責務なし）
    pub fn install_plan(
        &self,
        cfg: &InstallConfig,
        dry_run: bool,
        expected_debugger: &str,
    ) -> Result<Vec<InstallPlanEntry>, DomainError> {
        let mut guard_cfg = GuardConfig {
            targets: cfg.targets.clone(),
            friction: cfg.friction,
            nudge_messages: cfg.nudge_messages.clone(),
            auto_restore_seconds: cfg.auto_restore_seconds,
        };
        guard_cfg.ensure_defaults();
        guard_cfg.validate()?;

        Ok(guard_cfg
            .targets
            .iter()
            .filter(|t| t.enabled())
            .map(|t| InstallPlanEntry {
                target: t.exe_name().to_string(),
                action: if dry_run {
                    PlanAction::WouldInstall
                } else {
                    PlanAction::Install
                },
                debugger_path: expected_debugger.to_string(),
            })
            .collect())
    }
}

// --- 上位層向けDTO（プレゼンテーションフリー） ---

#[derive(Debug, Clone)]
pub struct InstallPlanEntry {
    pub target: String,
    pub action: PlanAction,
    pub debugger_path: String,
}

#[derive(Debug, Clone, Copy)]
pub enum PlanAction {
    Install,
    WouldInstall,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kh_domain::model::{
        BackgroundConfig, FrictionSettings, Language, NudgeMessage, PolicyConfig, RegistryView,
        Target,
    };
    use kh_domain::port::driven::{
        BackupEntry, BackupStore, Clock, IfeoRepository, RegistryPort, SignatureVerifier,
    };
    use kh_domain::model::SignatureStatus;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const EXPECTED_DEBUGGER: &str = r"C:\\Program Files\\KaptainhooK\\kh-bootstrap.exe";
    const OTHER_DEBUGGER: &str = r"C:\\OtherProduct\\debugger.exe";

    #[test]
    fn install_with_backup_abort_conflict_returns_error() {
        let service = AppService::new();
        let cfg = single_target_config(true);
        let repo = MockRepo::with_conflict("powershell.exe", OTHER_DEBUGGER);
        let backup = MockBackupStore::default();
        let clock = MockClock;
        let sig = MockSignatureVerifier;

        let result = service.install_with_backup_and_conflict(
            &cfg,
            &repo,
            &backup,
            &clock,
            &sig,
            EXPECTED_DEBUGGER,
            ConflictResolution::Abort,
        );

        match result {
            Err(DomainError::Conflict { target, existing }) => {
                assert_eq!(target, "powershell.exe");
                assert_eq!(existing, OTHER_DEBUGGER);
            }
            other => panic!("expected conflict error, got {:?}", other),
        }

        assert!(
            backup
                .entries()
                .into_iter()
                .all(|entry| entry.target != "powershell.exe")
        );
        assert_eq!(
            repo.get_debugger("powershell.exe", RegistryView::Bit64)
                .unwrap()
                .as_deref(),
            Some(OTHER_DEBUGGER)
        );
    }

    #[test]
    fn install_with_backup_skip_disables_conflicted_target() {
        let service = AppService::new();
        let cfg = single_target_config(true);
        let repo = MockRepo::with_conflict("powershell.exe", OTHER_DEBUGGER);
        let backup = MockBackupStore::default();
        let clock = MockClock;
        let sig = MockSignatureVerifier;

        let report = service
            .install_with_backup_and_conflict(
                &cfg,
                &repo,
                &backup,
                &clock,
                &sig,
                EXPECTED_DEBUGGER,
                ConflictResolution::Skip,
            )
            .expect("skip mode should succeed");

        assert!(
            report
                .registered
                .iter()
                .all(|t| t != "powershell.exe")
        );
        assert!(report.unregistered.is_empty());
        assert!(
            backup
                .entries()
                .into_iter()
                .all(|entry| entry.target != "powershell.exe")
        );
        for view in RegistryView::all() {
            assert_eq!(
                repo.get_debugger("powershell.exe", *view)
                    .unwrap()
                    .as_deref(),
                Some(OTHER_DEBUGGER)
            );
        }
    }

    #[test]
    fn conflicts_detects_foreign_entries_per_view() {
        let service = AppService::new();
        let cfg = multi_target_config();
        let repo = MockRepo::default();
        let sig = MockSignatureVerifier;

        repo.set_entry("powershell.exe", RegistryView::Bit64, OTHER_DEBUGGER);
        repo.set_entry("powershell.exe", RegistryView::Bit32, EXPECTED_DEBUGGER);
        repo.set_entry(
            "cmd.exe",
            RegistryView::Bit64,
            r#""C:\Program Files\KaptainhooK\kh-bootstrap.exe" --ifeo-view=64"#,
        );

        let conflicts = service
            .conflicts(&cfg, &repo, &sig, EXPECTED_DEBUGGER)
            .expect("conflict scan should succeed");

        assert_eq!(conflicts.len(), 1);
        let entry = &conflicts[0];
        assert_eq!(entry.target, "powershell.exe");
        assert_eq!(entry.view, RegistryView::Bit64);
        assert_eq!(entry.existing_debugger, OTHER_DEBUGGER);
    }

    #[test]
    fn install_with_backup_skip_mixed_targets_only_installs_safe_ones() {
        let service = AppService::new();
        let cfg = multi_target_config();
        let repo = MockRepo::with_conflict("powershell.exe", OTHER_DEBUGGER);
        let backup = MockBackupStore::default();
        let clock = MockClock;
        let sig = MockSignatureVerifier;

        let report = service
            .install_with_backup_and_conflict(
                &cfg,
                &repo,
                &backup,
                &clock,
                &sig,
                EXPECTED_DEBUGGER,
                ConflictResolution::Skip,
            )
            .expect("skip mode should succeed");

        assert!(report.registered.contains(&"cmd.exe".to_string()));
        assert!(!report.registered.contains(&"powershell.exe".to_string()));

        for view in RegistryView::all() {
            assert_eq!(
                repo.get_debugger("powershell.exe", *view)
                    .unwrap()
                    .as_deref(),
                Some(OTHER_DEBUGGER)
            );
            assert_eq!(
                repo.get_debugger("cmd.exe", *view).unwrap().as_deref(),
                Some(EXPECTED_DEBUGGER)
            );
        }

        let entries = backup.entries();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|e| e.target == "cmd.exe"));
    }

    #[test]
    fn install_with_backup_overwrite_mixed_targets_overwrites_conflicts() {
        let service = AppService::new();
        let cfg = multi_target_config();
        let repo = MockRepo::with_conflict("powershell.exe", OTHER_DEBUGGER);
        let backup = MockBackupStore::default();
        let clock = MockClock;
        let sig = MockSignatureVerifier;

        let report = service
            .install_with_backup_and_conflict(
                &cfg,
                &repo,
                &backup,
                &clock,
                &sig,
                EXPECTED_DEBUGGER,
                ConflictResolution::Overwrite,
            )
            .expect("overwrite should succeed");

        assert!(report.registered.contains(&"powershell.exe".to_string()));
        assert!(report.registered.contains(&"cmd.exe".to_string()));

        for view in RegistryView::all() {
            assert_eq!(
                repo.get_debugger("powershell.exe", *view)
                    .unwrap()
                    .as_deref(),
                Some(EXPECTED_DEBUGGER)
            );
            assert_eq!(
                repo.get_debugger("cmd.exe", *view).unwrap().as_deref(),
                Some(EXPECTED_DEBUGGER)
            );
        }

        let entries = backup.entries();
        let powershell_entries: Vec<_> = entries
            .iter()
            .filter(|entry| entry.target == "powershell.exe")
            .collect();
        let cmd_entries: Vec<_> = entries
            .iter()
            .filter(|entry| entry.target == "cmd.exe")
            .collect();
        assert_eq!(powershell_entries.len(), 2);
        assert_eq!(cmd_entries.len(), 2);
        assert!(powershell_entries
            .iter()
            .all(|entry| entry.original_debugger.as_deref() == Some(OTHER_DEBUGGER)));
        assert!(cmd_entries
            .iter()
            .all(|entry| entry.original_debugger.is_none()));
    }

    #[test]
    fn install_with_backup_overwrite_replaces_debugger_and_backs_up() {
        let service = AppService::new();
        let cfg = single_target_config(true);
        let repo = MockRepo::with_conflict("powershell.exe", OTHER_DEBUGGER);
        let backup = MockBackupStore::default();
        let clock = MockClock;
        let sig = MockSignatureVerifier;

        let report = service
            .install_with_backup_and_conflict(
                &cfg,
                &repo,
                &backup,
                &clock,
                &sig,
                EXPECTED_DEBUGGER,
                ConflictResolution::Overwrite,
            )
            .expect("overwrite should succeed");

        assert!(report
            .registered
            .contains(&"powershell.exe".to_string()));

        for view in RegistryView::all() {
            assert_eq!(
                repo.get_debugger("powershell.exe", *view)
                    .unwrap()
                    .as_deref(),
                Some(EXPECTED_DEBUGGER)
            );
        }

        let entries = backup.entries();
        let ours: Vec<_> = entries
            .iter()
            .filter(|entry| entry.target == "powershell.exe")
            .collect();
        assert_eq!(ours.len(), 2);
        for entry in ours {
            assert_eq!(entry.our_debugger, EXPECTED_DEBUGGER);
            assert_eq!(entry.original_debugger.as_deref(), Some(OTHER_DEBUGGER));
        }
    }

    #[test]
    fn install_with_backup_failure_rolls_back() {
        let service = AppService::new();
        let cfg = single_target_config(true);
        let repo = FailingRepo::with_conflict(
            "powershell.exe",
            OTHER_DEBUGGER,
            RegistryView::Bit32,
            EXPECTED_DEBUGGER,
        );
        let backup = MockBackupStore::default();
        let clock = MockClock;
        let sig = MockSignatureVerifier;

        let result = service.install_with_backup_and_conflict(
            &cfg,
            &repo,
            &backup,
            &clock,
            &sig,
            EXPECTED_DEBUGGER,
            ConflictResolution::Overwrite,
        );

        assert!(result.is_err());
        for view in RegistryView::all() {
            assert_eq!(
                repo.get_debugger("powershell.exe", *view)
                    .unwrap()
                    .as_deref(),
                Some(OTHER_DEBUGGER)
            );
        }
        assert!(backup.entries().is_empty());
    }

    #[test]
    fn install_plan_respects_dry_run_flag() {
        let service = AppService::new();
        let cfg = InstallConfig::default();

        let dry_plan = service
            .install_plan(&cfg, true, EXPECTED_DEBUGGER)
            .expect("plan should succeed");
        assert!(!dry_plan.is_empty());
        assert!(dry_plan
            .iter()
            .all(|entry| matches!(entry.action, PlanAction::WouldInstall)));

        let live_plan = service
            .install_plan(&cfg, false, EXPECTED_DEBUGGER)
            .expect("plan should succeed");
        assert!(!live_plan.is_empty());
        assert!(live_plan
            .iter()
            .all(|entry| matches!(entry.action, PlanAction::Install)));
    }

    #[test]
    fn cleanup_report_unregisters_all_targets() {
        let service = AppService::new();
        let cfg = multi_target_config();
        let registry = MockRegistryPort::default();

        let report = service
            .cleanup_report(&cfg, &registry)
            .expect("cleanup should succeed");

        assert_eq!(
            report.removed,
            cfg.targets.iter().map(|t| t.exe_name().to_string()).collect::<Vec<_>>()
        );
        assert_eq!(registry.unregistered(), report.removed);
    }

    #[test]
    fn rollback_from_backup_restores_entries_and_clears_store() {
        let service = AppService::new();
        let repo = MockRepo::with_conflict("powershell.exe", EXPECTED_DEBUGGER);
        let backup = MockBackupStore::default();
        backup.replace_all(vec![
            backup_entry(RegistryView::Bit64, Some(OTHER_DEBUGGER)),
            backup_entry(RegistryView::Bit32, Some(OTHER_DEBUGGER)),
        ]);

        let restored = service
            .rollback_from_backup(&backup, &repo)
            .expect("rollback should succeed");

        assert_eq!(restored, vec!["powershell.exe".to_string()]);
        for view in RegistryView::all() {
            assert_eq!(
                repo.get_debugger("powershell.exe", *view)
                    .unwrap()
                    .as_deref(),
                Some(OTHER_DEBUGGER)
            );
        }
        assert!(backup.entries().is_empty());
    }

    fn single_target_config(enabled: bool) -> InstallConfig {
        InstallConfig {
            version: "0.95.0".into(),
            targets: vec![Target::new("powershell.exe", enabled).unwrap()],
            friction: FrictionSettings::default(),
            nudge_messages: vec![NudgeMessage::default()],
            auto_restore_seconds: 5,
            search_paths: Vec::new(),
            policy: PolicyConfig::default(),
            language: Language::default(),
            reaction: Default::default(),
            background: BackgroundConfig::default(),
        }
    }

    fn multi_target_config() -> InstallConfig {
        InstallConfig {
            version: "0.95.0".into(),
            targets: vec![
                Target::new("powershell.exe", true).unwrap(),
                Target::new("cmd.exe", true).unwrap(),
            ],
            friction: FrictionSettings::default(),
            nudge_messages: vec![NudgeMessage::default()],
            auto_restore_seconds: 5,
            search_paths: Vec::new(),
            policy: PolicyConfig::default(),
            language: Language::default(),
            reaction: Default::default(),
            background: BackgroundConfig::default(),
        }
    }

    #[derive(Default)]
    struct MockRepo {
        entries: RefCell<HashMap<(String, RegistryView), String>>,
    }

    impl MockRepo {
        fn with_conflict(target: &str, debugger: &str) -> Self {
            let repo = Self::default();
            for view in RegistryView::all() {
                repo.entries.borrow_mut().insert(
                    (target.to_string(), *view),
                    debugger.to_string(),
                );
            }
            repo
        }

        fn set_entry(&self, target: &str, view: RegistryView, debugger: &str) {
            self.entries
                .borrow_mut()
                .insert((target.to_string(), view), debugger.to_string());
        }
    }

    impl IfeoRepository for MockRepo {
        fn get_debugger(
            &self,
            target: &str,
            view: RegistryView,
        ) -> Result<Option<String>, DomainError> {
            Ok(self
                .entries
                .borrow()
                .get(&(target.to_string(), view))
                .cloned())
        }

        fn set_debugger(
            &self,
            target: &str,
            view: RegistryView,
            path: &str,
        ) -> Result<(), DomainError> {
            self.entries
                .borrow_mut()
                .insert((target.to_string(), view), path.to_string());
            Ok(())
        }

        fn remove_debugger(&self, target: &str, view: RegistryView) -> Result<(), DomainError> {
            self.entries.borrow_mut().remove(&(target.to_string(), view));
            Ok(())
        }

        fn list_all_targets(&self, view: RegistryView) -> Result<Vec<(String, String)>, DomainError> {
            let entries = self.entries.borrow();
            let result: Vec<_> = entries
                .iter()
                .filter(|((_, v), _)| *v == view)
                .map(|((t, _), d)| (t.clone(), d.clone()))
                .collect();
            Ok(result)
        }
    }

    struct FailingRepo {
        entries: RefCell<HashMap<(String, RegistryView), String>>,
        fail_target: String,
        fail_view: RegistryView,
        fail_debugger: String,
    }

    impl FailingRepo {
        fn with_conflict(
            target: &str,
            debugger: &str,
            fail_view: RegistryView,
            fail_debugger: &str,
        ) -> Self {
            let mut entries = HashMap::new();
            for view in RegistryView::all() {
                entries.insert((target.to_string(), *view), debugger.to_string());
            }
            Self {
                entries: RefCell::new(entries),
                fail_target: target.to_string(),
                fail_view,
                fail_debugger: fail_debugger.to_string(),
            }
        }
    }

    impl IfeoRepository for FailingRepo {
        fn get_debugger(
            &self,
            target: &str,
            view: RegistryView,
        ) -> Result<Option<String>, DomainError> {
            Ok(self
                .entries
                .borrow()
                .get(&(target.to_string(), view))
                .cloned())
        }

        fn set_debugger(
            &self,
            target: &str,
            view: RegistryView,
            path: &str,
        ) -> Result<(), DomainError> {
            if target.eq_ignore_ascii_case(&self.fail_target)
                && view == self.fail_view
                && path == self.fail_debugger
            {
                return Err(DomainError::Unknown("forced failure".into()));
            }
            self.entries
                .borrow_mut()
                .insert((target.to_string(), view), path.to_string());
            Ok(())
        }

        fn remove_debugger(&self, target: &str, view: RegistryView) -> Result<(), DomainError> {
            self.entries.borrow_mut().remove(&(target.to_string(), view));
            Ok(())
        }

        fn list_all_targets(&self, view: RegistryView) -> Result<Vec<(String, String)>, DomainError> {
            let entries = self.entries.borrow();
            let result: Vec<_> = entries
                .iter()
                .filter(|((_, v), _)| *v == view)
                .map(|((t, _), d)| (t.clone(), d.clone()))
                .collect();
            Ok(result)
        }
    }

    #[derive(Default)]
    struct MockBackupStore {
        entries: RefCell<Vec<BackupEntry>>,
    }

    impl MockBackupStore {
        fn entries(&self) -> Vec<BackupEntry> {
            self.entries.borrow().clone()
        }
    }

    impl BackupStore for MockBackupStore {
        fn save_entry(&self, entry: &BackupEntry) -> Result<(), DomainError> {
            self.entries
                .borrow_mut()
                .retain(|e| !(e.target == entry.target && e.view == entry.view));
            self.entries.borrow_mut().push(entry.clone());
            Ok(())
        }

        fn load_entry(
            &self,
            target: &str,
            view: RegistryView,
        ) -> Result<Option<BackupEntry>, DomainError> {
            Ok(self
                .entries
                .borrow()
                .iter()
                .find(|e| e.target == target && e.view == view)
                .cloned())
        }

        fn remove_entry(&self, target: &str, view: RegistryView) -> Result<(), DomainError> {
            self.entries
                .borrow_mut()
                .retain(|e| !(e.target == target && e.view == view));
            Ok(())
        }

        fn list_entries(&self) -> Result<Vec<BackupEntry>, DomainError> {
            Ok(self.entries.borrow().clone())
        }

        fn verify_integrity(&self) -> Result<bool, DomainError> {
            Ok(true)
        }

        fn clear(&self) -> Result<(), DomainError> {
            self.entries.borrow_mut().clear();
            Ok(())
        }
    }

    impl MockBackupStore {
        fn replace_all(&self, entries: Vec<BackupEntry>) {
            *self.entries.borrow_mut() = entries;
        }
    }

    struct MockClock;

    impl Clock for MockClock {
        fn now_ms(&self) -> u64 {
            0
        }

        fn now_iso8601(&self) -> String {
            "2024-01-01T00:00:00Z".into()
        }
    }

    struct MockSignatureVerifier;

    impl SignatureVerifier for MockSignatureVerifier {
        fn verify(&self, _path: &str) -> SignatureStatus {
            SignatureStatus::Unsigned
        }
    }

    #[derive(Default)]
    struct MockRegistryPort {
        unregistered: RefCell<Vec<String>>,
    }

    impl MockRegistryPort {
        fn unregistered(&self) -> Vec<String> {
            self.unregistered.borrow().clone()
        }
    }

    impl RegistryPort for MockRegistryPort {
        fn register(&self, target: &Target) -> Result<(), DomainError> {
            let _ = target;
            Ok(())
        }

        fn unregister(&self, target: &Target) -> Result<(), DomainError> {
            self.unregistered
                .borrow_mut()
                .push(target.exe_name().to_string());
            Ok(())
        }
    }

    fn backup_entry(view: RegistryView, original: Option<&str>) -> BackupEntry {
        BackupEntry {
            target: "powershell.exe".to_string(),
            view,
            original_debugger: original.map(|s| s.to_string()),
            our_debugger: EXPECTED_DEBUGGER.to_string(),
            timestamp: "2024-01-01T00:00:00Z".into(),
        }
    }
}
