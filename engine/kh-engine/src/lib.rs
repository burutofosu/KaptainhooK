//! kh-engine: IFEO インストール／クリーンアップ／ステータス／競合検出などの
//! ワークフローを実装する層。ドメイン（kh-domain）のポートにのみ依存する。

use kh_domain::DomainError;
use kh_domain::model::{
    InstallConfig, PathHint, RegistryView, SignatureNoticeKind, SignatureStatus, Target,
};
use kh_domain::port::driven::{
    BackupEntry, BackupStore, Clock, IfeoRepository, RegistryPort, SignatureVerifier,
};
use kh_domain::service::ownership_service::{is_owned_debugger, normalize_debugger_exe};
use kh_domain::service::threat_service::{extract_path_hints, signature_notice};
use kh_domain::service::{UnregisterDecision, decide_unregister};

/// インストール結果の要約
/// 登録成功・解除成功のターゲット一覧を保持
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub registered: Vec<String>,   // 登録されたターゲット
    pub unregistered: Vec<String>, // 解除されたターゲット
}

/// クリーンアップ結果の要約
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupReport {
    pub removed: Vec<String>, // 削除されたターゲット
}

/// インストール計画を実行（レジストリに書き込み）
/// 有効なターゲットを登録し、無効なターゲットを解除する
pub fn apply_install(
    cfg: &InstallConfig,
    registry: &impl RegistryPort,
) -> Result<InstallReport, DomainError> {
    let mut registered = Vec::new();
    let mut unregistered = Vec::new();

    for target in &cfg.targets {
        if target.enabled() {
            registry.register(target)?;
            registered.push(target.exe_name().to_string());
        } else {
            registry.unregister(target)?;
            unregistered.push(target.exe_name().to_string());
        }
    }

    Ok(InstallReport {
        registered,
        unregistered,
    })
}

/// バックアップ付きインストール
/// 既存のデバッガ値を保存してから上書きする。
/// 失敗時は [`rollback_from_backup`] で復元可能。
pub fn install_with_backup(
    cfg: &InstallConfig,
    repo: &impl IfeoRepository,
    backup: &impl BackupStore,
    clock: &impl Clock,
    our_debugger: &str,
) -> Result<InstallReport, DomainError> {
    let mut registered = Vec::new();
    let mut unregistered = Vec::new();
    let timestamp = clock.now_iso8601();

    for target in &cfg.targets {
        if target.enabled() {
            for view in RegistryView::all() {
                let existing = repo.get_debugger(target.exe_name(), *view)?;

                // バックアップ保存
                let entry = BackupEntry {
                    target: target.exe_name().to_string(),
                    view: *view,
                    original_debugger: existing,
                    our_debugger: our_debugger.to_string(),
                    timestamp: timestamp.clone(),
                };
                backup.save_entry(&entry)?;

                repo.set_debugger(target.exe_name(), *view, our_debugger)?;
            }
            registered.push(target.exe_name().to_string());
        } else {
            // 無効ターゲット: 自分のエントリのみ削除（実際に削除した場合だけ記録）
            let mut removed_any = false;
            for view in RegistryView::all() {
                let existing = repo.get_debugger(target.exe_name(), *view)?;
                if let UnregisterDecision::Remove =
                    decide_unregister(existing.as_deref(), our_debugger)
                {
                    let entry = BackupEntry {
                        target: target.exe_name().to_string(),
                        view: *view,
                        original_debugger: existing.clone(),
                        our_debugger: String::new(), // 空=解除済み
                        timestamp: timestamp.clone(),
                    };
                    backup.save_entry(&entry)?;
                    repo.remove_debugger(target.exe_name(), *view)?;
                    removed_any = true;
                }
            }
            if removed_any {
                unregistered.push(target.exe_name().to_string());
            }
        }
    }

    Ok(InstallReport {
        registered,
        unregistered,
    })
}

/// バックアップからIFEOを復元する
/// 元のデバッガがあれば復元、なければ削除。
/// 成功後バックアップをクリア。復元したターゲット一覧を返す。
pub fn rollback_from_backup(
    backup: &impl BackupStore,
    repo: &impl IfeoRepository,
) -> Result<Vec<String>, DomainError> {
    let entries = backup.list_entries()?;
    let mut rolled_back = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for entry in &entries {
        let result = match &entry.original_debugger {
            Some(original) => repo.set_debugger(&entry.target, entry.view, original),
            None => repo.remove_debugger(&entry.target, entry.view),
        };
        if let Err(e) = result {
            errors.push(format!(
                "rollback failed for {} {:?}: {}",
                entry.target, entry.view, e
            ));
            continue;
        }

        if !rolled_back.contains(&entry.target) {
            rolled_back.push(entry.target.clone());
        }
    }

    if errors.is_empty() {
        backup.clear()?;
        Ok(rolled_back)
    } else {
        Err(DomainError::Unknown(errors.join("; ")))
    }
}

/// 全ターゲットをIFEOから削除（所有権チェックなし）。
/// 注意: 他製品のエントリも削除する。通常は [`safe_cleanup`] を使用。
pub fn cleanup(
    targets: &[Target],
    registry: &impl RegistryPort,
) -> Result<CleanupReport, DomainError> {
    let mut removed = Vec::new();
    for target in targets {
        registry.unregister(target)?;
        removed.push(target.exe_name().to_string());
    }
    Ok(CleanupReport { removed })
}

/// 安全クリーンアップの結果
/// 他製品のエントリはスキップした詳細を含む
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeCleanupReport {
    /// 削除したターゲット（自社エントリ）
    pub removed: Vec<String>,
    /// スキップしたターゲット（他製品）: (ターゲット名, 既存パス)
    pub skipped: Vec<(String, String)>,
    /// 未登録だったターゲット
    pub not_registered: Vec<String>,
}

/// 自社エントリのみ安全に削除
/// 他製品のエントリはスキップしてレポートに記録。
pub fn safe_cleanup(
    targets: &[Target],
    repo: &impl IfeoRepository,
    our_debugger: &str,
) -> Result<SafeCleanupReport, DomainError> {
    let mut report = SafeCleanupReport {
        removed: Vec::new(),
        skipped: Vec::new(),
        not_registered: Vec::new(),
    };

    for target in targets {
        let mut target_removed = false;
        let mut target_skipped = false;
        let mut target_not_registered = true;

        for view in RegistryView::all() {
            let current = repo.get_debugger(target.exe_name(), *view)?;

            match decide_unregister(current.as_deref(), our_debugger) {
                UnregisterDecision::Remove => {
                    repo.remove_debugger(target.exe_name(), *view)?;
                    target_removed = true;
                    target_not_registered = false;
                }
                UnregisterDecision::Skip { existing } => {
                    // ターゲットごとに1回だけスキップ記録
                    if !target_skipped {
                        report
                            .skipped
                            .push((target.exe_name().to_string(), existing));
                        target_skipped = true;
                    }
                    target_not_registered = false;
                }
                UnregisterDecision::NotRegistered => {
                    // 他ビューも確認
                }
            }
        }

        // 結果を分類
        if target_removed {
            report.removed.push(target.exe_name().to_string());
        } else if target_not_registered && !target_skipped {
            report.not_registered.push(target.exe_name().to_string());
        }
    }

    Ok(report)
}

/// 有効ターゲットのIFEO状態を再整合
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    /// 再適用したターゲット
    pub repaired: Vec<String>,
    /// 競合のためスキップしたターゲット: (ターゲット名, 既存パス)
    pub skipped: Vec<(String, String)>,
    /// 変更なしのターゲット
    pub unchanged: Vec<String>,
}

pub fn reconcile_enabled_targets(
    enabled_targets: &[String],
    repo: &impl IfeoRepository,
    our_debugger: &str,
) -> Result<ReconcileReport, DomainError> {
    let mut report = ReconcileReport {
        repaired: Vec::new(),
        skipped: Vec::new(),
        unchanged: Vec::new(),
    };

    for raw in enabled_targets {
        let target = raw.to_ascii_lowercase();
        if Target::validate_name(&target).is_err() {
            continue;
        }

        let mut foreign: Option<String> = None;
        let mut missing_views: Vec<RegistryView> = Vec::new();

        for view in RegistryView::all() {
            let current = repo.get_debugger(&target, *view)?;
            match current {
                None => missing_views.push(*view),
                Some(ref value) if value.trim().is_empty() => missing_views.push(*view),
                Some(ref value) if is_owned_debugger(value, our_debugger) => {}
                Some(value) => {
                    foreign = Some(value);
                    break;
                }
            }
        }

        if let Some(existing) = foreign {
            report.skipped.push((target.clone(), existing));
            continue;
        }

        if missing_views.is_empty() {
            report.unchanged.push(target.clone());
            continue;
        }

        for view in missing_views {
            repo.set_debugger(&target, view, our_debugger)?;
        }
        report.repaired.push(target.clone());
    }

    report.repaired.sort();
    report.skipped.sort_by(|a, b| a.0.cmp(&b.0));
    report.unchanged.sort();

    Ok(report)
}

/// 単一ターゲットを安全に解除
/// 削除した場合Ok(true)、スキップした場合Ok(false)を返す。
pub fn safe_unregister_target(
    target: &Target,
    repo: &impl IfeoRepository,
    our_debugger: &str,
) -> Result<bool, DomainError> {
    let mut any_removed = false;

    for view in RegistryView::all() {
        let current = repo.get_debugger(target.exe_name(), *view)?;

        if let UnregisterDecision::Remove = decide_unregister(current.as_deref(), our_debugger) {
            repo.remove_debugger(target.exe_name(), *view)?;
            any_removed = true;
        }
    }

    Ok(any_removed)
}

/// 設定済みターゲットの現在のデバッガエントリを返す
pub fn status(
    cfg: &InstallConfig,
    repo: &impl IfeoRepository,
) -> Result<Vec<StatusEntry>, DomainError> {
    let mut entries = Vec::new();
    for target in &cfg.targets {
        for view in RegistryView::all().iter() {
            let dbg = repo.get_debugger(target.exe_name(), *view)?;
            entries.push(StatusEntry {
                target: target.exe_name().to_string(),
                enabled: target.enabled(),
                debugger: dbg,
                view: *view,
            });
        }
    }
    Ok(entries)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusEntry {
    pub target: String,
    pub enabled: bool,
    pub debugger: Option<String>,
    pub view: RegistryView,
}

/// 競合情報（既存デバッガが期待値と異なる場合）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictEntry {
    pub target: String,
    pub view: RegistryView,
    pub existing_debugger: String,
    pub expected_debugger: String,
    pub signature: SignatureStatus,
    pub signature_notice: Option<SignatureNoticeKind>,
    pub path_hints: Vec<PathHint>,
}

/// 競合を検出: デバッガが設定済みで期待パスと異なるエントリを返す
pub fn detect_conflicts(
    cfg: &InstallConfig,
    repo: &impl IfeoRepository,
    sig: &impl SignatureVerifier,
    expected_debugger: &str,
) -> Result<Vec<ConflictEntry>, DomainError> {
    let mut conflicts = Vec::new();
    for target in &cfg.targets {
        for view in RegistryView::all().iter() {
            if let Some(dbg) = repo.get_debugger(target.exe_name(), *view)? {
                let current_exe = normalize_debugger_exe(&dbg).unwrap_or_else(|| dbg.clone());
                let expected_exe = normalize_debugger_exe(expected_debugger)
                    .unwrap_or_else(|| expected_debugger.to_string());
                if !current_exe.eq_ignore_ascii_case(&expected_exe) {
                    let signature = sig.verify(&current_exe);
                    let path_hints = extract_path_hints(&current_exe);
                    let signature_notice = signature_notice(&signature);
                    conflicts.push(ConflictEntry {
                        target: target.exe_name().to_string(),
                        view: *view,
                        existing_debugger: dbg,
                        expected_debugger: expected_debugger.to_string(),
                        signature,
                        signature_notice,
                        path_hints,
                    });
                }
            }
        }
    }
    Ok(conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kh_domain::model::{NudgeMessage, Target};
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockRegistry {
        map: RefCell<HashMap<String, String>>,
    }

    impl RegistryPort for MockRegistry {
        fn register(&self, target: &Target) -> Result<(), DomainError> {
            self.map
                .borrow_mut()
                .insert(target.exe_name().to_string(), "dbg.exe".into());
            Ok(())
        }
        fn unregister(&self, target: &Target) -> Result<(), DomainError> {
            self.map.borrow_mut().remove(target.exe_name());
            Ok(())
        }
    }

    impl IfeoRepository for MockRegistry {
        fn get_debugger(
            &self,
            target: &str,
            _view: kh_domain::model::RegistryView,
        ) -> Result<Option<String>, DomainError> {
            Ok(self.map.borrow().get(target).cloned())
        }
        fn set_debugger(
            &self,
            _target: &str,
            _view: kh_domain::model::RegistryView,
            _path: &str,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        fn remove_debugger(
            &self,
            _target: &str,
            _view: kh_domain::model::RegistryView,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        fn list_all_targets(
            &self,
            _view: kh_domain::model::RegistryView,
        ) -> Result<Vec<(String, String)>, DomainError> {
            Ok(self
                .map
                .borrow()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }
    }

    #[test]
    fn install_and_status() {
        let cfg = InstallConfig {
            version: "1".into(),
            targets: vec![Target::new("powershell.exe", true).unwrap()],
            friction: Default::default(),
            nudge_messages: vec![NudgeMessage::default()],
            auto_restore_seconds: 5,
            search_paths: Vec::new(),
            policy: Default::default(),
            language: Default::default(),
            reaction: Default::default(),
            background: Default::default(),
        };
        let registry = MockRegistry::default();

        let report = apply_install(&cfg, &registry).unwrap();
        assert_eq!(report.registered, vec!["powershell.exe"]);

        let status = status(&cfg, &registry).unwrap();
        assert_eq!(status[0].debugger.as_deref(), Some("dbg.exe"));
    }

    #[test]
    fn cleanup_unregisters() {
        let target = Target::new("cmd.exe", true).unwrap();
        let registry = MockRegistry::default();
        registry.register(&target).unwrap();

        let report = cleanup(&[target.clone()], &registry).unwrap();
        assert_eq!(report.removed, vec!["cmd.exe"]);
        let after = status(
            &InstallConfig {
                version: "1".into(),
                targets: vec![target],
                friction: Default::default(),
                nudge_messages: vec![NudgeMessage::default()],
                auto_restore_seconds: 5,
                search_paths: Vec::new(),
                policy: Default::default(),
                language: Default::default(),
                reaction: Default::default(),
                background: Default::default(),
            },
            &registry,
        )
        .unwrap();
        assert!(after[0].debugger.is_none());
    }

    #[derive(Default)]
    struct MockIfeoRepo {
        entries: RefCell<HashMap<(String, RegistryView), String>>,
    }

    impl MockIfeoRepo {
        fn set(&self, target: &str, view: RegistryView, debugger: &str) {
            self.entries
                .borrow_mut()
                .insert((target.to_string(), view), debugger.to_string());
        }
    }

    #[derive(Default)]
    struct MockBackupStore {
        entries: RefCell<Vec<BackupEntry>>,
    }

    impl MockBackupStore {
        fn snapshot(&self) -> Vec<BackupEntry> {
            self.entries.borrow().clone()
        }
    }

    impl BackupStore for MockBackupStore {
        fn save_entry(&self, entry: &BackupEntry) -> Result<(), DomainError> {
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

    #[derive(Default)]
    struct MockClock;

    impl Clock for MockClock {
        fn now_ms(&self) -> u64 {
            0
        }

        fn now_iso8601(&self) -> String {
            "2024-01-01T00:00:00Z".into()
        }
    }

    impl IfeoRepository for MockIfeoRepo {
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
            self.entries
                .borrow_mut()
                .remove(&(target.to_string(), view));
            Ok(())
        }

        fn list_all_targets(
            &self,
            view: RegistryView,
        ) -> Result<Vec<(String, String)>, DomainError> {
            let entries = self.entries.borrow();
            let result: Vec<_> = entries
                .iter()
                .filter(|((_, v), _)| *v == view)
                .map(|((t, _), d)| (t.clone(), d.clone()))
                .collect();
            Ok(result)
        }
    }

    #[test]
    fn safe_cleanup_removes_our_entries() {
        let repo = MockIfeoRepo::default();
        let our_debugger = r"C:\KaptainhooK\kh-bootstrap.exe";

        repo.set("powershell.exe", RegistryView::Bit64, our_debugger);
        repo.set("powershell.exe", RegistryView::Bit32, our_debugger);

        let targets = vec![Target::new("powershell.exe", true).unwrap()];
        let report = safe_cleanup(&targets, &repo, our_debugger).unwrap();

        assert_eq!(report.removed, vec!["powershell.exe"]);
        assert!(report.skipped.is_empty());
        assert!(
            repo.get_debugger("powershell.exe", RegistryView::Bit64)
                .unwrap()
                .is_none()
        );
        assert!(
            repo.get_debugger("powershell.exe", RegistryView::Bit32)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn safe_cleanup_skips_other_products() {
        let repo = MockIfeoRepo::default();
        let our_debugger = r"C:\KaptainhooK\kh-bootstrap.exe";
        let other_debugger = r"C:\OtherProduct\debugger.exe";

        repo.set("powershell.exe", RegistryView::Bit64, other_debugger);

        let targets = vec![Target::new("powershell.exe", true).unwrap()];
        let report = safe_cleanup(&targets, &repo, our_debugger).unwrap();

        assert!(report.removed.is_empty());
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].0, "powershell.exe");
        assert_eq!(report.skipped[0].1, other_debugger);
        assert_eq!(
            repo.get_debugger("powershell.exe", RegistryView::Bit64)
                .unwrap(),
            Some(other_debugger.to_string())
        );
    }

    #[test]
    fn safe_cleanup_partial_remove_is_reported() {
        let repo = MockIfeoRepo::default();
        let our_debugger = r"C:\KaptainhooK\kh-bootstrap.exe";
        let other_debugger = r"C:\OtherProduct\debugger.exe";

        repo.set("powershell.exe", RegistryView::Bit64, our_debugger);
        repo.set("powershell.exe", RegistryView::Bit32, other_debugger);

        let targets = vec![Target::new("powershell.exe", true).unwrap()];
        let report = safe_cleanup(&targets, &repo, our_debugger).unwrap();

        assert_eq!(report.removed, vec!["powershell.exe"]);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].0, "powershell.exe");
        assert_eq!(report.skipped[0].1, other_debugger);
    }


    #[test]
    fn safe_cleanup_handles_not_registered() {
        let repo = MockIfeoRepo::default();
        let our_debugger = r"C:\KaptainhooK\kh-bootstrap.exe";

        let targets = vec![Target::new("powershell.exe", true).unwrap()];
        let report = safe_cleanup(&targets, &repo, our_debugger).unwrap();

        assert!(report.removed.is_empty());
        assert!(report.skipped.is_empty());
        assert_eq!(report.not_registered, vec!["powershell.exe"]);
    }

    #[test]
    fn safe_cleanup_mixed_scenario() {
        let repo = MockIfeoRepo::default();
        let our_debugger = r"C:\KaptainhooK\kh-bootstrap.exe";
        let other_debugger = r"C:\OtherProduct\debugger.exe";

        repo.set("powershell.exe", RegistryView::Bit64, our_debugger);
        repo.set("cmd.exe", RegistryView::Bit64, other_debugger);

        let targets = vec![
            Target::new("powershell.exe", true).unwrap(),
            Target::new("cmd.exe", true).unwrap(),
            Target::new("wscript.exe", true).unwrap(),
        ];
        let report = safe_cleanup(&targets, &repo, our_debugger).unwrap();

        assert_eq!(report.removed, vec!["powershell.exe"]);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].0, "cmd.exe");
        assert_eq!(report.not_registered, vec!["wscript.exe"]);
    }

    #[test]
    fn reconcile_repairs_missing_views() {
        let repo = MockIfeoRepo::default();
        let our_debugger = r"C:\KaptainhooK\kh-bootstrap.exe";

        repo.set("powershell.exe", RegistryView::Bit64, our_debugger);

        let enabled = vec!["powershell.exe".to_string()];
        let report = reconcile_enabled_targets(&enabled, &repo, our_debugger).unwrap();

        assert_eq!(report.repaired, vec!["powershell.exe"]);
        assert!(report.skipped.is_empty());
        assert!(report.unchanged.is_empty());
        assert_eq!(
            repo.get_debugger("powershell.exe", RegistryView::Bit32)
                .unwrap()
                .as_deref(),
            Some(our_debugger)
        );
    }

    #[test]
    fn reconcile_skips_foreign_targets() {
        let repo = MockIfeoRepo::default();
        let our_debugger = r"C:\KaptainhooK\kh-bootstrap.exe";
        let other_debugger = r"C:\OtherProduct\debugger.exe";

        repo.set("powershell.exe", RegistryView::Bit64, other_debugger);

        let enabled = vec!["powershell.exe".to_string()];
        let report = reconcile_enabled_targets(&enabled, &repo, our_debugger).unwrap();

        assert!(report.repaired.is_empty());
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].0, "powershell.exe");
        assert_eq!(report.skipped[0].1, other_debugger);
        assert!(repo
            .get_debugger("powershell.exe", RegistryView::Bit32)
            .unwrap()
            .is_none());
    }

    fn base_config(targets: Vec<Target>) -> InstallConfig {
        InstallConfig {
            version: "1".into(),
            targets,
            friction: Default::default(),
            nudge_messages: vec![NudgeMessage::default()],
            auto_restore_seconds: 5,
            search_paths: Vec::new(),
            policy: Default::default(),
            language: Default::default(),
            reaction: Default::default(),
            background: Default::default(),
        }
    }

    #[test]
    fn install_with_backup_skips_other_products_for_disabled_targets() {
        let repo = MockIfeoRepo::default();
        let backup = MockBackupStore::default();
        let clock = MockClock::default();
        let other = r"C:\OtherProduct\debugger.exe";
        repo.set("cmd.exe", RegistryView::Bit64, other);
        repo.set("cmd.exe", RegistryView::Bit32, other);

        let target = Target::new("cmd.exe", false).unwrap();
        let cfg = base_config(vec![target]);
        let our = r"C:\Program Files\KaptainhooK\kh-bootstrap.exe";

        let report = install_with_backup(&cfg, &repo, &backup, &clock, our).unwrap();
        assert!(report.registered.is_empty());
        assert!(report.unregistered.is_empty());
        assert_eq!(
            repo.get_debugger("cmd.exe", RegistryView::Bit64)
                .unwrap()
                .as_deref(),
            Some(other)
        );
        assert!(backup.snapshot().is_empty());
    }

    #[test]
    fn install_with_backup_removes_our_entries_for_disabled_targets() {
        let repo = MockIfeoRepo::default();
        let backup = MockBackupStore::default();
        let clock = MockClock::default();
        let our = r"C:\Program Files\KaptainhooK\kh-bootstrap.exe";
        repo.set("powershell.exe", RegistryView::Bit64, our);
        repo.set("powershell.exe", RegistryView::Bit32, our);
        let target = Target::new("powershell.exe", false).unwrap();
        let cfg = base_config(vec![target]);

        let report = install_with_backup(&cfg, &repo, &backup, &clock, our).unwrap();
        assert_eq!(report.unregistered, vec!["powershell.exe"]);
        assert!(
            repo.get_debugger("powershell.exe", RegistryView::Bit64)
                .unwrap()
                .is_none()
        );
        let entries = backup.snapshot();
        assert_eq!(entries.len(), 2);
        for entry in entries {
            assert_eq!(entry.target, "powershell.exe");
            assert_eq!(entry.our_debugger, "");
        }
    }
}
