//! 設定/セットアップ用の管理ユースケース。

use kh_domain::DomainError;
use kh_domain::model::{InstallConfig, RegistryView, Target};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct ApplyTargetsRequest {
    pub enable: Vec<String>,
    pub disable: Vec<String>,
    pub enabled_targets: Vec<String>,
    pub conflicts: Vec<ConflictDecision>,
}

#[derive(Clone, Debug)]
pub struct ConflictDecision {
    pub target: String,
    pub action: ConflictAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictAction {
    Respect,
    TakeOver,
    Quarantine,
    Abort,
}

#[derive(Clone, Debug)]
pub struct ApplyTargetsPlan {
    pub to_enable: Vec<String>,
    pub to_disable: Vec<String>,
    pub enabled_targets: Vec<String>,
    pub backups: Vec<BackupActionTarget>,
}

#[derive(Clone, Debug)]
pub struct BackupActionTarget {
    pub target: String,
    pub action: BackupAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackupAction {
    TakeOver,
    Quarantine,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonStringConflict {
    pub target: String,
    pub view: RegistryView,
}

pub trait AdminPort {
    fn apply_targets(&self, plan: &ApplyTargetsPlan) -> Result<(), DomainError>;

    fn scan_non_string_conflicts(
        &self,
        targets: &[String],
    ) -> Result<Vec<NonStringConflict>, DomainError>;

    fn backup_uninstall_state(
        &self,
        enabled_targets: &[String],
        actions: &BTreeMap<String, BackupAction>,
    ) -> Result<(), DomainError>;
}

pub struct AdminDeps<'a> {
    pub port: &'a dyn AdminPort,
}

pub struct AdminService<'a> {
    deps: AdminDeps<'a>,
}

impl<'a> AdminService<'a> {
    pub fn new(deps: AdminDeps<'a>) -> Self {
        Self { deps }
    }

    pub fn apply_targets(&self, request: ApplyTargetsRequest) -> Result<(), DomainError> {
        let plan = build_apply_targets_plan(request)?;
        if plan.to_enable.is_empty()
            && plan.to_disable.is_empty()
            && plan.enabled_targets.is_empty()
        {
            return Ok(());
        }
        self.deps.port.apply_targets(&plan)
    }

    pub fn scan_non_string_conflicts(
        &self,
        targets: &[String],
    ) -> Result<Vec<NonStringConflict>, DomainError> {
        let normalized = normalize_targets(targets);
        if normalized.is_empty() {
            return Ok(Vec::new());
        }
        self.deps.port.scan_non_string_conflicts(&normalized)
    }

    pub fn backup_uninstall_state(
        &self,
        config: &InstallConfig,
        conflict_actions: Option<&BTreeMap<String, ConflictAction>>,
    ) -> Result<(), DomainError> {
        let mut enabled: Vec<String> = config
            .targets
            .iter()
            .filter(|t| t.enabled())
            .map(|t| t.exe_name().to_string())
            .collect();
        enabled = normalize_targets(&enabled);
        if enabled.is_empty() {
            return Ok(());
        }

        let mut actions: BTreeMap<String, BackupAction> = BTreeMap::new();
        if let Some(map) = conflict_actions {
            for (target, action) in map {
                let normalized = target.to_ascii_lowercase();
                match action {
                    ConflictAction::TakeOver => {
                        actions.insert(normalized, BackupAction::TakeOver);
                    }
                    ConflictAction::Quarantine => {
                        actions.insert(normalized, BackupAction::Quarantine);
                    }
                    _ => {}
                }
            }
        }

        self.deps
            .port
            .backup_uninstall_state(&enabled, &actions)
    }
}

pub fn build_apply_targets_plan(
    request: ApplyTargetsRequest,
) -> Result<ApplyTargetsPlan, DomainError> {
    let mut to_enable = normalize_targets(&request.enable);
    let to_disable = normalize_targets(&request.disable);
    let mut enabled_targets = normalize_targets(&request.enabled_targets);

    let mut backups = Vec::new();
    for decision in request.conflicts {
        let normalized = decision.target.to_ascii_lowercase();
        match decision.action {
            ConflictAction::Respect => {
                enabled_targets.retain(|t| !t.eq_ignore_ascii_case(&normalized));
                to_enable.retain(|t| !t.eq_ignore_ascii_case(&normalized));
            }
            ConflictAction::Abort => {
                return Err(DomainError::ValidationError(format!(
                    "conflict resolution aborted for {}",
                    normalized
                )));
            }
            ConflictAction::TakeOver => backups.push(BackupActionTarget {
                target: normalized,
                action: BackupAction::TakeOver,
            }),
            ConflictAction::Quarantine => backups.push(BackupActionTarget {
                target: normalized,
                action: BackupAction::Quarantine,
            }),
        }
    }

    Ok(ApplyTargetsPlan {
        to_enable,
        to_disable,
        enabled_targets,
        backups,
    })
}

fn normalize_targets(list: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in list {
        let normalized = raw.to_ascii_lowercase();
        if Target::validate_name(&normalized).is_ok() {
            out.push(normalized);
        }
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct CapturePort {
        plan: Mutex<Option<ApplyTargetsPlan>>,
        backup: Mutex<Option<(Vec<String>, std::collections::BTreeMap<String, BackupAction>)>>,
    }

    impl AdminPort for CapturePort {
        fn apply_targets(&self, plan: &ApplyTargetsPlan) -> Result<(), DomainError> {
            let mut guard = self.plan.lock().unwrap();
            *guard = Some(plan.clone());
            Ok(())
        }

        fn scan_non_string_conflicts(
            &self,
            _targets: &[String],
        ) -> Result<Vec<NonStringConflict>, DomainError> {
            Ok(Vec::new())
        }

        fn backup_uninstall_state(
            &self,
            enabled_targets: &[String],
            actions: &std::collections::BTreeMap<String, BackupAction>,
        ) -> Result<(), DomainError> {
            let mut guard = self.backup.lock().unwrap();
            *guard = Some((enabled_targets.to_vec(), actions.clone()));
            Ok(())
        }
    }

    #[test]
    fn apply_targets_respect_removes_entries() {
        let port = CapturePort::default();
        let service = AdminService::new(AdminDeps { port: &port });

        let req = ApplyTargetsRequest {
            enable: vec!["Foo.exe".into(), "Bar.exe".into()],
            disable: vec!["Baz.exe".into()],
            enabled_targets: vec!["Foo.exe".into(), "Bar.exe".into()],
            conflicts: vec![ConflictDecision {
                target: "Bar.exe".into(),
                action: ConflictAction::Respect,
            }],
        };

        service.apply_targets(req).unwrap();
        let plan = port.plan.lock().unwrap().clone().unwrap();
        assert_eq!(plan.to_enable, vec!["foo.exe".to_string()]);
        assert_eq!(plan.to_disable, vec!["baz.exe".to_string()]);
        assert_eq!(plan.enabled_targets, vec!["foo.exe".to_string()]);
    }

    #[test]
    fn apply_targets_abort_returns_error() {
        let port = CapturePort::default();
        let service = AdminService::new(AdminDeps { port: &port });

        let req = ApplyTargetsRequest {
            enable: vec!["Foo.exe".into()],
            disable: vec![],
            enabled_targets: vec![],
            conflicts: vec![ConflictDecision {
                target: "Foo.exe".into(),
                action: ConflictAction::Abort,
            }],
        };

        assert!(service.apply_targets(req).is_err());
    }

    #[test]
    fn backup_uninstall_state_filters_enabled_targets() {
        let port = CapturePort::default();
        let service = AdminService::new(AdminDeps { port: &port });

        let mut cfg = InstallConfig::default();
        cfg.targets = vec![
            Target::new("Foo.exe", true).unwrap(),
            Target::new("Bar.exe", false).unwrap(),
        ];

        let mut conflicts = std::collections::BTreeMap::new();
        conflicts.insert("Foo.exe".to_string(), ConflictAction::TakeOver);
        conflicts.insert("Bar.exe".to_string(), ConflictAction::Respect);

        service
            .backup_uninstall_state(&cfg, Some(&conflicts))
            .unwrap();

        let (enabled, actions) = port.backup.lock().unwrap().clone().unwrap();
        assert_eq!(enabled, vec!["foo.exe".to_string()]);
        assert_eq!(
            actions.get("foo.exe"),
            Some(&BackupAction::TakeOver)
        );
        assert!(actions.get("bar.exe").is_none());
    }
}
