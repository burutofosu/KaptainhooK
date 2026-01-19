//! 復元タスク処理。
//! LeaseState と有効ターゲットから復元対象を決める。

use kh_adapter_registry::{
    DebuggerOwnership, RegistryAdapter, TargetsRegistry, acquire_ifeo_mutex, classify_debugger_value,
};
use kh_domain::model::{RegistryView, Target};
use kh_domain::port::driven::{IfeoRepository, LeaseStore};

pub fn run_restore() -> crate::error::Result<()> {
    let _ifeo_lock = match acquire_ifeo_mutex(5000) {
        Ok(lock) => lock,
        Err(_) => {
            // 他のIFEO操作が進行中のため競合を避ける
            return Ok(());
        }
    };

    let registry = RegistryAdapter::new();
    let our_debugger = kh_adapter_registry::default_debugger_path();

    // 有効ターゲットが読めなくても、期限切れLeaseは復元する。
    let enabled: std::collections::HashSet<String> = TargetsRegistry::new()
        .read_enabled_targets()
        .map(|s| s.into_iter().collect())
        .unwrap_or_default();

    let lease = registry.read_lease().ok().flatten();
    let now = now_ms();

    let mut restore_targets: std::collections::HashSet<String> = enabled;

    // Lease: 期限内は除外、期限切れは対象に追加
    let mut expired_lease_target: Option<String> = None;
    if let Some(ref lease) = lease {
        if now < lease.expires_at_ms {
            restore_targets.remove(&lease.target);
        } else {
            restore_targets.insert(lease.target.clone());
            expired_lease_target = Some(lease.target.clone());
        }
    }

    if restore_targets.is_empty() {
        // 期限内は何もしない。期限切れで空ならLeaseをクリア。
        if let Some(lease) = lease {
            if now >= lease.expires_at_ms {
                let _ = registry.clear_lease();
            }
        }
        return Ok(());
    }

    let mut expired_lease_restored_ok = false;

    for target in restore_targets {
        if Target::validate_name(&target).is_err() {
            continue;
        }
        let ok = restore_one_target(&registry, &our_debugger, &target);
        if expired_lease_target.as_deref() == Some(target.as_str()) {
            expired_lease_restored_ok = ok;
        }
    }

    // 期限切れLeaseは「復元すべき状態」なので、復元に成功したらクリアする。
    // 失敗した場合はクリアせず残し、次回のrestoreタスク実行で再試行できるようにする。
    if let Some(lease) = lease {
        if now >= lease.expires_at_ms {
            if expired_lease_target.is_none() || expired_lease_restored_ok {
                let _ = registry.clear_lease();
            }
        }
    }

    Ok(())
}

fn restore_one_target(registry: &RegistryAdapter, our_debugger: &str, target: &str) -> bool {
    let mut ok = true;
    for view in RegistryView::all() {
        let current = match registry.get_debugger_value(target, *view) {
            Ok(v) => v,
            Err(_) => {
                ok = false;
                continue;
            }
        };

        match classify_debugger_value(current, our_debugger) {
            DebuggerOwnership::Foreign => {
                ok = false;
                continue;
            }
            DebuggerOwnership::Owned | DebuggerOwnership::Disabled => {
                if registry.set_debugger(target, *view, our_debugger).is_err() {
                    ok = false;
                }
            }
        }
    }
    ok
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    (ms.min(u64::MAX as u128)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use kh_domain::port::driven::LeaseState;
    use std::collections::HashSet;

    fn set(strings: &[&str]) -> HashSet<String> {
        strings.iter().map(|s| s.to_string()).collect()
    }

    fn compute(enabled: HashSet<String>, lease: Option<LeaseState>, now_ms: u64) -> HashSet<String> {
        let mut restore_targets = enabled;
        let mut expired_lease_target = None;

        if let Some(ref lease) = lease {
            if now_ms < lease.expires_at_ms {
                restore_targets.remove(&lease.target);
            } else {
                restore_targets.insert(lease.target.clone());
                expired_lease_target = Some(lease.target.clone());
            }
        }

        // mimic empty behaviour
        if restore_targets.is_empty() {
            if let Some(lease) = lease {
                if now_ms >= lease.expires_at_ms {
                    // would clear
                    let _ = expired_lease_target;
                }
            }
        }
        restore_targets
    }

    #[test]
    fn lease_active_excludes_target() {
        let enabled = set(&["powershell.exe", "cmd.exe"]);
        let lease = LeaseState {
            target: "powershell.exe".into(),
            expires_at_ms: 2000,
        };
        let out = compute(enabled, Some(lease), 1500);
        assert!(out.contains("cmd.exe"));
        assert!(!out.contains("powershell.exe"));
    }

    #[test]
    fn lease_expired_includes_target_even_if_enabled_empty() {
        let enabled = HashSet::new();
        let lease = LeaseState {
            target: "powershell.exe".into(),
            expires_at_ms: 1000,
        };
        let out = compute(enabled, Some(lease), 1500);
        assert!(out.contains("powershell.exe"));
    }
}
