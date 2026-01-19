//! サービス用ランタイム配線。

use crate::error::{Result as AppResult, err};
use crate::paths;
use kh_adapter_fs::FsAdapter;
use kh_adapter_registry::{
    DebuggerOwnership, DebuggerValue, RegistryAdapter, TargetsRegistry, acquire_ifeo_mutex,
    classify_debugger_value,
};
use kh_adapter_service_ipc::{
    BeginBypassResponse, ClientContext, CompleteBypassResponse, DEFAULT_TTL_MS, ErrorResponse,
    ServiceErrorCode, ServiceErrorMessageId, ServiceIpcServer, ServiceRequest, ServiceResponse,
};
use kh_adapter_task::{RestoreTaskRunner, DEFAULT_RESTORE_TASK_NAME};
use kh_domain::model::{normalize_exe_name, InstallConfig, RegistryView, Target};
use kh_domain::port::driven::{ConfigRepository, IfeoRepository, LeaseState, LeaseStore, LogWriter, OperationLogRecord, RestoreKicker};
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PROTOCOL_VERSION: u32 = kh_adapter_service_ipc::PROTOCOL_VERSION;

pub struct ServiceRuntime {
    server: ServiceIpcServer,
    state: Arc<Mutex<ServiceState>>,
}

struct ServiceState {
    registry: RegistryAdapter,
    debugger_path: String,
    restore_kicker: RestoreTaskRunner,
    in_progress: bool,
    leases: HashMap<String, Lease>,
}

#[derive(Clone)]
struct Lease {
    target: String,
    expires_at: Instant,
    client_pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreOutcome {
    Ok,
    Busy,
    ForeignDetected,
    Failed,
}

impl RestoreOutcome {
    fn is_ok(self) -> bool {
        matches!(self, RestoreOutcome::Ok)
    }
}

fn error_response(code: ServiceErrorCode, message_id: Option<ServiceErrorMessageId>) -> ServiceResponse {
    ServiceResponse::Error(ErrorResponse {
        protocol_version: PROTOCOL_VERSION,
        error_code: code,
        message_id,
    })
}

fn error_with_id(code: ServiceErrorCode, id: ServiceErrorMessageId) -> ServiceResponse {
    error_response(code, Some(id))
}

fn error_simple(code: ServiceErrorCode) -> ServiceResponse {
    error_response(code, None)
}

fn begin_response(lease_id: String, ttl_ms: u32) -> ServiceResponse {
    ServiceResponse::BeginBypass(BeginBypassResponse {
        protocol_version: PROTOCOL_VERSION,
        lease_id,
        ttl_ms,
    })
}

fn complete_response(restored_ok: bool) -> ServiceResponse {
    ServiceResponse::CompleteBypass(CompleteBypassResponse {
        protocol_version: PROTOCOL_VERSION,
        restored_ok,
    })
}

impl ServiceRuntime {
    pub fn new() -> AppResult<Self> {
        let registry = RegistryAdapter::new();
        let debugger_path = kh_adapter_registry::default_debugger_path();
        Ok(Self {
            server: ServiceIpcServer::new(),
            state: Arc::new(Mutex::new(ServiceState {
                registry,
                debugger_path,
                restore_kicker: RestoreTaskRunner::new(DEFAULT_RESTORE_TASK_NAME),
                in_progress: false,
                leases: HashMap::new(),
            })),
        })
    }

    pub fn run(&self) -> AppResult<()> {
        let state = Arc::clone(&self.state);
        self.server
            .run_with_context(move |request, ctx| handle_request(&state, request, ctx))
            .map_err(|e| err(e.to_string()))
    }

    pub fn run_until(&self, stop: &'static AtomicBool) -> AppResult<()> {
        let state = Arc::clone(&self.state);
        self.server
            .run_with_context_until(stop, move |request, ctx| handle_request(&state, request, ctx))
            .map_err(|e| err(e.to_string()))
    }
}

/// IPCサーバーを起こして停止要求を検知させる
pub fn poke_service_ipc() -> AppResult<()> {
    kh_adapter_service_ipc::poke_server(kh_adapter_service_ipc::PIPE_NAME)
        .map_err(|e| err(e.to_string()))
}

fn handle_request(
    state: &Arc<Mutex<ServiceState>>,
    request: ServiceRequest,
    ctx: ClientContext,
) -> ServiceResponse {
    match request {
        ServiceRequest::BeginBypass(req) => handle_begin(state, req, ctx),
        ServiceRequest::CompleteBypass(req) => handle_complete(state, req, ctx),
    }
}

fn handle_begin(
    state: &Arc<Mutex<ServiceState>>,
    req: kh_adapter_service_ipc::BeginBypassRequest,
    ctx: ClientContext,
) -> ServiceResponse {
    if req.protocol_version != PROTOCOL_VERSION {
        return error_simple(ServiceErrorCode::ProtocolVersionMismatch);
    }

    let normalized = normalize_exe_name(req.target_exe);
    if Target::validate_name(&normalized).is_err() {
        return error_with_id(
            ServiceErrorCode::TargetNotAllowed,
            ServiceErrorMessageId::InvalidTargetName,
        );
    }

    let allowed = match TargetsRegistry::new().read_enabled_targets() {
        Ok(list) => list,
        Err(_) => {
            return error_with_id(
                ServiceErrorCode::TargetsUnavailable,
                ServiceErrorMessageId::FailedReadProtectedTargets,
            );
        }
    };
    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            eprintln!("[ERROR] ServiceState mutex poisoned in handle_begin");
            eprintln!("[ERROR] {:?}", poisoned);
            return error_with_id(
                ServiceErrorCode::InternalError,
                ServiceErrorMessageId::StateLockPoisoned,
            );
        }
    };

    if !allowed.contains(&normalized)
        && !is_owned_ifeo_target(&guard.registry, &normalized, &guard.debugger_path)
    {
        return error_simple(ServiceErrorCode::TargetNotAllowed);
    }

    let ttl_ms = load_restore_ttl_ms();

    // サービスが再起動しても「バイパス中」を検出できるよう、HKLM の LeaseState を参照する。
    // - 期限内: 問答無用で Busy
    // - 期限切れ: 復元を試み、復元できたら LeaseState をクリアしてから処理続行
    let now = now_ms();
    match guard.registry.read_lease() {
        Ok(Some(lease)) => {
            if now < lease.expires_at_ms {
                return error_simple(ServiceErrorCode::Busy);
            }

            // 期限切れ(=復元すべき状態)なので、まず復元を試みる
            let outcome = restore_locked(&mut guard, &lease.target);
            match outcome {
                RestoreOutcome::Ok => {
                    if let Err(e) = guard.registry.clear_lease() {
                        eprintln!("[WARN] Failed to clear stale LeaseState: {}", e);
                    }
                }
                RestoreOutcome::ForeignDetected => {
                    let _ = guard.registry.clear_lease(); // 競合は解消できないので Lease は残しても意味が薄い
                    return error_with_id(
                        ServiceErrorCode::ForeignDetected,
                        ServiceErrorMessageId::ForeignDetectedDuringRestore,
                    );
                }
                RestoreOutcome::Busy => {
                    return error_simple(ServiceErrorCode::Busy);
                }
                RestoreOutcome::Failed => {
                    return error_with_id(
                        ServiceErrorCode::InternalError,
                        ServiceErrorMessageId::FailedRestoreStaleLease,
                    );
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("[ERROR] Failed to read LeaseState: {}", e);
            return error_with_id(
                ServiceErrorCode::InternalError,
                ServiceErrorMessageId::FailedReadLeaseState,
            );
        }
    }

    if guard.in_progress {
        return error_simple(ServiceErrorCode::Busy);
    }

    // 期限後に確実に復元が走るよう、タスクスケジューラへ「遅延実行」を依頼する。
    if let Err(_) = guard.restore_kicker.kick_restore_after(ttl_ms) {
        return error_with_id(
            ServiceErrorCode::InternalError,
            ServiceErrorMessageId::FailedKickRestoreTask,
        );
    }

    let lease_id = new_guid_string();
    let expires_at = Instant::now() + Duration::from_millis(ttl_ms as u64);
    guard.in_progress = true;

    let disable_result: std::result::Result<(), ServiceResponse> = (|| {
        let _ifeo_lock = match acquire_ifeo_mutex(0) {
            Ok(lock) => lock,
            Err(kh_domain::error::DomainError::Timeout(_)) => {
                return Err(error_simple(ServiceErrorCode::Busy));
            }
            Err(_) => {
                return Err(error_with_id(
                    ServiceErrorCode::InternalError,
                    ServiceErrorMessageId::FailedAcquireIfeoMutex,
                ));
            }
        };

        let our_debugger = guard.debugger_path.clone();
        let mut current_per_view: Vec<(RegistryView, Option<DebuggerValue>, DebuggerOwnership)> =
            Vec::new();
        for view in RegistryView::all() {
            match guard.registry.get_debugger_value(&normalized, *view) {
                Ok(current) => {
                    let ownership = classify_debugger_value(current.clone(), &our_debugger);
                    current_per_view.push((*view, current, ownership));
                }
                Err(_) => {
                    return Err(error_simple(ServiceErrorCode::InternalError));
                }
            }
        }

        for (_view, _current, ownership) in &current_per_view {
            match ownership {
                DebuggerOwnership::Foreign => {
                    return Err(error_with_id(
                        ServiceErrorCode::ForeignDetected,
                        ServiceErrorMessageId::ForeignDebuggerInView,
                    ));
                }
                DebuggerOwnership::Disabled => {
                    return Err(error_with_id(
                        ServiceErrorCode::InternalError,
                        ServiceErrorMessageId::IfeoEntryMissingInView,
                    ));
                }
                DebuggerOwnership::Owned => {}
            }
        }

        // 復元用に LeaseState を残す（IFEO変更前）
        let expires_at_ms = now_ms().saturating_add(ttl_ms as u64);
        let lease_state = LeaseState {
            target: normalized.clone(),
            expires_at_ms,
        };
        if guard.registry.write_lease(&lease_state).is_err() {
            return Err(error_with_id(
                ServiceErrorCode::InternalError,
                ServiceErrorMessageId::FailedWriteLeaseState,
            ));
        }

        let mut removed_views: Vec<RegistryView> = Vec::new();
        for (view, _current, ownership) in current_per_view {
            if matches!(ownership, DebuggerOwnership::Owned) {
                if guard.registry.remove_debugger(&normalized, view).is_err() {
                    // rollback
                    for restored_view in removed_views {
                        let _ = guard
                            .registry
                            .set_debugger(&normalized, restored_view, &our_debugger);
                    }
                    let _ = guard.registry.clear_lease();
                    return Err(error_with_id(
                        ServiceErrorCode::InternalError,
                        ServiceErrorMessageId::FailedDisableIfeo,
                    ));
                }
                removed_views.push(view);
            }
        }
        Ok(())
    })();

    if let Err(response) = disable_result {
        guard.in_progress = false;
        return response;
    }

    guard.leases.insert(
        lease_id.clone(),
        Lease {
            target: normalized.clone(),
            expires_at,
            client_pid: ctx.pid,
        },
    );

    let state_clone = Arc::clone(state);
    let lease_id_for_timer = lease_id.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(ttl_ms as u64));
        let mut guard = match state_clone.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                eprintln!(
                    "[ERROR] TTL timer: ServiceState mutex poisoned; lease_id={}",
                    lease_id_for_timer
                );
                eprintln!("[ERROR] TTL timer detail: {:?}", poisoned);
                return;
            }
        };
        let (expires_at, target) = match guard.leases.get(&lease_id_for_timer) {
            Some(l) => (l.expires_at, l.target.clone()),
            None => return,
        };
        if Instant::now() < expires_at {
            return;
        }

        let outcome = restore_locked(&mut guard, &target);
        match outcome {
            RestoreOutcome::Ok => {
                let _ = guard.registry.clear_lease();
            }
            RestoreOutcome::ForeignDetected => {
                let _ = guard.registry.clear_lease();
            }
            RestoreOutcome::Busy | RestoreOutcome::Failed => {
                // Lease は残す（期限切れ）: restoreタスクが拾える
            }
        }

        guard.leases.remove(&lease_id_for_timer);
        guard.in_progress = false;
    });

    begin_response(lease_id, ttl_ms)
}

fn handle_complete(
    state: &Arc<Mutex<ServiceState>>,
    req: kh_adapter_service_ipc::CompleteBypassRequest,
    ctx: ClientContext,
) -> ServiceResponse {
    if req.protocol_version != PROTOCOL_VERSION {
        return error_simple(ServiceErrorCode::ProtocolVersionMismatch);
    }

    let client_error = req.error_code;
    let launched_pid = req.launched_pid;

    let mut guard = match state.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            eprintln!("[ERROR] ServiceState mutex poisoned in handle_complete");
            eprintln!("[ERROR] {:?}", poisoned);
            return error_with_id(
                ServiceErrorCode::InternalError,
                ServiceErrorMessageId::StateLockPoisoned,
            );
        }
    };

    let lease = match guard.leases.get(&req.lease_id) {
        Some(l) => l.clone(),
        None => {
            // TTL スレッドが先に lease を回収する場合がある。
            // その後に guard から CompleteBypass が届いても、処理上は「既に回収済み」なので成功扱いにする。
            if !guard.in_progress {
                return complete_response(true);
            }
            return error_simple(ServiceErrorCode::InvalidLease);
        }
    };

    if ctx.pid != lease.client_pid {
        return error_simple(ServiceErrorCode::InvalidLease);
    }

    if Instant::now() > lease.expires_at {
        guard.leases.remove(&req.lease_id);
        guard.in_progress = false;
        return error_simple(ServiceErrorCode::LeaseExpired);
    }

    let outcome = restore_locked(&mut guard, &lease.target);
    let restored_ok = outcome.is_ok();

    if restored_ok {
        let _ = guard.registry.clear_lease();
    } else {
        // 期限前に終了したのに復元できなかった場合は、Lease を即時期限切れにして restore タスクで回収できるようにする
        let lease_state = LeaseState {
            target: lease.target.clone(),
            expires_at_ms: now_ms(),
        };
        if guard.registry.write_lease(&lease_state).is_ok() {
            let _ = guard.restore_kicker.kick_restore_after(0);
        }
    }

    guard.leases.remove(&req.lease_id);
    guard.in_progress = false;

    // guard 側が「起動失敗」等の理由を通知してきた場合は、サービス側の operation log に残す。
    if let Some(code) = client_error {
        let logger = FsAdapter::new(paths::default_data_dir());
        let record = OperationLogRecord {
            operation: "complete_bypass".into(),
            success: restored_ok,
            details: format!(
                "lease_id={}, client_pid={}, launched_pid={:?}, error_code={:?}, restored_ok={}",
                req.lease_id, ctx.pid, launched_pid, code, restored_ok
            ),
            targets: vec![lease.target.clone()],
        };
        let _ = logger.write_operation_log(&record);
    }

    complete_response(restored_ok)
}

fn load_restore_ttl_ms() -> u32 {
    let repo = FsAdapter::new(paths::default_data_dir());
    resolve_restore_ttl_ms(&repo)
}

fn resolve_restore_ttl_ms(repo: &dyn ConfigRepository) -> u32 {
    if !repo.exists() {
        return DEFAULT_TTL_MS;
    }
    match repo.load() {
        Ok(cfg) => config_ttl_ms(&cfg),
        Err(err) => {
            eprintln!(
                "[WARN] Failed to load config for auto_restore_seconds: {}",
                err
            );
            DEFAULT_TTL_MS
        }
    }
}

fn config_ttl_ms(cfg: &InstallConfig) -> u32 {
    cfg.auto_restore_seconds.saturating_mul(1000)
}

fn new_guid_string() -> String {
    #[cfg(windows)]
    {
        use windows::Win32::System::Com::CoCreateGuid;
        unsafe {
            if let Ok(guid) = CoCreateGuid() {
                return format_guid(&guid);
            }
        }
    }
    fallback_guid()
}

fn fallback_guid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("guid-{}", nanos)
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    (ms.min(u64::MAX as u128)) as u64
}

#[cfg(windows)]
fn format_guid(guid: &windows::core::GUID) -> String {
    let d4 = guid.data4;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        d4[0],
        d4[1],
        d4[2],
        d4[3],
        d4[4],
        d4[5],
        d4[6],
        d4[7]
    )
}

fn is_owned_ifeo_target(
    registry: &RegistryAdapter,
    target: &str,
    debugger_path: &str,
) -> bool {
    let values = RegistryView::all()
        .iter()
        .map(|view| registry.get_debugger_value(target, *view));
    is_owned_ifeo_values(values, debugger_path)
}

fn is_owned_ifeo_values<I>(
    values: I,
    debugger_path: &str,
) -> bool
where
    I: IntoIterator<Item = std::result::Result<Option<DebuggerValue>, kh_domain::DomainError>>,
{
    for value in values {
        match value {
            Ok(v) => {
                if !matches!(
                    classify_debugger_value(v, debugger_path),
                    DebuggerOwnership::Owned
                ) {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

fn restore_locked(state: &mut ServiceState, target: &str) -> RestoreOutcome {
    let _ifeo_lock = match acquire_ifeo_mutex(5000) {
        Ok(lock) => lock,
        Err(_) => return RestoreOutcome::Busy,
    };

    let our_debugger = state.debugger_path.clone();
    let mut ok = true;
    let mut foreign = false;

    for view in RegistryView::all() {
        let current = match state.registry.get_debugger_value(target, *view) {
            Ok(v) => v,
            Err(_) => {
                ok = false;
                continue;
            }
        };

        match classify_debugger_value(current, &our_debugger) {
            DebuggerOwnership::Foreign => {
                foreign = true;
                ok = false;
                continue;
            }
            DebuggerOwnership::Owned | DebuggerOwnership::Disabled => {
                if state
                    .registry
                    .set_debugger(target, *view, &our_debugger)
                    .is_err()
                {
                    ok = false;
                }
            }
        }
    }

    if foreign {
        RestoreOutcome::ForeignDetected
    } else if ok {
        RestoreOutcome::Ok
    } else {
        RestoreOutcome::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kh_domain::error::DomainError;

    struct StubRepo {
        exists: bool,
        config: InstallConfig,
        fail: bool,
    }

    impl ConfigRepository for StubRepo {
        fn load(&self) -> std::result::Result<InstallConfig, DomainError> {
            if self.fail {
                Err(DomainError::ConfigLoadFailed("boom".into()))
            } else {
                Ok(self.config.clone())
            }
        }

        fn save(&self, _config: &InstallConfig) -> std::result::Result<(), DomainError> {
            Ok(())
        }

        fn exists(&self) -> bool {
            self.exists
        }
    }

    #[test]
    fn resolve_restore_ttl_ms_uses_config_seconds() {
        let mut cfg = InstallConfig::default();
        cfg.auto_restore_seconds = 12;
        let repo = StubRepo {
            exists: true,
            config: cfg,
            fail: false,
        };
        assert_eq!(resolve_restore_ttl_ms(&repo), 12_000);
    }

    #[test]
    fn resolve_restore_ttl_ms_falls_back_when_missing() {
        let repo = StubRepo {
            exists: false,
            config: InstallConfig::default(),
            fail: false,
        };
        assert_eq!(resolve_restore_ttl_ms(&repo), DEFAULT_TTL_MS);
    }

    #[test]
    fn resolve_restore_ttl_ms_falls_back_on_error() {
        let repo = StubRepo {
            exists: true,
            config: InstallConfig::default(),
            fail: true,
        };
        assert_eq!(resolve_restore_ttl_ms(&repo), DEFAULT_TTL_MS);
    }

    #[test]
    fn owned_ifeo_values_returns_true_when_all_views_owned() {
        let debugger = r"C:\Program Files\KaptainhooK\bin\kh-bootstrap.exe";
        let owned = DebuggerValue::String {
            raw: debugger.to_string(),
            expanded: None,
            value_type: 1,
        };
        let values = vec![Ok(Some(owned.clone())), Ok(Some(owned))];
        assert!(is_owned_ifeo_values(values, debugger));
    }

    #[test]
    fn owned_ifeo_values_returns_false_on_foreign_or_disabled() {
        let debugger = r"C:\Program Files\KaptainhooK\bin\kh-bootstrap.exe";
        let owned = DebuggerValue::String {
            raw: debugger.to_string(),
            expanded: None,
            value_type: 1,
        };
        let foreign = DebuggerValue::String {
            raw: r"C:\Other\dbg.exe".to_string(),
            expanded: None,
            value_type: 1,
        };
        let values_foreign = vec![Ok(Some(owned.clone())), Ok(Some(foreign))];
        assert!(!is_owned_ifeo_values(values_foreign, debugger));

        let values_disabled = vec![Ok(Some(owned)), Ok(None)];
        assert!(!is_owned_ifeo_values(values_disabled, debugger));
    }
}
