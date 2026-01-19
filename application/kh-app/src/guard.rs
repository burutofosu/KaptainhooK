//! ガード用ユースケース（アプリ層）。

use kh_domain::error::{DomainError, ServiceErrorCode, ServiceErrorMessageId};
use kh_domain::model::{
    AuthMode, ForcedCategory, GuardNotification, GuardRequest, GuardResponse, NudgeMessage,
    PathHintKind, PromptContext, ReactionConfig, ReactionKind, SuspiciousPathWarning, exit_codes,
};
use kh_domain::port::driven::{
    AuthPrompt, Clock, ConfigRepository, IfeoRepository, LogWriter, PrivilegedLaunchRequest,
    PrivilegedLauncher, RandomSource, TargetPathResolver, TargetsRepository, UserNotifier,
};
use kh_domain::port::driving::GuardUseCase;
use kh_domain::service::threat_service::extract_path_hints;
use kh_domain::service::{ReactionAction, ReactionDecision, evaluate_reaction};
use std::collections::BTreeSet;
use std::time::Instant;

pub struct GuardDeps<'a> {
    pub config: &'a dyn ConfigRepository,
    pub targets: &'a dyn TargetsRepository,
    pub ifeo: &'a dyn IfeoRepository,
    pub launcher: &'a dyn PrivilegedLauncher,
    pub prompt: &'a dyn AuthPrompt,
    pub notifier: &'a dyn UserNotifier,
    pub logger: &'a dyn LogWriter,
    pub resolver: &'a dyn TargetPathResolver,
    pub clock: &'a dyn Clock,
    pub random: &'a dyn RandomSource,
}

pub struct GuardService<'a> {
    deps: GuardDeps<'a>,
}

impl<'a> GuardService<'a> {
    pub fn new(deps: GuardDeps<'a>) -> Self {
        Self { deps }
    }
}

impl GuardUseCase for GuardService<'_> {
    fn execute(&self, request: GuardRequest) -> GuardResponse {
        let start_time = Instant::now();

        let normalized = request.normalized_target.clone();
        let session = &request.session;
        let is_interactive = session.is_interactive();
        let config = match self.deps.config.load() {
            Ok(cfg) => cfg,
            Err(err) => {
                let notify = GuardNotification::ConfigLoadFailed;
                let log_reason = format!("config load failed: {}", err);
                let empty_categories: Vec<String> = Vec::new();
                if is_interactive {
                    self.deps.notifier.show_error_message(&notify);
                }
                let log = make_log(self.deps.clock, 
                    &request,
                    &normalized,
                    &log_reason,
                    "blocked",
                    false,
                    false,
                    ReactionKind::Log.as_str(),
                    &empty_categories,
                    Some(exit_codes::DIALOG_FAILED as i32),
                    start_time.elapsed().as_millis(),
                    None,
                    0,
                );
                let _ = self.deps.logger.write_guard_log(&log);
                return GuardResponse {
                    allowed: false,
                    reason: Some(log_reason),
                    emergency_used: false,
                    duration_ms: start_time.elapsed().as_millis(),
                    exit_code: exit_codes::DIALOG_FAILED,
                };
            }
        };

        let enabled_targets_set = match self.deps.targets.load_enabled_targets() {
            Ok(list) => list,
            Err(err) => {
                let notify = GuardNotification::TargetsUnavailable;
                let log_reason = format!("targets unavailable: {}", err);
                let empty_categories: Vec<String> = Vec::new();
                if is_interactive {
                    self.deps.notifier.show_error_message(&notify);
                }
                let log = make_log(self.deps.clock, 
                    &request,
                    &normalized,
                    &log_reason,
                    "blocked",
                    false,
                    false,
                    ReactionKind::Log.as_str(),
                    &empty_categories,
                    Some(exit_codes::DIALOG_FAILED as i32),
                    start_time.elapsed().as_millis(),
                    None,
                    0,
                );
                let _ = self.deps.logger.write_guard_log(&log);
                return GuardResponse {
                    allowed: false,
                    reason: Some(log_reason),
                    emergency_used: false,
                    duration_ms: start_time.elapsed().as_millis(),
                    exit_code: exit_codes::DIALOG_FAILED,
                };
            }
        };

        let mut is_protected = if enabled_targets_set.is_empty() {
            false
        } else {
            enabled_targets_set.contains(&normalized)
        };
        if !is_protected && has_ifeo_entry(self.deps.ifeo, &normalized) {
            is_protected = true;
        }
        let enabled_targets = enabled_targets_set.len() as u32;

        let resolved_path = self
            .deps
            .resolver
            .resolve_target_path(&request.target, &request.args);
        let suspicious_warning = if is_interactive {
            build_suspicious_path_warning(&request, &resolved_path)
        } else {
            None
        };

        let decision = evaluate_reaction(
            &request,
            &config.reaction,
            is_protected,
            is_interactive,
            config.policy.allow_non_interactive,
        );

        let reaction_label = decision.reaction.as_str().to_string();
        let origin_categories = ReactionConfig::matched_categories_as_strings(&decision.categories);
        let base_reason = format_reaction_reason(&decision, is_protected);

        match decision.action {
            ReactionAction::Allow => {
                if let Some(msg) = &suspicious_warning {
                    let notify = GuardNotification::SuspiciousPathWarning(msg.clone());
                    self.deps.notifier.show_warn_message(&notify);
                }
                let reason = base_reason.clone();
                let launch_request = match PrivilegedLaunchRequest::new(
                    request.target.clone(),
                    request.args.clone(),
                    normalized.clone(),
                    is_protected,
                ) {
                    Ok(req) => req,
                    Err(e) => {
                        let (reason, exit_code) =
                            handle_launch_error(self.deps.notifier, &e, is_interactive);
                        let log = make_log(self.deps.clock, 
                            &request,
                            &normalized,
                            &reason,
                            "blocked",
                            false,
                            false,
                            &reaction_label,
                            &origin_categories,
                            Some(exit_code as i32),
                            start_time.elapsed().as_millis(),
                            None,
                            enabled_targets,
                        );
                        let _ = self.deps.logger.write_guard_log(&log);
                        return GuardResponse {
                            allowed: false,
                            reason: Some(reason),
                            emergency_used: false,
                            duration_ms: start_time.elapsed().as_millis(),
                            exit_code,
                        };
                    }
                };

                match self.deps.launcher.launch_with_bypass(&launch_request) {
                    Ok(result) => {
                        let exit_code = result.exit_code() as i32;
                        let log_reason =
                            append_complete_bypass_error(&reason, result.complete_bypass_error());
                        let log = make_log(self.deps.clock, 
                            &request,
                            &normalized,
                            &log_reason,
                            "allowed",
                            true,
                            false,
                            &reaction_label,
                            &origin_categories,
                            Some(exit_code),
                            start_time.elapsed().as_millis(),
                            None,
                            enabled_targets,
                        );
                        let _ = self.deps.logger.write_guard_log(&log);
                        GuardResponse {
                            allowed: true,
                            reason: Some(reason),
                            emergency_used: false,
                            duration_ms: start_time.elapsed().as_millis(),
                            exit_code: result.exit_code(),
                        }
                    }
                    Err(err) => {
                        let (reason, exit_code) =
                            handle_launch_error(self.deps.notifier, &err, is_interactive);
                        let log = make_log(self.deps.clock, 
                            &request,
                            &normalized,
                            &reason,
                            "blocked",
                            false,
                            false,
                            &reaction_label,
                            &origin_categories,
                            Some(exit_code as i32),
                            start_time.elapsed().as_millis(),
                            None,
                            enabled_targets,
                        );
                        let _ = self.deps.logger.write_guard_log(&log);
                        GuardResponse {
                            allowed: false,
                            reason: Some(reason),
                            emergency_used: false,
                            duration_ms: start_time.elapsed().as_millis(),
                            exit_code,
                        }
                    }
                }
            }
            ReactionAction::Notify => {
                if is_interactive {
                    let notify = GuardNotification::NotifyAllowed {
                        categories: origin_categories.clone(),
                        warning: suspicious_warning.clone(),
                    };
                    self.deps.notifier.show_warn_message(&notify);
                }
                let reason = base_reason.clone();
                let launch_request = match PrivilegedLaunchRequest::new(
                    request.target.clone(),
                    request.args.clone(),
                    normalized.clone(),
                    is_protected,
                ) {
                    Ok(req) => req,
                    Err(e) => {
                        let (reason, exit_code) =
                            handle_launch_error(self.deps.notifier, &e, is_interactive);
                        let log = make_log(self.deps.clock, 
                            &request,
                            &normalized,
                            &reason,
                            "blocked",
                            false,
                            false,
                            &reaction_label,
                            &origin_categories,
                            Some(exit_code as i32),
                            start_time.elapsed().as_millis(),
                            None,
                            enabled_targets,
                        );
                        let _ = self.deps.logger.write_guard_log(&log);
                        return GuardResponse {
                            allowed: false,
                            reason: Some(reason),
                            emergency_used: false,
                            duration_ms: start_time.elapsed().as_millis(),
                            exit_code,
                        };
                    }
                };

                match self.deps.launcher.launch_with_bypass(&launch_request) {
                    Ok(result) => {
                        let exit_code = result.exit_code() as i32;
                        let log_reason =
                            append_complete_bypass_error(&reason, result.complete_bypass_error());
                        let log = make_log(self.deps.clock, 
                            &request,
                            &normalized,
                            &log_reason,
                            "allowed",
                            true,
                            false,
                            &reaction_label,
                            &origin_categories,
                            Some(exit_code),
                            start_time.elapsed().as_millis(),
                            None,
                            enabled_targets,
                        );
                        let _ = self.deps.logger.write_guard_log(&log);
                        GuardResponse {
                            allowed: true,
                            reason: Some(reason),
                            emergency_used: false,
                            duration_ms: start_time.elapsed().as_millis(),
                            exit_code: result.exit_code(),
                        }
                    }
                    Err(err) => {
                        let (reason, exit_code) =
                            handle_launch_error(self.deps.notifier, &err, is_interactive);
                        let log = make_log(self.deps.clock, 
                            &request,
                            &normalized,
                            &reason,
                            "blocked",
                            false,
                            false,
                            &reaction_label,
                            &origin_categories,
                            Some(exit_code as i32),
                            start_time.elapsed().as_millis(),
                            None,
                            enabled_targets,
                        );
                        let _ = self.deps.logger.write_guard_log(&log);
                        GuardResponse {
                            allowed: false,
                            reason: Some(reason),
                            emergency_used: false,
                            duration_ms: start_time.elapsed().as_millis(),
                            exit_code,
                        }
                    }
                }
            }
            ReactionAction::Block { exit_code } => {
                let reason = format_block_reason(&decision);
                let log = make_log(self.deps.clock, 
                    &request,
                    &normalized,
                    &reason,
                    "blocked",
                    false,
                    false,
                    &reaction_label,
                    &origin_categories,
                    Some(exit_code as i32),
                    start_time.elapsed().as_millis(),
                    None,
                    enabled_targets,
                );
                let _ = self.deps.logger.write_guard_log(&log);
                GuardResponse {
                    allowed: false,
                    reason: Some(reason),
                    emergency_used: false,
                    duration_ms: start_time.elapsed().as_millis(),
                    exit_code,
                }
            }
            ReactionAction::Prompt => {
                let nudge = select_nudge(&config.nudge_messages, self.deps.random);
                if let Some(msg) = &suspicious_warning {
                    let notify = GuardNotification::SuspiciousPathWarning(msg.clone());
                    self.deps.notifier.show_warn_message(&notify);
                }

                let timeout_cfg = if config.policy.timeout_seconds > 0 {
                    Some(config.policy.timeout_seconds)
                } else {
                    None
                };
                let prompt_ctx = PromptContext {
                    target: request.target.clone(),
                    args: request.args.clone(),
                    resolved_path,
                    username: session.username.clone(),
                    session_name: session.session_name.clone(),
                    nudge_text: Some(nudge.text().to_string()),
                    timeout_seconds: timeout_cfg,
                    language: config.language,
                };

                let outcome_result = match config.policy.auth_mode {
                    AuthMode::Hello => {
                        match self.deps.prompt.verify_hello(&prompt_ctx) {
                            Ok(outcome) => Ok(outcome),
                            Err(err) => {
                                let _ = err;
                                self.deps.prompt.show_friction(&config.friction, &prompt_ctx)
                            }
                        }
                    }
                    AuthMode::Friction => self.deps.prompt.show_friction(&config.friction, &prompt_ctx),
                };

                match outcome_result {
                    Ok(outcome) => {
                        if outcome.allowed {
                            let launch_request = match PrivilegedLaunchRequest::new(
                                request.target.clone(),
                                request.args.clone(),
                                normalized.clone(),
                                is_protected,
                            ) {
                                Ok(req) => req,
                                Err(e) => {
                                    let (reason, exit_code) =
                                        handle_launch_error(
                                            self.deps.notifier,
                                            &e,
                                            is_interactive,
                                        );
                                    let log = make_log(self.deps.clock, 
                                        &request,
                                        &normalized,
                                        &reason,
                                        "blocked",
                                        false,
                                        outcome.emergency,
                                        &reaction_label,
                                        &origin_categories,
                                        Some(exit_code as i32),
                                        start_time.elapsed().as_millis(),
                                        Some(nudge.message_id().as_str().to_string()),
                                        enabled_targets,
                                    );
                                    let _ = self.deps.logger.write_guard_log(&log);
                                    return GuardResponse {
                                        allowed: false,
                                        reason: Some(reason),
                                        emergency_used: outcome.emergency,
                                        duration_ms: start_time.elapsed().as_millis(),
                                        exit_code,
                                    };
                                }
                            };

                            match self.deps.launcher.launch_with_bypass(&launch_request) {
                                Ok(result) => {
                                    let exit_code = result.exit_code() as i32;
                                    let log_reason = append_complete_bypass_error(
                                        &outcome.reason,
                                        result.complete_bypass_error(),
                                    );
                                    let log = make_log(self.deps.clock, 
                                        &request,
                                        &normalized,
                                        &log_reason,
                                        "allowed",
                                        true,
                                        outcome.emergency,
                                        &reaction_label,
                                        &origin_categories,
                                        Some(exit_code),
                                        start_time.elapsed().as_millis(),
                                        Some(nudge.message_id().as_str().to_string()),
                                        enabled_targets,
                                    );
                                    let _ = self.deps.logger.write_guard_log(&log);
                                    GuardResponse {
                                        allowed: true,
                                        reason: Some(outcome.reason),
                                        emergency_used: outcome.emergency,
                                        duration_ms: start_time.elapsed().as_millis(),
                                        exit_code: result.exit_code(),
                                    }
                                }
                                Err(err) => {
                                    let (reason, exit_code) =
                                        handle_launch_error(
                                            self.deps.notifier,
                                            &err,
                                            is_interactive,
                                        );
                                    let log = make_log(self.deps.clock, 
                                        &request,
                                        &normalized,
                                        &reason,
                                        "blocked",
                                        false,
                                        outcome.emergency,
                                        &reaction_label,
                                        &origin_categories,
                                        Some(exit_code as i32),
                                        start_time.elapsed().as_millis(),
                                        Some(nudge.message_id().as_str().to_string()),
                                        enabled_targets,
                                    );
                                    let _ = self.deps.logger.write_guard_log(&log);
                                    GuardResponse {
                                        allowed: false,
                                        reason: Some(reason),
                                        emergency_used: outcome.emergency,
                                        duration_ms: start_time.elapsed().as_millis(),
                                        exit_code,
                                    }
                                }
                            }
                        } else {
                            let log = make_log(self.deps.clock, 
                                &request,
                                &normalized,
                                &outcome.reason,
                                "denied",
                                false,
                                false,
                                &reaction_label,
                                &origin_categories,
                                Some(exit_codes::DENIED_BY_USER as i32),
                                start_time.elapsed().as_millis(),
                                Some(nudge.message_id().as_str().to_string()),
                                enabled_targets,
                            );
                            let _ = self.deps.logger.write_guard_log(&log);
                            GuardResponse {
                                allowed: false,
                                reason: Some(outcome.reason),
                                emergency_used: false,
                                duration_ms: start_time.elapsed().as_millis(),
                                exit_code: exit_codes::DENIED_BY_USER,
                            }
                        }
                    }
                    Err(e) => {
                        let reason = e.to_string();
                        let log = make_log(self.deps.clock, 
                            &request,
                            &normalized,
                            &reason,
                            "dialog-failed",
                            false,
                            false,
                            &reaction_label,
                            &origin_categories,
                            Some(exit_codes::DIALOG_FAILED as i32),
                            start_time.elapsed().as_millis(),
                            Some(nudge.message_id().as_str().to_string()),
                            enabled_targets,
                        );
                        let _ = self.deps.logger.write_guard_log(&log);
                        GuardResponse {
                            allowed: false,
                            reason: Some(reason),
                            emergency_used: false,
                            duration_ms: start_time.elapsed().as_millis(),
                            exit_code: exit_codes::DIALOG_FAILED,
                        }
                    }
                }
            }
        }
    }
}

fn has_ifeo_entry(repo: &dyn IfeoRepository, target: &str) -> bool {
    for view in kh_domain::model::RegistryView::all() {
        match repo.get_debugger(target, *view) {
            Ok(Some(_)) => return true,
            Ok(None) => {}
            Err(_) => return true,
        }
    }
    false
}

fn select_nudge(nudges: &[NudgeMessage], random: &dyn RandomSource) -> NudgeMessage {
    if nudges.is_empty() {
        return NudgeMessage::default();
    }
    let idx = match random.next_u64() {
        Ok(value) => (value as usize) % nudges.len(),
        Err(_) => 0,
    };
    nudges
        .get(idx)
        .cloned()
        .unwrap_or_else(NudgeMessage::default)
}

fn format_reaction_reason(decision: &ReactionDecision, is_protected: bool) -> String {
    if !is_protected {
        return "target not in protection list".to_string();
    }
    let reaction = decision.reaction.as_str();
    match decision.forced {
        ForcedCategory::Always => format!("reaction {} (forced: always)", reaction),
        ForcedCategory::Logging => format!("reaction {} (forced: logging)", reaction),
        ForcedCategory::None => {
            if decision.categories.is_empty() {
                format!("reaction {} (no origin category)", reaction)
            } else {
                let mut categories: Vec<&str> =
                    decision.categories.iter().map(|c| c.as_str()).collect();
                categories.sort();
                format!("reaction {} (origin: {})", reaction, categories.join(","))
            }
        }
    }
}

fn format_block_reason(decision: &ReactionDecision) -> String {
    format!(
        "{}; non-interactive session blocked",
        format_reaction_reason(decision, true)
    )
}

fn build_suspicious_path_warning(
    request: &GuardRequest,
    resolved_path: &Option<String>,
) -> Option<SuspiciousPathWarning> {
    let primary = resolved_path
        .as_deref()
        .unwrap_or(request.target.as_str());
    let candidates = collect_path_candidates(request, resolved_path);
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut locations: Vec<String> = Vec::new();
    let mut reasons: Vec<PathHintKind> = Vec::new();

    for candidate in candidates {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key = trimmed.to_ascii_lowercase();
        if !seen.insert(key) {
            continue;
        }
        let hints = extract_path_hints(trimmed);
        let mut suspicious = false;
        for hint in hints {
            if hint.is_suspicious {
                suspicious = true;
                if !reasons.contains(&hint.kind) {
                    reasons.push(hint.kind);
                }
            }
        }
        if suspicious {
            locations.push(trimmed.to_string());
        }
    }

    if reasons.is_empty() {
        return None;
    }

    let location_list = if locations.is_empty() {
        primary.to_string()
    } else {
        locations.join(", ")
    };

    Some(SuspiciousPathWarning {
        target: primary.to_string(),
        related: location_list,
        reasons,
    })
}

fn collect_path_candidates(
    request: &GuardRequest,
    resolved_path: &Option<String>,
) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(path) = resolved_path.as_deref() {
        candidates.push(path.to_string());
    }
    candidates.push(request.target.clone());
    for arg in &request.args {
        candidates.extend(extract_arg_path_candidates(arg));
    }
    if let Some(path) = &request.parent.path {
        candidates.push(path.clone());
    }
    if let Some(path) = &request.grandparent.path {
        candidates.push(path.clone());
    }
    candidates
}

fn extract_arg_path_candidates(arg: &str) -> Vec<String> {
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Some((_, value)) = trimmed.split_once('=') {
        out.extend(extract_arg_path_candidates(value));
    }
    let unquoted = trimmed.trim_matches('"');
    if looks_like_path(unquoted) {
        out.push(unquoted.to_string());
    }
    out
}

fn looks_like_path(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 3
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
        && bytes[0].is_ascii_alphabetic()
    {
        return true;
    }
    if value.starts_with("\\\\") {
        return true;
    }
    value.contains('\\') || value.contains('/')
}

fn handle_launch_error(
    notifier: &dyn UserNotifier,
    err: &DomainError,
    is_interactive: bool,
) -> (String, u8) {
    match err {
        DomainError::IpcServiceError {
            code,
            message_id,
            ..
        } => {
            handle_service_error(notifier, *code, *message_id, is_interactive)
        }
        DomainError::IpcError(msg) => handle_ipc_error(notifier, msg, is_interactive),
        DomainError::TargetNotFound(_) => {
            let notify = GuardNotification::TargetNotFoundInSearchPaths;
            let reason = notify.fallback_message();
            if is_interactive {
                notifier.show_warn_message(&notify);
            }
            (reason, exit_codes::DIALOG_FAILED)
        }
        DomainError::ProcessLaunchFailed(msg) => {
            let notify = GuardNotification::LaunchFailed {
                detail: msg.to_string(),
            };
            let reason = notify.fallback_message();
            if is_interactive {
                notifier.show_error_message(&notify);
            }
            (reason, exit_codes::DIALOG_FAILED)
        }
        _ => {
            let notify = GuardNotification::LaunchFailed {
                detail: err.to_string(),
            };
            let reason = notify.fallback_message();
            if is_interactive {
                notifier.show_error_message(&notify);
            }
            (reason, exit_codes::DIALOG_FAILED)
        }
    }
}

fn handle_ipc_error(
    notifier: &dyn UserNotifier,
    msg: &str,
    is_interactive: bool,
) -> (String, u8) {
    if msg.starts_with("service_unavailable:") {
        let notify = GuardNotification::ServiceStopped;
        let reason = notify.fallback_message();
        if is_interactive && notifier.prompt_service_restart() {
            match notifier.run_service_restart_tool() {
                Ok(()) => {
                    notifier.show_info_message(&GuardNotification::ServiceRestarting);
                }
                Err(e) => {
                    notifier.show_error(&e);
                }
            }
        }
        return (reason, exit_codes::DIALOG_FAILED);
    }

    let notify = GuardNotification::ServiceCommFailed {
        detail: msg.to_string(),
    };
    let reason = notify.fallback_message();
    if is_interactive {
        notifier.show_error_message(&notify);
    }
    (reason, exit_codes::DIALOG_FAILED)
}

fn handle_service_error(
    notifier: &dyn UserNotifier,
    code: ServiceErrorCode,
    message_id: Option<ServiceErrorMessageId>,
    is_interactive: bool,
) -> (String, u8) {
    let notify = GuardNotification::ServiceError { code, message_id };
    let reason = notify.fallback_message();
    if is_interactive {
        match code {
            ServiceErrorCode::Busy | ServiceErrorCode::TargetNotAllowed => {
                notifier.show_warn_message(&notify);
            }
            _ => notifier.show_error_message(&notify),
        }
    }
    (reason, exit_codes::DIALOG_FAILED)
}

fn append_complete_bypass_error(reason: &str, error: Option<&str>) -> String {
    match error {
        Some(err) if !err.trim().is_empty() => {
            format!("{reason}; complete_bypass_failed={err}")
        }
        _ => reason.to_string(),
    }
}

fn make_log(
    clock: &dyn Clock,
    request: &GuardRequest,
    normalized_target: &str,
    reason: &str,
    action: &str,
    allowed: bool,
    emergency: bool,
    reaction: &str,
    origin_categories: &[String],
    exit_code: Option<i32>,
    duration_ms: u128,
    nudge_message_id: Option<String>,
    enabled_targets: u32,
) -> kh_domain::port::driven::GuardLogRecord {
    let timestamp = clock.now_iso8601();
    kh_domain::port::driven::GuardLogRecord {
        timestamp,
        normalized_target: normalized_target.to_string(),
        args: request.args.clone(),
        username: request.session.username.clone(),
        session: request.session.session_name.clone(),
        reason: reason.to_string(),
        action: action.to_string(),
        reaction: reaction.to_string(),
        origin_categories: origin_categories.to_vec(),
        allowed,
        emergency,
        nudge_message_id,
        exit_code,
        duration_ms,
        enabled_targets,
        parent_pid: request.parent.pid,
        parent_process: request.parent.name.clone(),
        parent_path: request.parent.path.clone(),
        grandparent_pid: request.grandparent.pid,
        grandparent_process: request.grandparent.name.clone(),
        grandparent_path: request.grandparent.path.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kh_domain::error::DomainError;
    use kh_domain::model::{
        FrictionSettings, InstallConfig, ProcessInfo, PromptContext, PromptOutcome, SessionInfo,
    };
    use kh_domain::port::driven::{
        ConfigRepository, GuardLogRecord, IfeoRepository, LogWriter, OperationLogRecord,
        PrivilegedLaunchRequest, PrivilegedLaunchResult, PrivilegedLauncher, TargetsRepository,
        UserNotifier, AuthPrompt,
    };
    use std::cell::RefCell;
    use std::collections::HashSet;

    struct FailingConfig;
    impl ConfigRepository for FailingConfig {
        fn load(&self) -> Result<InstallConfig, DomainError> {
            Err(DomainError::ConfigLoadFailed("boom".into()))
        }
        fn save(&self, _config: &InstallConfig) -> Result<(), DomainError> {
            Ok(())
        }
        fn exists(&self) -> bool {
            true
        }
    }

    struct StubTargets;
    impl TargetsRepository for StubTargets {
        fn load_enabled_targets(&self) -> Result<HashSet<String>, DomainError> {
            Ok(HashSet::new())
        }
    }

    struct StubIfeo;
    impl IfeoRepository for StubIfeo {
        fn get_debugger(
            &self,
            _target: &str,
            _view: kh_domain::model::RegistryView,
        ) -> Result<Option<String>, DomainError> {
            Ok(None)
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
            Ok(Vec::new())
        }
    }

    struct StubLauncher;
    impl PrivilegedLauncher for StubLauncher {
        fn launch_with_bypass(
            &self,
            _request: &PrivilegedLaunchRequest,
        ) -> Result<PrivilegedLaunchResult, DomainError> {
            Ok(PrivilegedLaunchResult::new(0))
        }
    }

    struct StubPrompt;
    impl AuthPrompt for StubPrompt {
        fn show_friction(
            &self,
            _settings: &FrictionSettings,
            _ctx: &PromptContext,
        ) -> Result<PromptOutcome, DomainError> {
            Ok(PromptOutcome {
                allowed: true,
                reason: "ok".into(),
                emergency: false,
            })
        }

        fn verify_hello(&self, _ctx: &PromptContext) -> Result<PromptOutcome, DomainError> {
            Ok(PromptOutcome {
                allowed: true,
                reason: "ok".into(),
                emergency: false,
            })
        }
    }

    struct StubResolver;
    impl TargetPathResolver for StubResolver {
        fn resolve_target_path(&self, _target: &str, _args: &[String]) -> Option<String> {
            None
        }
    }

    #[derive(Default)]
    struct TestNotifier {
        errors: RefCell<Vec<String>>,
    }
    impl UserNotifier for TestNotifier {
        fn show_error(&self, msg: &str) {
            self.errors.borrow_mut().push(msg.to_string());
        }
        fn show_warn(&self, _msg: &str) {}
        fn show_info(&self, _msg: &str) {}
        fn prompt_service_restart(&self) -> bool {
            false
        }
        fn run_service_restart_tool(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestLogger {
        guard_logs: RefCell<Vec<GuardLogRecord>>,
    }
    impl LogWriter for TestLogger {
        fn write_guard_log(&self, record: &GuardLogRecord) -> Result<(), DomainError> {
            self.guard_logs.borrow_mut().push(record.clone());
            Ok(())
        }
        fn write_operation_log(&self, _record: &OperationLogRecord) -> Result<(), DomainError> {
            Ok(())
        }
        fn rotate_if_needed(&self) -> Result<(), DomainError> {
            Ok(())
        }
    }

    struct TestClock;
    impl Clock for TestClock {
        fn now_ms(&self) -> u64 {
            0
        }

        fn now_iso8601(&self) -> String {
            "2026-01-01T00:00:00.000Z".to_string()
        }
    }

    struct TestRandom;
    impl RandomSource for TestRandom {
        fn next_u64(&self) -> Result<u64, DomainError> {
            Ok(0)
        }
    }

    #[test]
    fn config_load_failure_blocks_and_logs() {
        let notifier = TestNotifier::default();
        let logger = TestLogger::default();
        let clock = TestClock;
        let random = TestRandom;
        let deps = GuardDeps {
            config: &FailingConfig,
            targets: &StubTargets,
            ifeo: &StubIfeo,
            launcher: &StubLauncher,
            prompt: &StubPrompt,
            notifier: &notifier,
            logger: &logger,
            resolver: &StubResolver,
            clock: &clock,
            random: &random,
        };
        let service = GuardService::new(deps);
        let request = GuardRequest {
            target: "calc.exe".into(),
            args: Vec::new(),
            normalized_target: "calc.exe".into(),
            session: SessionInfo::default(),
            parent: ProcessInfo::default(),
            grandparent: ProcessInfo::default(),
        };

        let response = service.execute(request);

        assert!(!response.allowed);
        assert_eq!(response.exit_code, exit_codes::DIALOG_FAILED);
        assert_eq!(notifier.errors.borrow().len(), 1);
        assert_eq!(logger.guard_logs.borrow().len(), 1);
    }
}
