#![windows_subsystem = "windows"]
//! KaptainhooK 設定UI（WebView2）

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use kh_composition::app::admin::{
    AdminDeps, AdminService, ApplyTargetsRequest, ConflictAction, ConflictDecision,
};
use kh_composition::cli::CliRuntime;
use kh_composition::domain::model::{
    default_nudges, AuthMode, BackgroundConfig, ForcedCategory, FrictionSettings, InstallConfig,
    Language, MessageId, NudgeMessage, PathHint, PathHintKind, PolicyConfig, ReactionConfig,
    ReactionKind, ReactionPreset, ReactionRule, RegistryView, RevocationStatus, SignatureKind,
    SignatureNoticeKind, SignatureStatus, SignatureTrust, Target, TargetReaction,
};
use kh_composition::guard::is_admin;
use kh_composition::paths;
use kh_composition::ui_common::i18n;
use serde::{Deserialize, Serialize};
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop};
use tao::window::WindowBuilder;
use wry::http::{Request, Response, StatusCode};
use wry::{WebContext, WebView, WebViewBuilder};

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE};
#[cfg(windows)]
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
#[cfg(windows)]
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
#[cfg(windows)]
use wry::WebViewBuilderExtWindows;

type AnyResult<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
type StringResult<T> = std::result::Result<T, String>;

static SKIN_ASSETS: std::sync::OnceLock<HashMap<String, PathBuf>> = std::sync::OnceLock::new();

#[derive(Debug)]
struct SimpleError(String);

impl std::fmt::Display for SimpleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for SimpleError {}

fn err(msg: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(SimpleError(msg.into()))
}

const ARG_APPLY_TARGETS_AND_CONFIG_PIPE: &str = "--apply-targets-and-config-pipe";
const ARG_APPLY_TARGETS_AND_CONFIG_CLIENT: &str = "--apply-targets-and-config-client";
const PIPE_HANDSHAKE_TIMEOUT_SECS: u64 = 30;
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";
const CUSTOM_PROTOCOL_ORIGIN: &str = "http://kaptainhook.localhost";
const CUSTOM_PROTOCOL_INDEX: &str = "http://kaptainhook.localhost/index.html";
const CUSTOM_PROTOCOL_ORIGIN_PREFIX: &str = "http://kaptainhook.localhost/";
const CUSTOM_PROTOCOL_HTTPS_ORIGIN: &str = "https://kaptainhook.localhost";
const CUSTOM_PROTOCOL_HTTPS_ORIGIN_PREFIX: &str = "https://kaptainhook.localhost/";

fn is_japanese() -> bool {
    matches!(i18n::current_language(), Language::Japanese)
}

fn is_allowed_navigation(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    if lower == "about:blank" || lower == "about:srcdoc" {
        return true;
    }
    if lower == CUSTOM_PROTOCOL_ORIGIN
        || lower.starts_with(CUSTOM_PROTOCOL_ORIGIN_PREFIX)
        || lower == CUSTOM_PROTOCOL_HTTPS_ORIGIN
        || lower.starts_with(CUSTOM_PROTOCOL_HTTPS_ORIGIN_PREFIX)
        || lower.starts_with("kaptainhook://")
    {
        return true;
    }
    false
}

fn main() {
    let config = CliRuntime::new().load_config_or_default();
    i18n::set_language(config.language);

    if let Some((pipe_id, client_pid)) = parse_apply_targets_and_config_pipe_args() {
        let code = match apply_targets_and_save_from_pipe(&pipe_id, client_pid) {
            Ok(()) => 0,
            Err(e) => {
                let t = i18n::t();
                show_info(&t.settings_error_apply_targets_failed(&e.to_string()));
                1
            }
        };
        std::process::exit(code);
    }

    if let Err(_err) = run_gui() {
        let config_path = paths::default_config_path();
        let t = i18n::t();
        show_info(&t.settings_error_opengl_required(&config_path.display().to_string()));
    }
}

fn run_gui() -> AnyResult<()> {
    let runtime = CliRuntime::new();
    let mut config = runtime.load_config_or_default();
    ensure_default_targets(&mut config);
    sync_targets_from_registry(&mut config);

    let state = Rc::new(RefCell::new(AppState::new(runtime, config)));
    let webview_cell: Rc<RefCell<Option<WebView>>> = Rc::new(RefCell::new(None));

    let mut web_context = build_web_context();

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title(i18n::t().settings_title())
        .with_inner_size(LogicalSize::new(784.0, 576.0))
        .build(&event_loop)
        .map_err(|e| err(format!("window build failed: {e}")))?;

    let webview_cell_clone = webview_cell.clone();
    let state_clone = state.clone();
    let webview_builder = WebViewBuilder::new(&window)
        .with_web_context(&mut web_context)
        .with_custom_protocol("kaptainhook".into(), move |request| {
            handle_custom_protocol(request)
        })
        .with_devtools(false)
        .with_navigation_handler(|url| is_allowed_navigation(&url));
    #[cfg(windows)]
    let webview_builder = webview_builder.with_https_scheme(false);
    let webview = webview_builder
        .with_url(CUSTOM_PROTOCOL_INDEX)
        .with_ipc_handler(move |req: Request<String>| {
            handle_ipc(req.body(), &state_clone, &webview_cell_clone);
        })
        .build()
        .map_err(|e| err(format!("WebView build failed: {e}")))?;

    *webview_cell.borrow_mut() = Some(webview);

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent { event, .. } = event {
            if let WindowEvent::CloseRequested = event {
                *control_flow = ControlFlow::Exit;
            }
        }
    });

    #[allow(unreachable_code)]
    Ok(())
}

fn build_html() -> String {
    let template = include_str!("../web/index.html");
    let css = include_str!("../web/style.css");
    let js = include_str!("../web/app.js");
    let (skin_options, skin_urls) = build_skin_catalog();
    let options_json = serde_json::to_string(&skin_options).unwrap_or_else(|_| "[]".to_string());
    let urls_json = serde_json::to_string(&skin_urls).unwrap_or_else(|_| "{}".to_string());
    let js = js
        .replace("__SKIN_OPTIONS__", &options_json)
        .replace("__SKIN_URLS__", &urls_json);
    template
        .replace("/* {{CSS}} */", css)
        .replace("/* {{JS}} */", &js)
}

fn handle_custom_protocol(request: Request<Vec<u8>>) -> Response<Cow<'static, [u8]>> {
    if let Some(origin) = request
        .headers()
        .get("Origin")
        .and_then(|v| v.to_str().ok())
    {
        if origin != CUSTOM_PROTOCOL_ORIGIN {
            return empty_response(StatusCode::FORBIDDEN);
        }
    }
    let uri = request.uri();
    let raw_host = uri.host().unwrap_or_default();
    let host = raw_host
        .strip_prefix("kaptainhook.")
        .unwrap_or(raw_host)
        .to_ascii_lowercase();
    let raw_path = uri.path().trim_start_matches('/');
    let decoded_path = percent_decode(raw_path);
    if host.eq_ignore_ascii_case("app")
        || host.is_empty()
        || host.eq_ignore_ascii_case("localhost")
    {
        let mut path = decoded_path.trim_start_matches('/').to_string();
        if (host.is_empty() || host.eq_ignore_ascii_case("localhost")) && path.starts_with("app/") {
            path = path.trim_start_matches("app/").to_string();
        }
        if path.is_empty() || path == "index.html" {
            let html = build_html();
            return build_response(
                StatusCode::OK,
                Cow::Owned(html.into_bytes()),
                Some("text/html; charset=utf-8"),
            );
        }
        if let Some(rest) = path.strip_prefix("assets/") {
            return serve_asset(rest);
        }
        return empty_response(StatusCode::NOT_FOUND);
    }

    if host.eq_ignore_ascii_case("assets") {
        return serve_asset(&decoded_path);
    }

    empty_response(StatusCode::NOT_FOUND)
}

fn empty_response(status: StatusCode) -> Response<Cow<'static, [u8]>> {
    build_response(status, Cow::Borrowed(&[] as &[u8]), None)
}

fn build_response(
    status: StatusCode,
    body: Cow<'static, [u8]>,
    content_type: Option<&str>,
) -> Response<Cow<'static, [u8]>> {
    let mut builder = Response::builder()
        .status(status)
        .header("Access-Control-Allow-Origin", CUSTOM_PROTOCOL_ORIGIN)
        .header("Cross-Origin-Resource-Policy", "same-origin");
    if let Some(ct) = content_type {
        builder = builder.header("Content-Type", ct);
    }
    match builder.body(body) {
        Ok(resp) => resp,
        Err(_) => {
            // builder error（ヘッダ不正など）で panic させない。
            // 固定ヘッダなので通常は起きないが、万一でも 500 を返す。
            let mut resp = Response::new(Cow::Borrowed(&[] as &[u8]));
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            {
                use wry::http::header::{HeaderName, HeaderValue};
                let headers = resp.headers_mut();
                headers.insert(
                    HeaderName::from_static("access-control-allow-origin"),
                    HeaderValue::from_static(CUSTOM_PROTOCOL_ORIGIN),
                );
                headers.insert(
                    HeaderName::from_static("cross-origin-resource-policy"),
                    HeaderValue::from_static("same-origin"),
                );
            }
            resp
        }
    }
}

fn serve_asset(name: &str) -> Response<Cow<'static, [u8]>> {
    if name.is_empty() {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if name.contains("..") || name.contains('\\') || name.contains('/') {
        return empty_response(StatusCode::NOT_FOUND);
    }
    let assets = SKIN_ASSETS.get_or_init(|| scan_skin_assets());
    let key = name.to_ascii_lowercase();
    let Some(path) = assets.get(&key) else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    let bytes = match std::fs::read(&path) {
        Ok(v) => v,
        Err(_) => return empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let mime = mime_from_name(name).unwrap_or("application/octet-stream");
    build_response(StatusCode::OK, Cow::Owned(bytes), Some(mime))
}

fn mime_from_name(name: &str) -> Option<&'static str> {
    let ext = Path::new(name)
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase())?;
    match ext.as_str() {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "webp" => Some("image/webp"),
        "bmp" => Some("image/bmp"),
        "gif" => Some("image/gif"),
        "ico" => Some("image/x-icon"),
        _ => None,
    }
}

#[derive(Serialize)]
struct SkinOption {
    value: String,
    label: String,
}

fn build_skin_catalog() -> (Vec<SkinOption>, HashMap<String, String>) {
    let assets = scan_skin_assets();
    let mut options = Vec::new();
    let mut urls = HashMap::new();
    for path in assets.values() {
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let label = skin_label_from_name(name);
        let url = format!(
            "{}/assets/{}",
            CUSTOM_PROTOCOL_ORIGIN,
            encode_url_component(name)
        );
        options.push(SkinOption {
            value: name.to_string(),
            label,
        });
        urls.insert(name.to_string(), url);
    }
    options.sort_by(|a, b| a.label.to_ascii_lowercase().cmp(&b.label.to_ascii_lowercase()));
    let _ = SKIN_ASSETS.set(assets);
    (options, urls)
}

fn scan_skin_assets() -> HashMap<String, PathBuf> {
    let mut assets = HashMap::new();
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            dirs.push(dir.join("assets"));
            if let Some(parent) = dir.parent() {
                dirs.push(parent.join("assets"));
            }
        }
    }
    let bin_dir = paths::default_bin_dir();
    dirs.push(bin_dir.join("assets"));
    if let Some(parent) = bin_dir.parent() {
        dirs.push(parent.join("assets"));
    }
    dirs.push(paths::default_product_root_dir().join("assets"));

    for dir in dirs {
        if !dir.is_dir() {
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
                continue;
            };
            let ext = ext.to_ascii_lowercase();
            let is_image = matches!(
                ext.as_str(),
                "png" | "jpg" | "jpeg" | "webp" | "bmp" | "gif"
            );
            if !is_image {
                continue;
            }
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let key = name.to_ascii_lowercase();
            assets.entry(key).or_insert(path);
        }
    }
    assets
}

fn skin_label_from_name(name: &str) -> String {
    let stem = Path::new(name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    if stem.eq_ignore_ascii_case("k-hook") || stem.eq_ignore_ascii_case("k_hook") {
        return "K-HOOK".to_string();
    }
    stem.replace('_', " ")
}

fn encode_url_component(value: &str) -> String {
    let mut out = String::new();
    for b in value.as_bytes() {
        match *b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn build_web_context() -> WebContext {
    let mut data_dir = webview_data_dir();
    if std::fs::create_dir_all(&data_dir).is_err() {
        data_dir = std::env::temp_dir()
            .join("KaptainhooK")
            .join("webview2")
            .join("settings");
        let _ = std::fs::create_dir_all(&data_dir);
    }
    WebContext::new(Some(data_dir))
}

fn webview_data_dir() -> PathBuf {
    if let Ok(base) = std::env::var("LOCALAPPDATA") {
        PathBuf::from(base)
            .join("KaptainhooK")
            .join("webview2")
            .join("settings")
    } else {
        std::env::temp_dir()
            .join("KaptainhooK")
            .join("webview2")
            .join("settings")
    }
}

fn ensure_default_targets(config: &mut InstallConfig) {
    let mut seen = std::collections::HashSet::new();
    for target in &config.targets {
        seen.insert(target.exe_name().to_ascii_lowercase());
    }
    for preset in kh_composition::domain::model::default_targets() {
        if !seen.contains(&preset.exe_name().to_ascii_lowercase()) {
            config.targets.push(preset);
        }
    }
    config
        .targets
        .sort_by(|a, b| a.exe_name().cmp(b.exe_name()));
}

fn sync_targets_from_registry(config: &mut InstallConfig) {
    let enabled = match kh_composition::targets::load_enabled_targets() {
        Ok(set) => set,
        Err(_) => return,
    };

    let mut seen = std::collections::HashSet::new();
    for target in &mut config.targets {
        let name = target.exe_name().to_ascii_lowercase();
        target.set_enabled(enabled.contains(&name));
        seen.insert(name);
    }

    for name in enabled {
        if !seen.contains(&name) {
            if let Ok(target) = Target::new(name, true) {
                config.targets.push(target);
            }
        }
    }

    config.normalize();
    config
        .targets
        .sort_by(|a, b| a.exe_name().cmp(b.exe_name()));
}

fn handle_ipc(msg: &str, state: &Rc<RefCell<AppState>>, webview_cell: &Rc<RefCell<Option<WebView>>>) {
    let Ok(req) = serde_json::from_str::<IpcRequest>(msg) else {
        return;
    };

    match req {
        IpcRequest::Init => {
            let (config, config_path) = {
                let s = state.borrow();
                (ConfigDto::from(&s.config), s.config_path.clone())
            };
            send_response(
                webview_cell,
                IpcResponse::Init {
                    config,
                    config_path,
                },
            );
        }
        IpcRequest::Save { config } => {
            let outcome = {
                let mut s = state.borrow_mut();
                s.handle_save(config)
            };
            match outcome {
                SaveOutcome::Status { ok, message } => {
                    send_response(webview_cell, IpcResponse::Status { ok, message });
                }
                SaveOutcome::Conflicts { items } => {
                    send_response(webview_cell, IpcResponse::Conflicts { items });
                }
            }
        }
        IpcRequest::ResolveConflicts { decisions } => {
            let outcome = {
                let mut s = state.borrow_mut();
                s.handle_conflict_decisions(decisions)
            };
            send_response(
                webview_cell,
                IpcResponse::Status {
                    ok: outcome.0,
                    message: outcome.1,
                },
            );
        }
        IpcRequest::AbortConflicts => {
            let message = {
                let mut s = state.borrow_mut();
                s.pending_save = None;
                i18n::t().settings_status_save_cancelled().to_string()
            };
            send_response(
                webview_cell,
                IpcResponse::Status {
                    ok: false,
                    message,
                },
            );
        }
    }
}

fn send_response(webview_cell: &Rc<RefCell<Option<WebView>>>, response: IpcResponse) {
    let binding = webview_cell.borrow();
    let Some(webview) = binding.as_ref() else {
        return;
    };
    if let Ok(payload) = serde_json::to_string(&response) {
        let script = format!("window.__onHostMessage({});", payload);
        let _ = webview.evaluate_script(&script);
    }
}

struct AppState {
    runtime: CliRuntime,
    config: InstallConfig,
    original_config: InstallConfig,
    pending_save: Option<PendingSave>,
    config_path: String,
}

impl AppState {
    fn new(runtime: CliRuntime, config: InstallConfig) -> Self {
        let config_path = paths::default_config_path();
        i18n::set_language(config.language);
        Self {
            runtime,
            config: config.clone(),
            original_config: config,
            pending_save: None,
            config_path: config_path.display().to_string(),
        }
    }

    fn handle_save(&mut self, config: ConfigDto) -> SaveOutcome {
        let next_config = match InstallConfig::try_from(config) {
            Ok(cfg) => cfg,
            Err(err) => {
                let t = i18n::t();
                return SaveOutcome::Status {
                    ok: false,
                    message: t.settings_status_validation_error(&err),
                };
            }
        };

        let diff = compute_target_diff(&self.original_config, &next_config);
        if let Ok(conflicts) = scan_foreign_conflicts(&self.runtime, &diff.enable) {
            if !conflicts.is_empty() {
                self.pending_save = Some(PendingSave {
                    next_config,
                    to_enable: diff.enable,
                    to_disable: diff.disable,
                });
                return SaveOutcome::Conflicts {
                    items: conflicts.into_iter().map(ConflictItemDto::from).collect(),
                };
            }
        }

        match apply_and_save(
            &self.runtime,
            &mut self.config,
            &mut self.original_config,
            next_config,
            diff,
        ) {
            Ok(()) => {
                let t = i18n::t();
                SaveOutcome::Status {
                    ok: true,
                    message: t.settings_saved().to_string(),
                }
            }
            Err(err) => SaveOutcome::Status {
                ok: false,
                message: err,
            },
        }
    }

    fn handle_conflict_decisions(&mut self, decisions: Vec<ConflictDecisionDto>) -> (bool, String) {
        let pending = match self.pending_save.take() {
            Some(p) => p,
            None => return (false, "保留中の保存がありません。".to_string()),
        };

        let mut next_config = pending.next_config;
        let mut to_enable = pending.to_enable;
        let to_disable = pending.to_disable;
        let mut actions: Vec<ConflictDecision> = Vec::new();

        for decision in decisions {
            match decision.action {
                ConflictActionDto::Respect => {
                    set_target_enabled(&mut next_config, &decision.target, false);
                    to_enable.retain(|t| !t.eq_ignore_ascii_case(&decision.target));
                }
                ConflictActionDto::TakeOver | ConflictActionDto::Quarantine => {
                    actions.push(ConflictDecision {
                        target: decision.target,
                        action: ConflictAction::from(decision.action),
                    });
                }
                ConflictActionDto::Abort => {
                    let t = i18n::t();
                    return (false, t.settings_status_save_aborted().to_string());
                }
            }
        }

        let diff = TargetDiff {
            enable: to_enable,
            disable: to_disable,
        };

        match apply_and_save_with_conflicts(
            &self.runtime,
            &mut self.config,
            &mut self.original_config,
            next_config,
            diff,
            actions,
        ) {
            Ok(()) => {
                let t = i18n::t();
                (true, t.settings_saved().to_string())
            }
            Err(err) => (false, err),
        }
    }
}

struct PendingSave {
    next_config: InstallConfig,
    to_enable: Vec<String>,
    to_disable: Vec<String>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum IpcRequest {
    Init,
    Save { config: ConfigDto },
    ResolveConflicts { decisions: Vec<ConflictDecisionDto> },
    AbortConflicts,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum IpcResponse {
    Init { config: ConfigDto, config_path: String },
    Status { ok: bool, message: String },
    Conflicts { items: Vec<ConflictItemDto> },
}

#[derive(Serialize)]
struct ConflictItemDto {
    target: String,
    details: Vec<String>,
}

impl From<ConflictItem> for ConflictItemDto {
    fn from(item: ConflictItem) -> Self {
        Self {
            target: item.target,
            details: item.details,
        }
    }
}

#[derive(Deserialize)]
struct ConflictDecisionDto {
    target: String,
    action: ConflictActionDto,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum ConflictActionDto {
    Respect,
    TakeOver,
    Quarantine,
    Abort,
}

impl From<ConflictActionDto> for ConflictAction {
    fn from(action: ConflictActionDto) -> Self {
        match action {
            ConflictActionDto::Respect => ConflictAction::Respect,
            ConflictActionDto::TakeOver => ConflictAction::TakeOver,
            ConflictActionDto::Quarantine => ConflictAction::Quarantine,
            ConflictActionDto::Abort => ConflictAction::Abort,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
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
    #[serde(default)]
    language: String,
    #[serde(default)]
    reaction: ReactionDto,
    #[serde(default)]
    background: BackgroundDto,
}

#[derive(Serialize, Deserialize, Clone)]
struct BackgroundDto {
    image: String,
    opacity: u8,
}

impl Default for BackgroundDto {
    fn default() -> Self {
        Self {
            image: "none".to_string(),
            opacity: 30,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct PolicyDto {
    #[serde(default)]
    allow_non_interactive: bool,
    #[serde(default)]
    timeout_seconds: u32,
    #[serde(default)]
    auth_mode: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct ReactionDto {
    preset: String,
    default_rule: ReactionRuleDto,
    #[serde(default)]
    overrides: Vec<TargetReactionDto>,
}

impl Default for ReactionDto {
    fn default() -> Self {
        Self {
            preset: ReactionPreset::AllLog.as_str().to_string(),
            default_rule: ReactionRuleDto::default(),
            overrides: Vec::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Serialize, Deserialize, Clone)]
struct TargetReactionDto {
    target: String,
    #[serde(default)]
    forced: String,
    rule: ReactionRuleDto,
}

#[derive(Serialize, Deserialize, Clone)]
struct TargetDto {
    exe_name: String,
    enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct FrictionDto {
    require_hold: bool,
    hold_ms: u32,
    require_pointer_movement: bool,
    pointer_move_threshold_px: u32,
    emergency_bypass: bool,
    emergency_hold_ms: u32,
}

#[derive(Serialize, Deserialize, Clone, Default)]
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
    fn try_into_message(self) -> StringResult<NudgeMessage> {
        let id = MessageId::new(self.message_id).map_err(|e| e.to_string())?;
        NudgeMessage::new(id, self.text).map_err(|e| e.to_string())
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
    type Error = String;

    fn try_from(dto: ReactionDto) -> std::result::Result<Self, Self::Error> {
        let mut cfg = ReactionConfig {
            preset: ReactionPreset::from_str(&dto.preset),
            default_rule: dto.default_rule.to_rule(),
            overrides: dto.overrides.into_iter().map(|o| o.to_domain()).collect(),
        };
        cfg.normalize();
        cfg.validate().map_err(|e| e.to_string())?;
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
    type Error = String;

    fn try_from(dto: ConfigDto) -> std::result::Result<Self, Self::Error> {
        let targets: StringResult<Vec<Target>> = dto
            .targets
            .into_iter()
            .map(|t| Target::new(t.exe_name, t.enabled).map_err(|e| e.to_string()))
            .collect();

        let nudges = if dto.nudge_messages.is_empty() {
            default_nudges()
        } else {
            dto.nudge_messages
                .into_iter()
                .map(NudgeDto::try_into_message)
                .collect::<StringResult<Vec<_>>>()?
        };

        let friction = FrictionSettings::new(
            dto.friction.require_hold,
            dto.friction.hold_ms,
            dto.friction.require_pointer_movement,
            dto.friction.pointer_move_threshold_px,
            dto.friction.emergency_bypass,
            dto.friction.emergency_hold_ms,
        )
        .map_err(|e| e.to_string())?;

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
                auth_mode: AuthMode::from_str(&dto.policy.auth_mode).unwrap_or_default(),
            },
            language,
            reaction,
            background,
        };
        cfg.normalize();
        cfg.validate().map_err(|e| e.to_string())?;
        Ok(cfg)
    }
}

struct TargetDiff {
    enable: Vec<String>,
    disable: Vec<String>,
}

fn compute_target_diff(old_cfg: &InstallConfig, new_cfg: &InstallConfig) -> TargetDiff {
    use std::collections::HashMap;
    let mut old_map: HashMap<String, bool> = HashMap::new();
    for target in &old_cfg.targets {
        old_map.insert(target.exe_name().to_ascii_lowercase(), target.enabled());
    }

    let mut new_map: HashMap<String, bool> = HashMap::new();
    for target in &new_cfg.targets {
        new_map.insert(target.exe_name().to_ascii_lowercase(), target.enabled());
    }

    let mut to_enable = Vec::new();
    for (name, enabled) in &new_map {
        let was_enabled = old_map.get(name).copied().unwrap_or(false);
        if *enabled && !was_enabled {
            to_enable.push(name.clone());
        }
    }

    let mut to_disable = Vec::new();
    for (name, was_enabled) in &old_map {
        let enabled_now = new_map.get(name).copied().unwrap_or(false);
        if *was_enabled && !enabled_now {
            to_disable.push(name.clone());
        }
    }

    TargetDiff {
        enable: to_enable,
        disable: to_disable,
    }
}

fn apply_and_save(
    runtime: &CliRuntime,
    config: &mut InstallConfig,
    original_config: &mut InstallConfig,
    next_config: InstallConfig,
    diff: TargetDiff,
) -> StringResult<()> {
    let prev_config = config.clone();
    let prev_original = original_config.clone();
    let payload = build_apply_targets_request(
        &diff.enable,
        &diff.disable,
        &next_config,
        Vec::new(),
    );
    let prev_enabled_targets = enabled_targets_from_config(&prev_config);
    match apply_targets_and_save_with_uac_if_needed(
        runtime,
        payload,
        &next_config,
        &prev_enabled_targets,
    ) {
        Ok(()) => {
            *config = next_config;
            *original_config = config.clone();
            Ok(())
        }
        Err(err) => {
            *config = prev_config;
            *original_config = prev_original;
            let t = i18n::t();
            Err(t.settings_status_save_after_apply_failed(&err))
        }
    }
}

fn apply_and_save_with_conflicts(
    runtime: &CliRuntime,
    config: &mut InstallConfig,
    original_config: &mut InstallConfig,
    next_config: InstallConfig,
    diff: TargetDiff,
    conflicts: Vec<ConflictDecision>,
) -> StringResult<()> {
    let prev_config = config.clone();
    let prev_original = original_config.clone();
    let payload =
        build_apply_targets_request(&diff.enable, &diff.disable, &next_config, conflicts);
    let prev_enabled_targets = enabled_targets_from_config(&prev_config);
    match apply_targets_and_save_with_uac_if_needed(
        runtime,
        payload,
        &next_config,
        &prev_enabled_targets,
    ) {
        Ok(()) => {
            *config = next_config;
            *original_config = config.clone();
            Ok(())
        }
        Err(err) => {
            *config = prev_config;
            *original_config = prev_original;
            let t = i18n::t();
            Err(t.settings_status_save_after_apply_failed(&err))
        }
    }
}

fn set_target_enabled(config: &mut InstallConfig, name: &str, enabled: bool) {
    for target in &mut config.targets {
        if target.exe_name().eq_ignore_ascii_case(name) {
            target.set_enabled(enabled);
        }
    }
}

#[derive(Clone)]
struct ConflictItem {
    target: String,
    details: Vec<String>,
}

fn scan_foreign_conflicts(
    runtime: &CliRuntime,
    to_enable: &[String],
) -> StringResult<Vec<ConflictItem>> {
    if to_enable.is_empty() {
        return Ok(Vec::new());
    }

    let mut temp_config = InstallConfig::default();
    temp_config.targets.clear();
    for target in to_enable {
        if let Ok(t) = Target::new(target, true) {
            temp_config.targets.push(t);
        }
    }
    if temp_config.targets.is_empty() {
        return Ok(Vec::new());
    }

    let conflict_entries = runtime
        .detect_conflicts(&temp_config)
        .map_err(|e| {
            if is_japanese() {
                format!("競合の検出に失敗しました: {e}")
            } else {
                format!("Failed to detect conflicts: {e}")
            }
        })?;

    let mut grouped: std::collections::HashMap<String, ConflictItem> =
        std::collections::HashMap::new();
    let mut seen_views: std::collections::HashSet<(String, RegistryView)> =
        std::collections::HashSet::new();
    let t = i18n::t();
    for entry in conflict_entries {
        let item = grouped
            .entry(entry.target.clone())
            .or_insert_with(|| ConflictItem {
                target: entry.target.clone(),
                details: Vec::new(),
            });
        item.details.push(format!(
            "{}: {}",
            view_label(entry.view),
            entry.existing_debugger
        ));
        item.details.push(format!(
            "{}: {}",
            t.setup_conflict_signature(),
            format_signature_status(&entry.signature)
        ));
        if let Some(note) = &entry.signature_notice {
            item.details.push(format!(
                "{}: {}",
                t.common_note(),
                format_signature_notice(note)
            ));
        }
        if !entry.path_hints.is_empty() {
            item.details.push(format!(
                "{}: {}",
                t.setup_conflict_path_hints(),
                format_path_hints(&entry.path_hints).join(", ")
            ));
        }
        seen_views.insert((entry.target.to_ascii_lowercase(), entry.view));
    }

    let admin = AdminService::new(AdminDeps { port: runtime });
    if let Ok(non_string) = admin.scan_non_string_conflicts(to_enable) {
        for conflict in non_string {
            let key = (conflict.target.to_ascii_lowercase(), conflict.view);
            if seen_views.contains(&key) {
                continue;
            }
            let item = grouped
                .entry(conflict.target.clone())
                .or_insert_with(|| ConflictItem {
                    target: conflict.target.clone(),
                    details: Vec::new(),
                });
            item.details.push(format!(
                "{}: {}",
                view_label(conflict.view),
                t.settings_conflict_non_string_debugger(),
            ));
            item.details.push(format!(
                "{}: {}",
                t.setup_conflict_signature(),
                t.settings_conflict_signature_unsupported()
            ));
        }
    }

    Ok(grouped.into_values().collect())
}

fn view_label(view: RegistryView) -> &'static str {
    let t = i18n::t();
    match view {
        RegistryView::Bit64 => t.common_view_64(),
        RegistryView::Bit32 => t.common_view_32(),
    }
}

fn format_signature_status(status: &SignatureStatus) -> String {
    let t = i18n::t();
    match status {
        SignatureStatus::Signed {
            kind,
            trust,
            subject,
            issuer,
            revocation,
        } => {
            let kind_label = match kind {
                SignatureKind::Authenticode => t.signature_kind_authenticode(),
                SignatureKind::Other { name } => name.as_str(),
            };
            let trust_label = match trust {
                SignatureTrust::Trusted => t.signature_trust_trusted().to_string(),
                SignatureTrust::Untrusted => t.signature_trust_untrusted().to_string(),
                SignatureTrust::Unknown => t.signature_trust_unknown().to_string(),
            };
            let rev_label = match revocation {
                RevocationStatus::Good => t.signature_revocation_good().to_string(),
                RevocationStatus::Revoked => t.signature_revocation_revoked().to_string(),
                RevocationStatus::NotChecked { reason } => t.signature_revocation_not_checked(reason),
                RevocationStatus::CheckFailed { reason } => {
                    t.signature_revocation_check_failed(reason)
                }
            };
            let mut parts = vec![t.common_signature_signed(kind_label)];
            parts.push(t.common_signature_trust(&trust_label));
            parts.push(t.common_signature_revocation(&rev_label));
            if let Some(subject) = subject {
                if !subject.is_empty() {
                    parts.push(t.common_signature_subject(subject));
                }
            }
            if let Some(issuer) = issuer {
                if !issuer.is_empty() {
                    parts.push(t.common_signature_issuer(issuer));
                }
            }
            parts.join(", ")
        }
        SignatureStatus::Unsigned => t.common_signature_unsigned().to_string(),
        SignatureStatus::Error { message } => t.common_signature_error(message),
        SignatureStatus::Unsupported { reason } => t.common_signature_unsupported(reason),
    }
}

fn format_signature_notice(kind: &SignatureNoticeKind) -> String {
    let t = i18n::t();
    match kind {
        SignatureNoticeKind::Unsigned => t.common_signature_notice_unsigned().to_string(),
        SignatureNoticeKind::Untrusted => t.common_signature_notice_untrusted().to_string(),
        SignatureNoticeKind::Revoked => t.common_signature_notice_revoked().to_string(),
        SignatureNoticeKind::RevocationNotChecked => {
            t.common_signature_notice_revocation_not_checked().to_string()
        }
        SignatureNoticeKind::RevocationCheckFailed => {
            t.common_signature_notice_revocation_check_failed().to_string()
        }
        SignatureNoticeKind::Error => t.common_signature_notice_error().to_string(),
        SignatureNoticeKind::Unsupported => t.common_signature_notice_unsupported().to_string(),
    }
}

fn format_path_hints(hints: &[PathHint]) -> Vec<String> {
    let t = i18n::t();
    hints
        .iter()
        .map(|hint| {
            let label = match hint.kind {
                PathHintKind::PublicUserDir => t.common_path_hint_public_user_dir(),
                PathHintKind::TempDir => t.common_path_hint_temp_dir(),
                PathHintKind::UserTempDir => t.common_path_hint_user_temp_dir(),
                PathHintKind::DownloadsDir => t.common_path_hint_downloads_dir(),
                PathHintKind::DesktopDir => t.common_path_hint_desktop_dir(),
                PathHintKind::ProgramFilesDir => t.common_path_hint_program_files_dir(),
                PathHintKind::ProgramFilesX86Dir => t.common_path_hint_program_files_x86_dir(),
                PathHintKind::System32Dir => t.common_path_hint_system32_dir(),
                PathHintKind::SysWow64Dir => t.common_path_hint_syswow64_dir(),
            };
            format!("{} ({})", label, hint.pattern)
        })
        .collect()
}

fn build_apply_targets_request(
    to_enable: &[String],
    to_disable: &[String],
    next_config: &InstallConfig,
    conflicts: Vec<ConflictDecision>,
) -> ApplyTargetsRequest {
    let enabled_targets: Vec<String> = next_config
        .targets
        .iter()
        .filter(|t| t.enabled())
        .map(|t| t.exe_name().to_string())
        .collect();

    ApplyTargetsRequest {
        enable: to_enable.to_vec(),
        disable: to_disable.to_vec(),
        enabled_targets,
        conflicts,
    }
}

fn enabled_targets_from_config(config: &InstallConfig) -> Vec<String> {
    let mut targets: Vec<String> = config
        .targets
        .iter()
        .filter(|t| t.enabled())
        .map(|t| t.exe_name().to_ascii_lowercase())
        .collect();
    targets.sort();
    targets.dedup();
    targets
}

fn apply_targets_and_save_with_uac_if_needed(
    runtime: &CliRuntime,
    payload: ApplyTargetsRequest,
    config: &InstallConfig,
    previous_enabled_targets: &[String],
) -> StringResult<()> {
    if is_admin() {
        return runtime
            .apply_targets_and_save_config(payload, config, previous_enabled_targets)
            .map_err(|e| {
                if is_japanese() {
                    format!("対象の適用と保存に失敗しました: {e}")
                } else {
                    format!("Failed to apply targets and save: {e}")
                }
            });
    }

    let combined = ApplyTargetsAndSavePayload {
        apply: TargetApplyPayload::from(&payload),
        config: ConfigDto::from(config),
        previous_enabled_targets: previous_enabled_targets.to_vec(),
    };
    let data = serde_json::to_vec_pretty(&combined).map_err(|e| {
        if is_japanese() {
            format!("送信データの作成に失敗しました: {e}")
        } else {
            format!("Failed to build payload: {e}")
        }
    })?;
    let pipe_id = new_guid_string()?;
    let pipe_name = format!(r"\\.\pipe\\kh-apply-targets-and-config-{}", pipe_id);
    let client_pid = std::process::id();
    let params = format!(
        "{} {} {} {}",
        ARG_APPLY_TARGETS_AND_CONFIG_PIPE,
        quote_windows_arg(OsStr::new(&pipe_id)),
        ARG_APPLY_TARGETS_AND_CONFIG_CLIENT,
        client_pid
    );

    match run_self_as_admin_and_wait_with_pipe(&params, &pipe_name, &data) {
        Ok(0) => Ok(()),
        Ok(code) => Err(if is_japanese() {
            format!("適用と保存に失敗しました（終了コード {code}）。")
        } else {
            format!("Apply and save failed (exit {code}).")
        }),
        Err(e) => Err(e),
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ApplyTargetsAndSavePayload {
    apply: TargetApplyPayload,
    config: ConfigDto,
    previous_enabled_targets: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TargetApplyPayload {
    enable: Vec<String>,
    disable: Vec<String>,
    enabled_targets: Vec<String>,
    conflicts: Vec<TargetConflictDecision>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TargetConflictDecision {
    target: String,
    action: TargetConflictAction,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum TargetConflictAction {
    Respect,
    TakeOver,
    Quarantine,
    Abort,
}

impl From<&ApplyTargetsRequest> for TargetApplyPayload {
    fn from(request: &ApplyTargetsRequest) -> Self {
        Self {
            enable: request.enable.clone(),
            disable: request.disable.clone(),
            enabled_targets: request.enabled_targets.clone(),
            conflicts: request
                .conflicts
                .iter()
                .map(|c| TargetConflictDecision {
                    target: c.target.clone(),
                    action: TargetConflictAction::from(c.action),
                })
                .collect(),
        }
    }
}

impl From<TargetConflictAction> for ConflictAction {
    fn from(action: TargetConflictAction) -> Self {
        match action {
            TargetConflictAction::Respect => ConflictAction::Respect,
            TargetConflictAction::TakeOver => ConflictAction::TakeOver,
            TargetConflictAction::Quarantine => ConflictAction::Quarantine,
            TargetConflictAction::Abort => ConflictAction::Abort,
        }
    }
}

impl From<ConflictAction> for TargetConflictAction {
    fn from(action: ConflictAction) -> Self {
        match action {
            ConflictAction::Respect => TargetConflictAction::Respect,
            ConflictAction::TakeOver => TargetConflictAction::TakeOver,
            ConflictAction::Quarantine => TargetConflictAction::Quarantine,
            ConflictAction::Abort => TargetConflictAction::Abort,
        }
    }
}

impl From<TargetApplyPayload> for ApplyTargetsRequest {
    fn from(payload: TargetApplyPayload) -> Self {
        Self {
            enable: payload.enable,
            disable: payload.disable,
            enabled_targets: payload.enabled_targets,
            conflicts: payload
                .conflicts
                .into_iter()
                .map(|c| ConflictDecision {
                    target: c.target,
                    action: ConflictAction::from(c.action),
                })
                .collect(),
        }
    }
}

#[cfg(windows)]
fn apply_targets_and_save_from_pipe(pipe_id: &str, expected_pid: u32) -> StringResult<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;
    use windows::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED, GetLastError, FALSE};
    use windows::Win32::Storage::FileSystem::{ReadFile, PIPE_ACCESS_INBOUND};
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::core::PCWSTR;

    if !is_admin() {
        return Err(if is_japanese() {
            "管理者権限が必要です。".to_string()
        } else {
            "Administrator privileges are required.".to_string()
        });
    }
    if pipe_id.trim().is_empty() {
        return Err(if is_japanese() {
            "パイプIDが不正です。".to_string()
        } else {
            "Invalid pipe id.".to_string()
        });
    }

    let full_name = format!(r"\\.\pipe\\kh-apply-targets-and-config-{}", pipe_id);
    let name = wstr(OsStr::new(&full_name));
    let mut sd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
    let mut sd_len: u32 = 0;
    if let Err(err) = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wstr(OsStr::new(PIPE_SDDL)).as_ptr()),
            SDDL_REVISION_1 as u32,
            &mut sd,
            Some(&mut sd_len),
        )
    } {
        return Err(if is_japanese() {
            format!(
                "パイプのセキュリティ記述子の生成に失敗しました: {}",
                err.message()
            )
        } else {
            format!(
                "Failed to build pipe security descriptor: {}",
                err.message()
            )
        });
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0 as *mut _,
        bInheritHandle: FALSE,
    };

    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name.as_ptr()),
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0,
            64 * 1024,
            5_000,
            Some(&sa),
        )
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0 as _)));
    }
    if handle.is_invalid() {
        return Err(if is_japanese() {
            format!(
                "パイプの作成に失敗しました: {}",
                unsafe { GetLastError().0 }
            )
        } else {
            format!(
                "Failed to create pipe: {}",
                unsafe { GetLastError().0 }
            )
        });
    }
    let _guard = PipeHandleGuard(handle);

    let connected_flag = Arc::new(AtomicBool::new(false));
    let watchdog_flag = Arc::clone(&connected_flag);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(PIPE_HANDSHAKE_TIMEOUT_SECS));
        if !watchdog_flag.load(Ordering::SeqCst) {
            std::process::exit(1);
        }
    });

    let connected = unsafe { ConnectNamedPipe(handle, None) };
    if connected.is_err() {
        let err = unsafe { GetLastError() };
        if err != ERROR_PIPE_CONNECTED {
            return Err(if is_japanese() {
                format!("パイプ接続に失敗しました: {}", err.0)
            } else {
                format!("Pipe connect failed: {}", err.0)
            });
        }
    }
    connected_flag.store(true, Ordering::SeqCst);

    let mut client_pid: u32 = 0;
    let pid_ok = unsafe { GetNamedPipeClientProcessId(handle, &mut client_pid) };
    if pid_ok.is_err() || client_pid != expected_pid {
        return Err(if is_japanese() {
            "パイプのクライアントが一致しません。".to_string()
        } else {
            "Pipe client mismatch.".to_string()
        });
    }
    let current_exe = std::env::current_exe().map_err(|e| {
        if is_japanese() {
            format!("実行ファイルの取得に失敗しました: {e}")
        } else {
            format!("current_exe: {e}")
        }
    })?;
    let client_path = get_process_path(client_pid)?;
    if !paths_equal_ignore_case(&client_path, &current_exe) {
        return Err(if is_japanese() {
            "パイプのクライアントパスが一致しません。".to_string()
        } else {
            "Pipe client path mismatch.".to_string()
        });
    }

    let mut buf = vec![0u8; 8192];
    let mut data: Vec<u8> = Vec::new();
    loop {
        let mut read = 0u32;
        let ok = unsafe { ReadFile(handle, Some(buf.as_mut_slice()), Some(&mut read), None) };
        if ok.is_err() {
            let err = unsafe { GetLastError() };
            if err == ERROR_BROKEN_PIPE {
                break;
            }
            return Err(if is_japanese() {
                format!("パイプの読み取りに失敗しました: {}", err.0)
            } else {
                format!("Pipe read failed: {}", err.0)
            });
        }
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buf[..read as usize]);
    }

    let payload: ApplyTargetsAndSavePayload =
        serde_json::from_slice(&data).map_err(|e| {
            if is_japanese() {
                format!("受信データの読み取りに失敗しました: {e}")
            } else {
                format!("Failed to parse payload: {e}")
            }
        })?;
    let runtime = CliRuntime::new();
    let request: ApplyTargetsRequest = payload.apply.into();
    let config = InstallConfig::try_from(payload.config).map_err(|e| {
        if is_japanese() {
            format!("設定の読み取りに失敗しました: {e}")
        } else {
            format!("Failed to parse config: {e}")
        }
    })?;
    runtime
        .apply_targets_and_save_config(request, &config, &payload.previous_enabled_targets)
        .map_err(|e| {
            if is_japanese() {
                format!("対象の適用と保存に失敗しました: {e}")
            } else {
                format!("Failed to apply targets and save: {e}")
            }
        })?;
    Ok(())
}

#[cfg(not(windows))]
fn apply_targets_and_save_from_pipe(_pipe_id: &str, _expected_pid: u32) -> StringResult<()> {
    Err(if is_japanese() {
        "このプラットフォームでは UAC 昇格に対応していません。".to_string()
    } else {
        "UAC elevation is not supported on this platform.".to_string()
    })
}

#[cfg(windows)]
struct PipeHandleGuard(HANDLE);

#[cfg(windows)]
impl Drop for PipeHandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
struct ProcessHandleGuard(HANDLE);

#[cfg(windows)]
impl Drop for ProcessHandleGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn normalize_path_for_compare(path: &Path) -> String {
    let mut value = path.to_string_lossy().to_string();
    if let Some(stripped) = value.strip_prefix(r"\\?\") {
        value = stripped.to_string();
    }
    value.replace('/', "\\").to_ascii_lowercase()
}

#[cfg(windows)]
fn paths_equal_ignore_case(left: &Path, right: &Path) -> bool {
    normalize_path_for_compare(left) == normalize_path_for_compare(right)
}

#[cfg(windows)]
fn get_process_path(pid: u32) -> StringResult<PathBuf> {
    use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::core::PWSTR;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| {
            if is_japanese() {
                format!("プロセスの取得に失敗しました: {}", e.message())
            } else {
                format!("OpenProcess failed: {}", e.message())
            }
        })?;
        let _guard = ProcessHandleGuard(handle);

        let mut size: u32 = 260;
        loop {
            let mut buffer: Vec<u16> = vec![0u16; size as usize];
            let mut len = size;
            let result = QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buffer.as_mut_ptr()),
                &mut len,
            );
            if result.is_ok() {
                buffer.truncate(len as usize);
                let path = String::from_utf16_lossy(&buffer);
                return Ok(PathBuf::from(path));
            }

            let err = GetLastError();
            if err == ERROR_INSUFFICIENT_BUFFER {
                size = size.saturating_mul(2).max(520);
                if size > 8192 {
                    return Err(if is_japanese() {
                        "クライアントパスが長すぎます。".to_string()
                    } else {
                        "Client path is too long.".to_string()
                    });
                }
                continue;
            }
            if err.0 == 0 {
                return Err(if is_japanese() {
                    "QueryFullProcessImageNameW に失敗しました。".to_string()
                } else {
                    "QueryFullProcessImageNameW failed.".to_string()
                });
            }
            return Err(if is_japanese() {
                format!("QueryFullProcessImageNameW に失敗しました: {}", err.0)
            } else {
                format!("QueryFullProcessImageNameW failed: {}", err.0)
            });
        }
    }
}


#[cfg(windows)]
fn run_self_as_admin_and_wait_with_pipe(
    parameters: &str,
    pipe_name: &str,
    payload: &[u8],
) -> StringResult<u32> {
    let exe = std::env::current_exe().map_err(|e| {
        if is_japanese() {
            format!("実行ファイルの取得に失敗しました: {e}")
        } else {
            format!("current_exe: {e}")
        }
    })?;
    let exe_w = wstr(exe.as_os_str());
    let verb_w = wstr(OsStr::new("runas"));
    let params_w = wstr(OsStr::new(parameters));

    unsafe {
        let mut sei = SHELLEXECUTEINFOW::default();
        sei.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = PCWSTR(verb_w.as_ptr());
        sei.lpFile = PCWSTR(exe_w.as_ptr());
        sei.lpParameters = PCWSTR(params_w.as_ptr());
        sei.nShow = SW_SHOWNORMAL.0 as i32;

        if let Err(err) = ShellExecuteExW(&mut sei) {
            if err.code().0 as u32 == ERROR_CANCELLED.0 {
                return Err(if is_japanese() {
                    "UAC の確認がキャンセルされました。".to_string()
                } else {
                    "User cancelled UAC prompt.".to_string()
                });
            }
            return Err(if is_japanese() {
                format!("ShellExecuteExW に失敗しました: {}", err.message())
            } else {
                format!("ShellExecuteExW failed: {}", err.message())
            });
        }

        let h: HANDLE = sei.hProcess;
        if h.is_invalid() {
            return Err(if is_japanese() {
                "ShellExecuteExW がプロセスハンドルを返しませんでした。".to_string()
            } else {
                "ShellExecuteExW returned no process handle.".to_string()
            });
        }

        let send_result = send_payload_to_pipe(pipe_name, payload);
        let wait = WaitForSingleObject(h, INFINITE);
        if wait.0 != 0 {
            let _ = CloseHandle(h);
            return Err(if is_japanese() {
                format!("WaitForSingleObject に失敗しました: {}", wait.0)
            } else {
                format!("WaitForSingleObject failed: {}", wait.0)
            });
        }

        let mut code: u32 = 1;
        if let Err(err) = GetExitCodeProcess(h, &mut code) {
            let _ = CloseHandle(h);
            return Err(if is_japanese() {
                format!("GetExitCodeProcess に失敗しました: {}", err.message())
            } else {
                format!("GetExitCodeProcess failed: {}", err.message())
            });
        }
        let _ = CloseHandle(h);

        match send_result {
            Ok(()) => Ok(code),
            Err(e) => Err(e),
        }
    }
}

#[cfg(windows)]
fn send_payload_to_pipe(pipe_name: &str, payload: &[u8]) -> StringResult<()> {
    use std::time::{Duration, Instant};
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GetLastError};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_MODE,
        OPEN_EXISTING,
    };
    use windows::Win32::System::Pipes::WaitNamedPipeW;

    let name = wstr(OsStr::new(pipe_name));
    let desired_access = FILE_GENERIC_WRITE.0;
    let deadline = Instant::now() + Duration::from_secs(PIPE_HANDSHAKE_TIMEOUT_SECS);
    loop {
        if Instant::now() >= deadline {
            return Err(if is_japanese() {
                "パイプ待機がタイムアウトしました。".to_string()
            } else {
                "Timed out waiting for pipe.".to_string()
            });
        }
        let handle = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                desired_access,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        let handle = match handle {
            Ok(handle) => handle,
            Err(_) => {
                let err = unsafe { GetLastError() };
                if err == ERROR_PIPE_BUSY {
                    let _ = unsafe { WaitNamedPipeW(PCWSTR(name.as_ptr()), 2_000) };
                    continue;
                }
                if err == ERROR_FILE_NOT_FOUND {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
                return Err(if is_japanese() {
                    format!("パイプを開けませんでした: {}", err.0)
                } else {
                    format!("Failed to open pipe: {}", err.0)
                });
            }
        };
        let mut written: u32 = 0;
        let write_ok = unsafe { WriteFile(handle, Some(payload), Some(&mut written), None) };
        let _ = unsafe { CloseHandle(handle) };
        if write_ok.is_err() {
            return Err(if is_japanese() {
                "パイプへの書き込みに失敗しました。".to_string()
            } else {
                "Failed to write payload to pipe.".to_string()
            });
        }
        if written as usize != payload.len() {
            return Err(if is_japanese() {
                "パイプへの書き込みが完了しませんでした。".to_string()
            } else {
                "Incomplete payload write.".to_string()
            });
        }
        return Ok(());
    }
}

fn parse_apply_targets_and_config_pipe_args() -> Option<(String, u32)> {
    let args: Vec<OsString> = std::env::args_os().collect();
    let mut iter = args.iter();
    let mut pipe_name: Option<String> = None;
    let mut client_pid: Option<u32> = None;
    while let Some(arg) = iter.next() {
        if arg == ARG_APPLY_TARGETS_AND_CONFIG_PIPE {
            pipe_name = iter
                .next()
                .and_then(|v| v.to_str().map(|s| s.to_string()));
            continue;
        }
        if arg == ARG_APPLY_TARGETS_AND_CONFIG_CLIENT {
            client_pid = iter
                .next()
                .and_then(|v| v.to_str())
                .and_then(|s| s.parse::<u32>().ok());
            continue;
        }
    }
    match (pipe_name, client_pid) {
        (Some(name), Some(pid)) if !name.trim().is_empty() => Some((name, pid)),
        _ => None,
    }
}

#[cfg(windows)]
fn wstr(s: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn quote_windows_arg(arg: &OsStr) -> String {
    let s = arg.to_string_lossy();
    if s.contains([' ', '\t', '\n', '\r', '"']) {
        format!("\"{}\"", s.replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

#[cfg(windows)]
fn new_guid_string() -> StringResult<String> {
    use windows::Win32::System::Com::CoCreateGuid;
    let guid = unsafe {
        CoCreateGuid().map_err(|e| {
            if is_japanese() {
                format!("CoCreateGuid に失敗しました: {e}")
            } else {
                format!("CoCreateGuid failed: {e}")
            }
        })?
    };
    Ok(format_guid(&guid))
}

#[cfg(not(windows))]
fn new_guid_string() -> StringResult<String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Ok(format!("guid-{}", nanos))
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

#[cfg(windows)]
fn show_info(msg: &str) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};

    let title: Vec<u16> = OsStr::new(i18n::t().settings_title())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let text: Vec<u16> = OsStr::new(msg)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let _ = MessageBoxW(
            None,
            PCWSTR(text.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

#[cfg(not(windows))]
fn show_info(msg: &str) {
    println!("{}", msg);
}

enum SaveOutcome {
    Status { ok: bool, message: String },
    Conflicts { items: Vec<ConflictItemDto> },
}
