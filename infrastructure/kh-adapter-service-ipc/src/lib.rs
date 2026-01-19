//! guard と service 間の IPC アダプタ。
//!
//! メッセージプロトコルを定義し、クライアント/サーバー実装を提供する。

use kh_domain::error::DomainError;
pub use kh_domain::error::{ServiceErrorCode, ServiceErrorMessageId};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;

pub const PIPE_NAME: &str = r"\\.\pipe\KaptainhooKService";
pub const PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_TTL_MS: u32 = 2_000;
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024;

#[cfg(windows)]
static NO_STOP: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy)]
pub struct ClientContext {
    pub pid: u32,
}

impl ClientContext {
    pub fn unknown() -> Self {
        Self { pid: 0 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeginBypassRequest {
    pub protocol_version: u32,
    pub target_exe: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeginBypassResponse {
    pub protocol_version: u32,
    pub lease_id: String,
    pub ttl_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteBypassRequest {
    pub protocol_version: u32,
    pub lease_id: String,
    pub launched_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "service_error_code_serde::option")]
    pub error_code: Option<ServiceErrorCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteBypassResponse {
    pub protocol_version: u32,
    pub restored_ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub protocol_version: u32,
    #[serde(with = "service_error_code_serde")]
    pub error_code: ServiceErrorCode,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "service_error_message_id_serde::option")]
    pub message_id: Option<ServiceErrorMessageId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceRequest {
    BeginBypass(BeginBypassRequest),
    CompleteBypass(CompleteBypassRequest),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceResponse {
    BeginBypass(BeginBypassResponse),
    CompleteBypass(CompleteBypassResponse),
    Error(ErrorResponse),
}

mod service_error_code_serde {
    use super::ServiceErrorCode;
    use serde::{Deserializer, Serializer};
    use serde::de::{self, Visitor};
    use std::fmt;

    pub fn serialize<S>(value: &ServiceErrorCode, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ServiceErrorCode, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CodeVisitor;

        impl<'de> Visitor<'de> for CodeVisitor {
            type Value = ServiceErrorCode;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("service error code")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                ServiceErrorCode::from_str(v)
                    .ok_or_else(|| de::Error::custom(format!("unknown ServiceErrorCode: {v}")))
            }
        }

        deserializer.deserialize_str(CodeVisitor)
    }

    pub mod option {
        use super::ServiceErrorCode;
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(value: &Option<ServiceErrorCode>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match value {
                Some(code) => serializer.serialize_some(code.as_str()),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<ServiceErrorCode>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt = Option::<String>::deserialize(deserializer)?;
            match opt {
                Some(code) => ServiceErrorCode::from_str(&code)
                    .ok_or_else(|| serde::de::Error::custom(format!("unknown ServiceErrorCode: {code}")))
                    .map(Some),
                None => Ok(None),
            }
        }
    }
}

mod service_error_message_id_serde {
    pub mod option {
        use crate::ServiceErrorMessageId;
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(
            value: &Option<ServiceErrorMessageId>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match value {
                Some(id) => serializer.serialize_some(id.as_str()),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(
            deserializer: D,
        ) -> Result<Option<ServiceErrorMessageId>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt = Option::<String>::deserialize(deserializer)?;
            match opt {
                Some(id) => ServiceErrorMessageId::from_str(&id)
                    .ok_or_else(|| serde::de::Error::custom(format!("unknown ServiceErrorMessageId: {id}")))
                    .map(Some),
                None => Ok(None),
            }
        }
    }
}

pub fn encode_request(request: &ServiceRequest) -> Result<Vec<u8>, DomainError> {
    let data = serde_json::to_vec(request)
        .map_err(|e| DomainError::IpcError(format!("serialize request failed: {e}")))?;
    if data.len() > MAX_MESSAGE_BYTES {
        return Err(DomainError::IpcError("request too large".into()));
    }
    Ok(data)
}

pub fn decode_request(data: &[u8]) -> Result<ServiceRequest, DomainError> {
    if data.len() > MAX_MESSAGE_BYTES {
        return Err(DomainError::IpcError("request too large".into()));
    }
    serde_json::from_slice(data)
        .map_err(|e| DomainError::IpcError(format!("parse request failed: {e}")))
}

pub fn encode_response(response: &ServiceResponse) -> Result<Vec<u8>, DomainError> {
    let data = serde_json::to_vec(response)
        .map_err(|e| DomainError::IpcError(format!("serialize response failed: {e}")))?;
    if data.len() > MAX_MESSAGE_BYTES {
        return Err(DomainError::IpcError("response too large".into()));
    }
    Ok(data)
}

pub fn decode_response(data: &[u8]) -> Result<ServiceResponse, DomainError> {
    if data.len() > MAX_MESSAGE_BYTES {
        return Err(DomainError::IpcError("response too large".into()));
    }
    serde_json::from_slice(data)
        .map_err(|e| DomainError::IpcError(format!("parse response failed: {e}")))
}

#[derive(Debug, Clone)]
pub struct ServiceIpcClient {
    pipe_name: String,
}

impl Default for ServiceIpcClient {
    fn default() -> Self {
        Self {
            pipe_name: PIPE_NAME.to_string(),
        }
    }
}

impl ServiceIpcClient {
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
        }
    }

    pub fn begin_bypass(&self, target_exe: &str) -> Result<BeginBypassResponse, DomainError> {
        let request = ServiceRequest::BeginBypass(BeginBypassRequest {
            protocol_version: PROTOCOL_VERSION,
            target_exe: target_exe.to_string(),
        });
        let response = self.send_request(&request)?;
        match response {
            ServiceResponse::BeginBypass(resp) => Ok(resp),
            ServiceResponse::Error(err) => Err(DomainError::IpcServiceError {
                context: "begin_bypass".to_string(),
                code: err.error_code,
                message_id: err.message_id,
            }),
            _ => Err(DomainError::IpcError(
                "unexpected response for begin_bypass".into(),
            )),
        }
    }

    pub fn complete_bypass(
        &self,
        lease_id: &str,
        launched_pid: Option<u32>,
        error_code: Option<ServiceErrorCode>,
    ) -> Result<CompleteBypassResponse, DomainError> {
        let request = ServiceRequest::CompleteBypass(CompleteBypassRequest {
            protocol_version: PROTOCOL_VERSION,
            lease_id: lease_id.to_string(),
            launched_pid,
            error_code,
        });
        let response = self.send_request(&request)?;
        match response {
            ServiceResponse::CompleteBypass(resp) => Ok(resp),
            ServiceResponse::Error(err) => Err(DomainError::IpcServiceError {
                context: "complete_bypass".to_string(),
                code: err.error_code,
                message_id: err.message_id,
            }),
            _ => Err(DomainError::IpcError(
                "unexpected response for complete_bypass".into(),
            )),
        }
    }

    fn send_request(&self, _request: &ServiceRequest) -> Result<ServiceResponse, DomainError> {
        send_request(&self.pipe_name, _request)
    }
}

#[cfg(windows)]
fn send_request(pipe_name: &str, request: &ServiceRequest) -> Result<ServiceResponse, DomainError> {
    windows_impl::send_request(pipe_name, request)
}

#[cfg(not(windows))]
fn send_request(_pipe_name: &str, _request: &ServiceRequest) -> Result<ServiceResponse, DomainError> {
    Err(DomainError::IpcError(
        "service IPC client not supported on this platform".into(),
    ))
}

#[derive(Debug, Clone)]
pub struct ServiceIpcServer {
    pipe_name: String,
}

impl Default for ServiceIpcServer {
    fn default() -> Self {
        Self {
            pipe_name: PIPE_NAME.to_string(),
        }
    }
}

impl ServiceIpcServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_pipe_name(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
        }
    }

    pub fn run<F>(&self, handler: F) -> Result<(), DomainError>
    where
        F: Fn(ServiceRequest) -> ServiceResponse + Send + Sync + 'static,
    {
        self.run_with_context(move |request, _ctx| handler(request))
    }

    pub fn run_with_context<F>(&self, handler: F) -> Result<(), DomainError>
    where
        F: Fn(ServiceRequest, ClientContext) -> ServiceResponse + Send + Sync + 'static,
    {
        let _ = &self.pipe_name;
        run_server(&self.pipe_name, handler)
    }

    pub fn run_with_context_until<F>(
        &self,
        stop: &'static AtomicBool,
        handler: F,
    ) -> Result<(), DomainError>
    where
        F: Fn(ServiceRequest, ClientContext) -> ServiceResponse + Send + Sync + 'static,
    {
        let _ = &self.pipe_name;
        run_server_until(&self.pipe_name, stop, handler)
    }
}

#[cfg(windows)]
fn run_server<F>(pipe_name: &str, handler: F) -> Result<(), DomainError>
where
    F: Fn(ServiceRequest, ClientContext) -> ServiceResponse + Send + Sync + 'static,
{
    run_server_until(pipe_name, &NO_STOP, handler)
}

#[cfg(windows)]
fn run_server_until<F>(
    pipe_name: &str,
    stop: &'static AtomicBool,
    handler: F,
) -> Result<(), DomainError>
where
    F: Fn(ServiceRequest, ClientContext) -> ServiceResponse + Send + Sync + 'static,
{
    windows_impl::run_server(pipe_name, stop, handler)
}

#[cfg(not(windows))]
fn run_server<F>(_pipe_name: &str, _handler: F) -> Result<(), DomainError>
where
    F: Fn(ServiceRequest, ClientContext) -> ServiceResponse + Send + Sync + 'static,
{
    Err(DomainError::IpcError(
        "service IPC server not supported on this platform".into(),
    ))
}

#[cfg(not(windows))]
fn run_server_until<F>(
    _pipe_name: &str,
    _stop: &'static AtomicBool,
    _handler: F,
) -> Result<(), DomainError>
where
    F: Fn(ServiceRequest, ClientContext) -> ServiceResponse + Send + Sync + 'static,
{
    Err(DomainError::IpcError(
        "service IPC server not supported on this platform".into(),
    ))
}

#[cfg(windows)]
pub fn poke_server(pipe_name: &str) -> Result<(), DomainError> {
    windows_impl::poke_server(pipe_name)
}

#[cfg(not(windows))]
pub fn poke_server(_pipe_name: &str) -> Result<(), DomainError> {
    Err(DomainError::IpcError(
        "service IPC server not supported on this platform".into(),
    ))
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use kh_log_utils::lifecycle_line;
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE, ERROR_MORE_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_BUSY,
        ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
        PeekNamedPipe, SetNamedPipeHandleState, WaitNamedPipeW,
        PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
    };
    use windows::Win32::UI::Shell::{FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::System::Registry::{
        RegGetValueW, RegOpenKeyExW, RegCloseKey, HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE,
        KEY_WOW64_64KEY, RRF_RT_REG_SZ,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::core::{BOOL, PCWSTR, PWSTR};
    use std::sync::{Mutex, OnceLock};
    use std::time::SystemTime;

    const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";
    const TRUSTED_HASHES_REG_PATH: &str = r"SOFTWARE\KaptainhooK\TrustedHashes";
    const READ_TIMEOUT_MS: u64 = 3_000;
    const CLIENT_RESPONSE_TIMEOUT_MS: u64 = 5_000;
    const MAX_ACTIVE_CLIENTS: usize = 32;

    fn log_ipc(msg: &str) {
        let line = lifecycle_line("SERVICE_IPC", msg);
        for path in log_paths() {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                let _ = file.write_all(line.as_bytes());
                let _ = file.flush();
                return;
            }
        }
    }

    fn log_paths() -> Vec<PathBuf> {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        let base = PathBuf::from(base).join("KaptainhooK");
        vec![
            base.join("final").join("logs").join("kh-lifecycle.log"),
            base.join("bin").join("kh-lifecycle.log"),
            std::env::temp_dir().join("kh-lifecycle.log"),
        ]
    }

    fn to_wide(s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }

    pub fn run_server<F>(
        pipe_name: &str,
        stop: &'static AtomicBool,
        handler: F,
    ) -> Result<(), DomainError>
    where
        F: Fn(ServiceRequest, ClientContext) -> ServiceResponse + Send + Sync + 'static,
    {
        let handler: Arc<
            dyn Fn(ServiceRequest, ClientContext) -> ServiceResponse + Send + Sync + 'static,
        > = Arc::new(handler);
        let active = Arc::new(AtomicUsize::new(0));
        loop {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let pipe = create_pipe(pipe_name)?;
            if let Err(_) = unsafe { ConnectNamedPipe(pipe, None) } {
                let err = unsafe { GetLastError() };
                if err != ERROR_PIPE_CONNECTED {
                    log_ipc(&format!("IPC ConnectNamedPipe failed: {}", err.0));
                    let _ = unsafe { CloseHandle(pipe) };
                    continue;
                }
            }
            if stop.load(Ordering::SeqCst) {
                let _ = unsafe { DisconnectNamedPipe(pipe) };
                let _ = unsafe { CloseHandle(pipe) };
                break;
            }
            if active.load(Ordering::SeqCst) >= MAX_ACTIVE_CLIENTS {
                let _ = unsafe { DisconnectNamedPipe(pipe) };
                let _ = unsafe { CloseHandle(pipe) };
                continue;
            }
            let handler = Arc::clone(&handler);
            let active = Arc::clone(&active);
            let pipe_raw = pipe.0 as usize;
            std::thread::spawn(move || {
                let pipe = HANDLE(pipe_raw as *mut _);
                let _guard = ActiveGuard::new(active);
                handle_client(pipe, handler, stop);
            });
        }
        Ok(())
    }

    struct ActiveGuard {
        active: Arc<AtomicUsize>,
    }

    impl ActiveGuard {
        fn new(active: Arc<AtomicUsize>) -> Self {
            active.fetch_add(1, Ordering::SeqCst);
            Self { active }
        }
    }

    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn handle_client(
        pipe: HANDLE,
        handler: Arc<dyn Fn(ServiceRequest, ClientContext) -> ServiceResponse + Send + Sync + 'static>,
        stop: &'static AtomicBool,
    ) {
        let client_ctx = match validate_client(pipe) {
            Ok(ctx) => ctx,
            Err(_) => {
                let response = ServiceResponse::Error(ErrorResponse {
                    protocol_version: PROTOCOL_VERSION,
                    error_code: ServiceErrorCode::ClientNotTrusted,
                    message_id: None,
                });
                if let Ok(response_data) = encode_response(&response) {
                    if write_message(pipe, &response_data).is_ok() {
                        let _ = flush_pipe(pipe);
                        log_ipc("IPC response sent: client_not_trusted");
                    }
                }
                let _ = unsafe { DisconnectNamedPipe(pipe) };
                let _ = unsafe { CloseHandle(pipe) };
                return;
            }
        };
        log_ipc(&format!("IPC client accepted: pid={}", client_ctx.pid));

        let request_data = match read_message_with_timeout(pipe, stop) {
            Ok(data) => data,
            Err(err) => {
                if stop.load(Ordering::SeqCst) {
                    let _ = unsafe { DisconnectNamedPipe(pipe) };
                    let _ = unsafe { CloseHandle(pipe) };
                    return;
                }
                let message_id = match &err {
                    PipeReadError::MessageTooLarge => Some(ServiceErrorMessageId::MessageTooLarge),
                    PipeReadError::Ipc(_) => None,
                };
                let (error_code, err_msg) = match &err {
                    PipeReadError::MessageTooLarge => (
                        ServiceErrorCode::MessageTooLarge,
                        "message too large".to_string(),
                    ),
                    PipeReadError::Ipc(e) => (ServiceErrorCode::InternalError, e.to_string()),
                };
                log_ipc(&format!("IPC read failed: {}", err_msg));
                let response = ServiceResponse::Error(ErrorResponse {
                    protocol_version: PROTOCOL_VERSION,
                    error_code,
                    message_id,
                });
                if let Ok(response_data) = encode_response(&response) {
                    if write_message(pipe, &response_data).is_ok() {
                        let _ = flush_pipe(pipe);
                        log_ipc("IPC response sent: error");
                    }
                }
                let _ = unsafe { DisconnectNamedPipe(pipe) };
                let _ = unsafe { CloseHandle(pipe) };
                return;
            }
        };

        let response = match decode_request(&request_data) {
            Ok(req) => {
                match &req {
                    ServiceRequest::BeginBypass(r) => {
                        log_ipc(&format!("IPC request: begin_bypass target={}", r.target_exe));
                    }
                    ServiceRequest::CompleteBypass(r) => {
                        log_ipc(&format!(
                            "IPC request: complete_bypass lease_id={}",
                            r.lease_id
                        ));
                    }
                }
                handler(req, client_ctx)
            }
            Err(_) => ServiceResponse::Error(ErrorResponse {
                protocol_version: PROTOCOL_VERSION,
                error_code: ServiceErrorCode::InternalError,
                message_id: Some(ServiceErrorMessageId::FailedParseRequest),
            }),
        };

        if let Ok(response_data) = encode_response(&response) {
            match write_message(pipe, &response_data) {
                Ok(()) => {
                    let _ = flush_pipe(pipe);
                    let label = match &response {
                        ServiceResponse::BeginBypass(_) => "begin_bypass",
                        ServiceResponse::CompleteBypass(_) => "complete_bypass",
                        ServiceResponse::Error(err) => err.error_code.as_str(),
                    };
                    log_ipc(&format!("IPC response sent: {}", label));
                }
                Err(err) => {
                    log_ipc(&format!("IPC write failed: {}", err));
                }
            }
        } else {
            log_ipc("IPC encode response failed");
        }

        let _ = unsafe { DisconnectNamedPipe(pipe) };
        let _ = unsafe { CloseHandle(pipe) };
    }

    fn create_pipe(pipe_name: &str) -> Result<HANDLE, DomainError> {
        let name = to_wide(pipe_name);
        let (sa, _sd_guard) = build_pipe_security_attributes()?;
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                MAX_MESSAGE_BYTES as u32,
                MAX_MESSAGE_BYTES as u32,
                0,
                Some(&sa),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(DomainError::IpcError(format!(
                "CreateNamedPipeW failed: {}",
                unsafe { GetLastError().0 }
            )));
        }
        Ok(handle)
    }

    pub fn send_request(pipe_name: &str, request: &ServiceRequest) -> Result<ServiceResponse, DomainError> {
        let data = encode_request(request)?;
        let handle = connect_pipe(pipe_name)?;
        let _handle_guard = HandleGuard(handle);
        set_message_mode(handle)?;
        write_message(handle, &data)?;
        let response_data = read_message_with_timeout_ms(handle, CLIENT_RESPONSE_TIMEOUT_MS)
            .map_err(|err| err.into_domain())?;
        decode_response(&response_data)
    }

    pub fn poke_server(pipe_name: &str) -> Result<(), DomainError> {
        let name = to_wide(pipe_name);
        let desired_access = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0;
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
        let Ok(handle) = handle else {
            return Ok(());
        };
        let _ = unsafe { CloseHandle(handle) };
        Ok(())
    }

    fn connect_pipe(pipe_name: &str) -> Result<HANDLE, DomainError> {
        let name = to_wide(pipe_name);
        let desired_access = FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0;
        loop {
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
                        let wait_ok =
                            unsafe { WaitNamedPipeW(PCWSTR(name.as_ptr()), 5_000).as_bool() };
                        if wait_ok {
                            continue;
                        }
                    }
                    return Err(DomainError::IpcError(format!(
                        "service_unavailable: CreateFileW(pipe) failed: {}",
                        err.0
                    )));
                }
            };

            return Ok(handle);
        }
    }

    fn set_message_mode(handle: HANDLE) -> Result<(), DomainError> {
        let mut mode = PIPE_READMODE_MESSAGE;
        unsafe { SetNamedPipeHandleState(handle, Some(&mut mode), None, None) }
            .map_err(|e| DomainError::IpcError(format!("SetNamedPipeHandleState failed: {}", e.message())))?;
        Ok(())
    }

    enum PipeReadError {
        MessageTooLarge,
        Ipc(DomainError),
    }

    impl PipeReadError {
        fn into_domain(self) -> DomainError {
            match self {
                Self::MessageTooLarge => DomainError::IpcError("message too large".into()),
                Self::Ipc(err) => err,
            }
        }
    }

    fn read_message(handle: HANDLE) -> Result<Vec<u8>, PipeReadError> {
        let mut buffer = vec![0u8; MAX_MESSAGE_BYTES];
        let mut read = 0u32;
        let result = unsafe { ReadFile(handle, Some(buffer.as_mut_slice()), Some(&mut read), None) };
        if result.is_ok() {
            buffer.truncate(read as usize);
            return Ok(buffer);
        }
        let err = unsafe { GetLastError() };
        if err == ERROR_MORE_DATA {
            return Err(PipeReadError::MessageTooLarge);
        }
        Err(PipeReadError::Ipc(DomainError::IpcError(format!(
            "ReadFile failed: {}",
            err.0
        ))))
    }

    fn read_message_with_timeout(
        handle: HANDLE,
        stop: &'static AtomicBool,
    ) -> Result<Vec<u8>, PipeReadError> {
        let start = Instant::now();
        loop {
            if stop.load(Ordering::SeqCst) {
                return Err(PipeReadError::Ipc(DomainError::IpcError(
                    "server stopping".into(),
                )));
            }
            let mut available = 0u32;
            let result = unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut available), None) };
            if result.is_err() {
                let err = unsafe { GetLastError() };
                if err == ERROR_BROKEN_PIPE {
                    return Err(PipeReadError::Ipc(DomainError::IpcError(
                        "client disconnected".into(),
                    )));
                }
                return Err(PipeReadError::Ipc(DomainError::IpcError(format!(
                    "PeekNamedPipe failed: {}",
                    err.0
                ))));
            }
            if available > 0 {
                return read_message(handle);
            }
            if start.elapsed() > Duration::from_millis(READ_TIMEOUT_MS) {
                return Err(PipeReadError::Ipc(DomainError::IpcError(
                    "timeout waiting for request".into(),
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn read_message_with_timeout_ms(
        handle: HANDLE,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, PipeReadError> {
        let start = Instant::now();
        loop {
            let mut available = 0u32;
            let result = unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut available), None) };
            if result.is_err() {
                let err = unsafe { GetLastError() };
                if err == ERROR_BROKEN_PIPE {
                    return Err(PipeReadError::Ipc(DomainError::IpcError(
                        "service disconnected".into(),
                    )));
                }
                return Err(PipeReadError::Ipc(DomainError::IpcError(format!(
                    "PeekNamedPipe failed: {}",
                    err.0
                ))));
            }
            if available > 0 {
                return read_message(handle);
            }
            if start.elapsed() > Duration::from_millis(timeout_ms) {
                return Err(PipeReadError::Ipc(DomainError::IpcError(
                    "timeout waiting for response".into(),
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn write_message(handle: HANDLE, data: &[u8]) -> Result<(), DomainError> {
        if data.len() > MAX_MESSAGE_BYTES {
            return Err(DomainError::IpcError("message too large".into()));
        }
        let mut written = 0u32;
        let result = unsafe { WriteFile(handle, Some(data), Some(&mut written), None) };
        if result.is_ok() {
            Ok(())
        } else {
            Err(DomainError::IpcError(format!(
                "WriteFile failed: {}",
                unsafe { GetLastError().0 }
            )))
        }
    }

    fn flush_pipe(handle: HANDLE) -> Result<(), DomainError> {
        unsafe { FlushFileBuffers(handle) }
            .map_err(|e| DomainError::IpcError(format!("FlushFileBuffers failed: {}", e.message())))?;
        Ok(())
    }

    fn build_pipe_security_attributes() -> Result<(SECURITY_ATTRIBUTES, SdGuard), DomainError> {
        let sddl_w = to_wide(PIPE_SDDL);
        unsafe {
            let mut sd = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl_w.as_ptr()),
                SDDL_REVISION_1 as u32,
                &mut sd,
                None,
            )
            .map_err(|e| DomainError::IpcError(format!("parse pipe SDDL failed: {}", e.message())))?;
            let guard = SdGuard(sd);
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0 as *mut _,
                bInheritHandle: BOOL(0),
            };
            Ok((sa, guard))
        }
    }

    struct SdGuard(PSECURITY_DESCRIPTOR);
    impl Drop for SdGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }

    fn validate_client(pipe: HANDLE) -> Result<ClientContext, DomainError> {
        let pid = match get_client_pid(pipe) {
            Ok(pid) => pid,
            Err(err) => {
                log_ipc(&format!("IPC reject: get client pid failed: {err}"));
                return Err(err);
            }
        };
        let exe_path = match get_process_path(pid) {
            Ok(path) => path,
            Err(err) => {
                log_ipc(&format!("IPC reject: get client path failed (pid={}): {err}", pid));
                return Err(err);
            }
        };

        let filename_ok = exe_path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name.eq_ignore_ascii_case("kh-guard.exe"))
            .unwrap_or(false);
        if !filename_ok {
            log_ipc(&format!(
                "IPC reject: client filename mismatch (pid={}, path={}): expected kh-guard.exe",
                pid,
                exe_path.display()
            ));
            return Err(DomainError::IpcError("client not trusted".into()));
        }

        let expected = expected_guard_path()
            .and_then(|p| normalize_local_absolute_path(p))
            .ok_or_else(|| {
                log_ipc("IPC reject: expected guard path not found");
                DomainError::IpcError("expected guard path not found".into())
            })?;
        let actual = normalize_local_absolute_path(&exe_path)
            .ok_or_else(|| {
                log_ipc(&format!(
                    "IPC reject: client path invalid (pid={}, path={})",
                    pid,
                    exe_path.display()
                ));
                DomainError::IpcError("client path invalid".into())
            })?;
        if !actual.eq_ignore_ascii_case(&expected) {
            log_ipc(&format!(
                "IPC reject: client path mismatch (pid={}): expected={}, actual={}",
                pid,
                expected,
                actual
            ));
            return Err(DomainError::IpcError("client path mismatch".into()));
        }

        let trusted_hash = match read_trusted_hash("GuardHash") {
            Ok(hash) => hash,
            Err(err) => {
                log_ipc(&format!("IPC reject: trusted hash read failed: {err}"));
                return Err(err);
            }
        };
        let current_hash = match guard_hash_cached(&exe_path, &actual) {
            Ok(hash) => hash,
            Err(err) => {
                log_ipc(&format!(
                    "IPC reject: guard hash compute failed (pid={}, path={}): {err}",
                    pid,
                    exe_path.display()
                ));
                return Err(err);
            }
        };

        if !trusted_hash.eq_ignore_ascii_case(&current_hash) {
            log_ipc(&format!(
                "IPC reject: guard hash mismatch (pid={}): expected={}, actual={}",
                pid,
                trusted_hash,
                current_hash
            ));
            return Err(DomainError::IpcError("client hash mismatch".into()));
        }

        Ok(ClientContext { pid })
    }

    fn get_client_pid(pipe: HANDLE) -> Result<u32, DomainError> {
        let mut pid: u32 = 0;
        let result = unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) };
        if result.is_ok() && pid != 0 {
            Ok(pid)
        } else {
            Err(DomainError::IpcError("failed to get client pid".into()))
        }
    }

    fn get_process_path(pid: u32) -> Result<PathBuf, DomainError> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                .map_err(|e| DomainError::IpcError(format!("OpenProcess failed: {}", e.message())))?;
            let _handle_guard = HandleGuard(handle);

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
                        return Err(DomainError::IpcError("client path too long".into()));
                    }
                    continue;
                }
                if err.0 == 0 {
                    return Err(DomainError::IpcError("QueryFullProcessImageNameW failed".into()));
                }
                return Err(DomainError::IpcError(format!(
                    "QueryFullProcessImageNameW failed: {}",
                    err.0
                )));
            }
        }
    }

    fn read_trusted_hash(value_name: &str) -> Result<String, DomainError> {
        let path_w = to_wide(TRUSTED_HASHES_REG_PATH);
        let mut key: HKEY = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(path_w.as_ptr()),
                Some(0),
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                &mut key,
            )
        };
        if status.is_err() {
            log_ipc("TrustedHashes key not found");
            return Err(DomainError::IpcError("TrustedHashes key not found".into()));
        }

        let name_w = to_wide(value_name);
        let mut buffer: Vec<u16> = vec![0u16; 260];
        let mut size_bytes: u32 = (buffer.len() * std::mem::size_of::<u16>()) as u32;
        let status = unsafe {
            RegGetValueW(
                key,
                PCWSTR::null(),
                PCWSTR(name_w.as_ptr()),
                RRF_RT_REG_SZ,
                None,
                Some(buffer.as_mut_ptr() as *mut _),
                Some(&mut size_bytes),
            )
        };
        let _ = unsafe { RegCloseKey(key) };
        if status.is_err() {
            log_ipc(&format!("TrustedHashes value not found: {}", value_name));
            return Err(DomainError::IpcError("TrustedHashes value not found".into()));
        }

        let len = (size_bytes as usize / 2).saturating_sub(1);
        buffer.truncate(len);
        Ok(String::from_utf16_lossy(&buffer))
    }

    struct GuardHashCache {
        normalized_path: String,
        len: u64,
        modified: Option<SystemTime>,
        hash: String,
    }

    static GUARD_HASH_CACHE: OnceLock<Mutex<Option<GuardHashCache>>> = OnceLock::new();

    fn guard_hash_cached(path: &Path, normalized: &str) -> Result<String, DomainError> {
        let meta = std::fs::metadata(path)
            .map_err(|e| DomainError::IpcError(format!("stat {:?}: {}", path, e)))?;
        let len = meta.len();
        let modified = meta.modified().ok();

        let cache = GUARD_HASH_CACHE.get_or_init(|| Mutex::new(None));
        let mut guard = match cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if let Some(cached) = guard.as_ref() {
            if cached.normalized_path.eq_ignore_ascii_case(normalized)
                && cached.len == len
                && cached.modified == modified
            {
                return Ok(cached.hash.clone());
            }
        }

        let hash = sha256_hex(path)?;
        *guard = Some(GuardHashCache {
            normalized_path: normalized.to_string(),
            len,
            modified,
            hash: hash.clone(),
        });
        Ok(hash)
    }

    fn sha256_hex(path: &Path) -> Result<String, DomainError> {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(path)
            .map_err(|e| DomainError::IpcError(format!("open {:?}: {}", path, e)))?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| DomainError::IpcError(format!("read {:?}: {}", path, e)))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let hash = hasher.finalize();
        Ok(hash.iter().map(|b| format!("{:02x}", b)).collect())
    }

    fn expected_guard_path() -> Option<PathBuf> {
        let candidate = PathBuf::from(default_guard_path());
        if candidate.exists() {
            Some(candidate)
        } else {
            None
        }
    }

    fn default_guard_path() -> String {
        default_install_bin_dir()
            .join("kh-guard.exe")
            .to_string_lossy()
            .to_string()
    }

    fn default_install_bin_dir() -> PathBuf {
        known_folder_path(&FOLDERID_ProgramFiles)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
            .join("KaptainhooK")
            .join("bin")
    }

    fn known_folder_path(id: &windows::core::GUID) -> Option<PathBuf> {
        unsafe {
            let raw: PWSTR = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
            let s = pwstr_to_string(raw);
            CoTaskMemFree(Some(raw.0 as _));
            if s.is_empty() {
                None
            } else {
                Some(PathBuf::from(s))
            }
        }
    }

    fn pwstr_to_string(pwstr: PWSTR) -> String {
        unsafe {
            if pwstr.is_null() {
                return String::new();
            }
            let mut len = 0usize;
            while *pwstr.0.add(len) != 0 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(pwstr.0, len);
            String::from_utf16_lossy(slice)
        }
    }

    fn normalize_local_absolute_path(path: impl AsRef<Path>) -> Option<String> {
        let raw = path.as_ref().to_string_lossy();
        kh_domain::path::normalize_local_drive_absolute_path(&raw)
    }

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}
