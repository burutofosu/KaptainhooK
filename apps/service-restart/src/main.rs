#![windows_subsystem = "windows"]
//! kh-service-restart: SCM API で KaptainhooK サービスを再起動する。

use std::error::Error;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx,
    StartServiceW, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STATUS,
    SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_PROCESS, SERVICE_STOP, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_RUNNING, SERVICE_START_PENDING, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO,
};
use windows::Win32::System::Threading::Sleep;
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK};
use windows::core::PCWSTR;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

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
const SERVICE_NAME: &str = "KaptainhooKService";
const WAIT_TIMEOUT_MS: u64 = 10_000;
const POLL_INTERVAL_MS: u64 = 200;

fn main() {
    if let Err(e) = run() {
        show_message("KaptainhooK Service", &format!("サービスの再起動に失敗しました。\n\n{e}"), true);
        return;
    }
    show_message("KaptainhooK Service", "サービスを再起動しました。", false);
}

fn run() -> Result<()> {
    let scm = open_scm()?;
    let service = open_service(scm, SERVICE_NAME)?;

    stop_service(&service)?;
    std::thread::sleep(Duration::from_millis(500));
    start_service(&service)?;

    Ok(())
}

fn open_scm() -> Result<SCMHandle> {
    unsafe {
        let handle = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
            .map_err(|e| err(format!("OpenSCManagerW failed: {}", e.message())))?;
        Ok(SCMHandle(handle))
    }
}

fn open_service(scm: SCMHandle, name: &str) -> Result<ServiceHandle> {
    let name_w: Vec<u16> = OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        match OpenServiceW(
            scm.0,
            PCWSTR(name_w.as_ptr()),
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP,
        ) {
            Ok(handle) => Ok(ServiceHandle(handle)),
            Err(e) => {
                if e.code().0 as u32 == ERROR_SERVICE_DOES_NOT_EXIST.0 {
                    Err(err(format!("Service not found: {}", name)))
                } else {
                    Err(err(format!("OpenServiceW failed: {}", e.message())))
                }
            }
        }
    }
}

fn stop_service(service: &ServiceHandle) -> Result<()> {
    let status = query_status(service)?;
    if status.dwCurrentState == SERVICE_STOPPED {
        return Ok(());
    }
    if status.dwCurrentState == SERVICE_STOP_PENDING {
        wait_for_status(service, SERVICE_STOPPED, WAIT_TIMEOUT_MS)?;
        return Ok(());
    }

    unsafe {
        let mut svc_status = SERVICE_STATUS::default();
        ControlService(service.0, SERVICE_CONTROL_STOP, &mut svc_status)
            .map_err(|e| err(format!("ControlService stop failed: {}", e.message())))?;
    }
    wait_for_status(service, SERVICE_STOPPED, WAIT_TIMEOUT_MS)
}

fn start_service(service: &ServiceHandle) -> Result<()> {
    let status = query_status(service)?;
    if status.dwCurrentState == SERVICE_RUNNING {
        return Ok(());
    }
    if status.dwCurrentState == SERVICE_START_PENDING {
        wait_for_status(service, SERVICE_RUNNING, WAIT_TIMEOUT_MS)?;
        return Ok(());
    }

    unsafe {
        StartServiceW(service.0, None)
            .map_err(|e| err(format!("StartServiceW failed: {}", e.message())))?;
    }
    wait_for_status(service, SERVICE_RUNNING, WAIT_TIMEOUT_MS)
}

fn query_status(service: &ServiceHandle) -> Result<SERVICE_STATUS_PROCESS> {
    unsafe {
        let mut bytes_needed = 0u32;
        let mut buffer = vec![0u8; std::mem::size_of::<SERVICE_STATUS_PROCESS>()];
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            Some(buffer.as_mut_slice()),
            &mut bytes_needed,
        )
        .map_err(|e| err(format!("QueryServiceStatusEx failed: {}", e.message())))?;
        if bytes_needed as usize > buffer.len() {
            return Err(err("QueryServiceStatusEx returned short buffer"));
        }
        let ptr = buffer.as_ptr() as *const SERVICE_STATUS_PROCESS;
        let status = std::ptr::read_unaligned(ptr);
        Ok(status)
    }
}

fn wait_for_status(
    service: &ServiceHandle,
    desired: SERVICE_STATUS_CURRENT_STATE,
    timeout_ms: u64,
) -> Result<()> {
    let start = Instant::now();
    loop {
        let status = query_status(service)?;
        if status.dwCurrentState == desired {
            return Ok(());
        }
        if start.elapsed() > Duration::from_millis(timeout_ms) {
            return Err(err("Timeout waiting for service state"));
        }
        unsafe { Sleep(POLL_INTERVAL_MS as u32) };
    }
}

fn show_message(title: &str, msg: &str, is_error: bool) {
    let title_w: Vec<u16> = OsStr::new(title)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let msg_w: Vec<u16> = OsStr::new(msg)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let flags = if is_error { MB_OK | MB_ICONERROR } else { MB_OK | MB_ICONINFORMATION };
    unsafe {
        let _ = MessageBoxW(None, PCWSTR(msg_w.as_ptr()), PCWSTR(title_w.as_ptr()), flags);
    }
}

struct SCMHandle(windows::Win32::System::Services::SC_HANDLE);
impl Drop for SCMHandle {
    fn drop(&mut self) {
        unsafe { let _ = CloseServiceHandle(self.0); }
    }
}

struct ServiceHandle(windows::Win32::System::Services::SC_HANDLE);
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe { let _ = CloseServiceHandle(self.0); }
    }
}
