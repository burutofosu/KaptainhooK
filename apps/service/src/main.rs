#![windows_subsystem = "windows"]
//! kh-service: 特権 Windows サービスのエントリポイント。

use std::error::Error;
use std::process::ExitCode;
use kh_log_utils::write_lifecycle_line;

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

fn log_service(msg: &str) {
    write_lifecycle_line("SERVICE", msg);
}

fn main() -> ExitCode {
    #[cfg(windows)]
    {
        match windows_service::try_run_service() {
            Ok(true) => return ExitCode::from(0),
            Ok(false) => {}
            Err(e) => {
                let msg = format!("kh-service error: {e}");
                eprintln!("{msg}");
                log_service(&msg);
                return ExitCode::from(1);
            }
        }
    }

    match run_console() {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            let msg = format!("kh-service error: {e}");
            eprintln!("{msg}");
            log_service(&msg);
            ExitCode::from(1)
        }
    }
}

fn run_console() -> Result<()> {
    let runtime = kh_composition::service::ServiceRuntime::new()?;
    runtime.run()
}

#[cfg(windows)]
mod windows_service {
    use kh_composition::service::ServiceRuntime;
    use kh_composition::service::poke_service_ipc;
    use super::log_service;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use windows::Win32::Foundation::ERROR_FAILED_SERVICE_CONTROLLER_CONNECT;
    use windows::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN,
        SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
        SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
        SERVICE_TABLE_ENTRYW,
        SERVICE_WIN32_OWN_PROCESS,
    };
    use windows::core::{PCWSTR, PWSTR};

    const SERVICE_NAME: &str = "KaptainhooKService";
    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
    static mut STATUS_HANDLE: SERVICE_STATUS_HANDLE = SERVICE_STATUS_HANDLE(std::ptr::null_mut());

    pub fn try_run_service() -> super::Result<bool> {
        let mut name = to_wide(SERVICE_NAME);
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: PWSTR(name.as_mut_ptr()),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW::default(),
        ];

        match unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } {
            Ok(()) => Ok(true),
            Err(err) => {
                let expected = hresult_from_win32(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.0);
                if err.code().0 as u32 == expected {
                    return Ok(false);
                }
                Err(super::err(format!(
                    "StartServiceCtrlDispatcherW failed: {}",
                    err.message()
                )))
            }
        }
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
        STOP_REQUESTED.store(false, Ordering::SeqCst);

        let name = to_wide(SERVICE_NAME);
        let handle = match unsafe {
            RegisterServiceCtrlHandlerExW(PCWSTR(name.as_ptr()), Some(service_ctrl_handler), None)
        } {
            Ok(handle) => handle,
            Err(_) => return,
        };
        unsafe {
            STATUS_HANDLE = handle;
        }

        let _ = report_status(SERVICE_START_PENDING, 0);

        let runtime = match ServiceRuntime::new() {
            Ok(rt) => rt,
            Err(e) => {
                log_service(&format!("ServiceRuntime::new failed: {e}"));
                let _ = report_status(SERVICE_STOPPED, 0);
                return;
            }
        };

        log_service("kh-service starting IPC server");
        let handle = std::thread::spawn(move || {
            if let Err(e) = runtime.run_until(&STOP_REQUESTED) {
                eprintln!("kh-service IPC server stopped: {e:#}");
                log_service(&format!("kh-service IPC server stopped: {e:#}"));
                STOP_REQUESTED.store(true, Ordering::SeqCst);
                let _ = poke_service_ipc();
            }
        });

        let _ = report_status(
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        );
        log_service("kh-service running");

        while !STOP_REQUESTED.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(200));
        }

        let _ = report_status(SERVICE_STOP_PENDING, 0);
        let _ = handle.join();
        let _ = report_status(SERVICE_STOPPED, 0);
    }

    unsafe extern "system" fn service_ctrl_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut std::ffi::c_void,
        _context: *mut std::ffi::c_void,
    ) -> u32 {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
                STOP_REQUESTED.store(true, Ordering::SeqCst);
                log_service("kh-service stop requested");
                let _ = poke_service_ipc();
                let _ = report_status(SERVICE_STOP_PENDING, 0);
            }
            _ => {}
        }
        0
    }

    fn report_status(state: SERVICE_STATUS_CURRENT_STATE, controls_accepted: u32) -> bool {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: controls_accepted,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        unsafe { SetServiceStatus(STATUS_HANDLE, &status).is_ok() }
    }

    fn hresult_from_win32(err: u32) -> u32 {
        0x80070000u32 | (err & 0xFFFF)
    }

    fn to_wide(s: &str) -> Vec<u16> {
        let mut wide: Vec<u16> = s.encode_utf16().collect();
        wide.push(0);
        wide
    }

}
