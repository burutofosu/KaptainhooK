//! kh-adapter-task: Windows タスクスケジューラ経由で復元専用タスクを実行するアダプタ。
//! `KaptainhooKRestore` タスクの作成・削除・存在確認・実行をラップする。

use kh_domain::{error::DomainError, port::driven::{RestoreKicker, TaskScheduler}};
use std::path::{Path, PathBuf};
#[cfg(not(windows))]
use std::process::Command;
#[cfg(windows)]
use windows::core::Interface;

#[cfg(windows)]
pub fn ensure_task_runnable_by_authenticated_users(task_name: &str) -> Result<(), DomainError> {
    use windows::core::BSTR;
    use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, S_FALSE, S_OK};
    use windows::Win32::System::Com::{
        COINIT_MULTITHREADED, CLSCTX_INPROC_SERVER, CoCreateInstance, CoInitializeEx, CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler as TASKSERVICE_CLSID};
    use windows::Win32::System::Variant::VARIANT;

    unsafe {
        // COM初期化（同一スレッドでの呼び出しを想定）
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        let did_init = if hr == S_OK || hr == S_FALSE {
            true
        } else if hr == RPC_E_CHANGED_MODE {
            // 既に別モデルで初期化済み。この場合はUninitializeしない。
            false
        } else {
            return Err(DomainError::ProcessLaunchFailed(format!(
                "COM init failed: 0x{:08x}",
                hr.0 as u32
            )));
        };

        // 対応する Uninitialize を呼ぶ
        struct CoUninit(bool);
        impl Drop for CoUninit {
            fn drop(&mut self) {
                if self.0 {
                    unsafe { CoUninitialize() }
                }
            }
        }
        let _guard = CoUninit(did_init);

        // タスクスケジューラに接続
        let service: ITaskService = CoCreateInstance(&TASKSERVICE_CLSID, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| DomainError::ProcessLaunchFailed(format!("CoCreateInstance(TaskScheduler) failed: {e}")))?;
        service
            .Connect(&VARIANT::default(), &VARIANT::default(), &VARIANT::default(), &VARIANT::default())
            .map_err(|e| DomainError::ProcessLaunchFailed(format!("ITaskService::Connect failed: {e}")))?;

        let root = BSTR::from("\\");
        let folder = service
            .GetFolder(&root)
            .map_err(|e| DomainError::ProcessLaunchFailed(format!("GetFolder(\\\\) failed: {e}")))?;

        let name = BSTR::from(task_name);
        let task = folder
            .GetTask(&name)
            .map_err(|e| DomainError::ProcessLaunchFailed(format!("GetTask({task_name}) failed: {e}")))?;

        // 0xF = OWNER|GROUP|DACL|SACL（PowerShell例相当）
        let sddl = task
            .GetSecurityDescriptor(0xF)
            .map_err(|e| DomainError::ProcessLaunchFailed(format!("GetSecurityDescriptor failed: {e}")))?;
        let sddl_str = sddl.to_string();

        // 既にAUが入っていれば何もしない
        if sddl_str.contains(";;;AU)") {
            return Ok(());
        }

        // (A;;GRGX;;;AU) をDACL末尾に追加（S: より前、または末尾）
        let ace = "(A;;GRGX;;;AU)";
        let new_sddl = if let Some(d_index) = sddl_str.find("D:") {
            let insert_at = sddl_str
                .find("S:")
                .unwrap_or_else(|| sddl_str.len());
            if insert_at >= d_index + 2 {
                let (head, tail) = sddl_str.split_at(insert_at);
                format!("{head}{ace}{tail}")
            } else {
                // 想定外だが、安全側に倒して末尾追加
                format!("{sddl_str}{ace}")
            }
        } else if let Some(s_index) = sddl_str.find("S:") {
            let (head, tail) = sddl_str.split_at(s_index);
            format!("{head}{ace}{tail}")
        } else {
            format!("{sddl_str}{ace}")
        };
        let new_bstr = BSTR::from(new_sddl);
        task.SetSecurityDescriptor(&new_bstr, 0)
            .map_err(|e| DomainError::ProcessLaunchFailed(format!("SetSecurityDescriptor failed: {e}")))?;
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn ensure_task_runnable_by_authenticated_users(_task_name: &str) -> Result<(), DomainError> {
    Ok(())
}

#[cfg(windows)]
fn com_error(context: &str, err: windows::core::Error) -> DomainError {
    DomainError::ProcessLaunchFailed(format!("{context}: {}", err.message()))
}

#[cfg(windows)]
fn is_not_found_error(err: &windows::core::Error) -> bool {
    matches!(err.code().0 as u32, 0x80070002 | 0x80070003)
}

#[cfg(windows)]
fn with_task_service<T, F>(f: F) -> Result<T, DomainError>
where
    F: FnOnce(&windows::Win32::System::TaskScheduler::ITaskService,
              &windows::Win32::System::TaskScheduler::ITaskFolder) -> Result<T, DomainError>,
{
    use windows::core::BSTR;
    use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, S_FALSE, S_OK};
    use windows::Win32::System::Com::{
        COINIT_MULTITHREADED, CLSCTX_INPROC_SERVER, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{
        ITaskService, TaskScheduler as TASKSERVICE_CLSID,
    };
    use windows::Win32::System::Variant::VARIANT;

    unsafe {
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        let did_init = if hr == S_OK || hr == S_FALSE {
            true
        } else if hr == RPC_E_CHANGED_MODE {
            false
        } else {
            return Err(DomainError::ProcessLaunchFailed(format!(
                "COM init failed: 0x{:08x}",
                hr.0 as u32
            )));
        };

        struct CoUninit(bool);
        impl Drop for CoUninit {
            fn drop(&mut self) {
                if self.0 {
                    unsafe { CoUninitialize() }
                }
            }
        }
        let _guard = CoUninit(did_init);

        let service: ITaskService =
            CoCreateInstance(&TASKSERVICE_CLSID, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| com_error("CoCreateInstance(TaskScheduler) failed", e))?;
        service
            .Connect(&VARIANT::default(), &VARIANT::default(), &VARIANT::default(), &VARIANT::default())
            .map_err(|e| com_error("ITaskService::Connect failed", e))?;

        let root = BSTR::from("\\");
        let folder = service
            .GetFolder(&root)
            .map_err(|e| com_error("GetFolder(\\\\) failed", e))?;

        f(&service, &folder)
    }
}

#[cfg(windows)]
fn create_task_via_com(task_name: &str, exe_path: &str) -> Result<(), DomainError> {
    use std::mem::ManuallyDrop;
    use windows::core::BSTR;
    use windows::Win32::Foundation::VARIANT_BOOL;
    use windows::Win32::System::TaskScheduler::{
        IExecAction, ITimeTrigger, TASK_ACTION_EXEC, TASK_CREATE_OR_UPDATE,
        TASK_LOGON_SERVICE_ACCOUNT, TASK_RUNLEVEL_HIGHEST, TASK_TRIGGER_TIME,
    };
    use windows::Win32::System::Variant::{VariantClear, VARIANT, VT_BSTR};

    struct VariantGuard(VARIANT);
    impl VariantGuard {
        fn from_bstr(value: &BSTR) -> Self {
            let mut variant = VARIANT::default();
            unsafe {
                let inner = &mut *variant.Anonymous.Anonymous;
                inner.vt = VT_BSTR;
                inner.Anonymous.bstrVal = ManuallyDrop::new(value.clone());
            }
            Self(variant)
        }

        fn as_ref(&self) -> &VARIANT {
            &self.0
        }
    }
    impl Drop for VariantGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = VariantClear(&mut self.0);
            }
        }
    }

    with_task_service(|service, folder| unsafe {
        let task_def = service
            .NewTask(0)
            .map_err(|e| com_error("NewTask failed", e))?;

        let principal = task_def
            .Principal()
            .map_err(|e| com_error("Principal failed", e))?;
        principal
            .SetUserId(&BSTR::from("SYSTEM"))
            .map_err(|e| com_error("SetUserId failed", e))?;
        principal
            .SetLogonType(TASK_LOGON_SERVICE_ACCOUNT)
            .map_err(|e| com_error("SetLogonType failed", e))?;
        principal
            .SetRunLevel(TASK_RUNLEVEL_HIGHEST)
            .map_err(|e| com_error("SetRunLevel failed", e))?;

        let settings = task_def
            .Settings()
            .map_err(|e| com_error("Settings failed", e))?;
        let yes = VARIANT_BOOL(1);
        let no = VARIANT_BOOL(0);
        let _ = settings.SetEnabled(yes);
        let _ = settings.SetAllowDemandStart(yes);
        let _ = settings.SetStartWhenAvailable(yes);
        let _ = settings.SetDisallowStartIfOnBatteries(no);
        let _ = settings.SetStopIfGoingOnBatteries(no);

        let triggers = task_def
            .Triggers()
            .map_err(|e| com_error("Triggers failed", e))?;
        let trigger = triggers
            .Create(TASK_TRIGGER_TIME)
            .map_err(|e| com_error("Create trigger failed", e))?;
        let time_trigger: ITimeTrigger = trigger
            .cast()
            .map_err(|e| com_error("Cast to ITimeTrigger failed", e))?;
        time_trigger
            .SetStartBoundary(&BSTR::from("2099-01-01T00:00:00Z"))
            .map_err(|e| com_error("SetStartBoundary failed", e))?;
        let _ = time_trigger.SetEnabled(no);

        let actions = task_def
            .Actions()
            .map_err(|e| com_error("Actions failed", e))?;
        let action = actions
            .Create(TASK_ACTION_EXEC)
            .map_err(|e| com_error("Create action failed", e))?;
        let exec: IExecAction = action
            .cast()
            .map_err(|e| com_error("Cast to IExecAction failed", e))?;
        exec.SetPath(&BSTR::from(exe_path))
            .map_err(|e| com_error("SetPath failed", e))?;
        if let Some(dir) = Path::new(exe_path).parent().and_then(|p| p.to_str()) {
            let _ = exec.SetWorkingDirectory(&BSTR::from(dir));
        }

        let name = BSTR::from(task_name);
        let user_bstr = BSTR::from("SYSTEM");
        let user = VariantGuard::from_bstr(&user_bstr);
        let password = VARIANT::default();
        let sddl = VARIANT::default();
        folder
            .RegisterTaskDefinition(
                &name,
                &task_def,
                TASK_CREATE_OR_UPDATE.0,
                user.as_ref(),
                &password,
                TASK_LOGON_SERVICE_ACCOUNT,
                &sddl,
            )
            .map_err(|e| com_error("RegisterTaskDefinition failed", e))?;

        Ok(())
    })
}

#[cfg(windows)]
fn delete_task_via_com(task_name: &str) -> Result<(), DomainError> {
    use windows::core::BSTR;
    with_task_service(|_service, folder| unsafe {
        let name = BSTR::from(task_name);
        match folder.DeleteTask(&name, 0) {
            Ok(()) => Ok(()),
            Err(e) if is_not_found_error(&e) => Ok(()),
            Err(e) => Err(com_error("DeleteTask failed", e)),
        }
    })
}

#[cfg(windows)]
fn task_exists_via_com(task_name: &str) -> Result<bool, DomainError> {
    use windows::core::BSTR;
    with_task_service(|_service, folder| unsafe {
        let name = BSTR::from(task_name);
        match folder.GetTask(&name) {
            Ok(_) => Ok(true),
            Err(e) if is_not_found_error(&e) => Ok(false),
            Err(e) => Err(com_error("GetTask failed", e)),
        }
    })
}

#[cfg(not(windows))]
fn task_exists_via_com(_task_name: &str) -> Result<bool, DomainError> {
    Ok(true)
}

#[cfg(windows)]

#[cfg(windows)]
fn compute_start_boundary_utc_z(delay_ms: u32) -> Result<String, DomainError> {
    use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
    use windows::Win32::System::Time::FileTimeToSystemTime;

    unsafe {
        let ft = GetSystemTimeAsFileTime();

        let mut ticks: u64 = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
        let add_100ns: u64 = (delay_ms as u64).saturating_mul(10_000); // 1ms = 10,000 * 100ns
        ticks = ticks.saturating_add(add_100ns);

        // 予約時刻がちょうど境界に一致すると、後段で書き込むLeaseState(expires_at_ms)より
        // 早く発火してしまう可能性があるため、常に「次の秒」へ繰り上げる。
        let rem = ticks % 10_000_000;
        if rem == 0 {
            ticks = ticks.saturating_add(10_000_000);
        } else {
            ticks = ticks.saturating_add(10_000_000 - rem);
        }

        let ft2 = FILETIME {
            dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };

        let mut st = SYSTEMTIME::default();
        FileTimeToSystemTime(&ft2, &mut st)
            .map_err(|e| com_error("FileTimeToSystemTime failed", e))?;

        Ok(format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        ))
    }
}

#[cfg(windows)]
fn schedule_task_once_after(task_name: &str, delay_ms: u32) -> Result<(), DomainError> {
    use std::mem::ManuallyDrop;
    use windows::core::BSTR;
    use windows::Win32::Foundation::VARIANT_BOOL;
    use windows::Win32::System::TaskScheduler::{
        ITimeTrigger, TASK_CREATE_OR_UPDATE, TASK_LOGON_SERVICE_ACCOUNT, TASK_TRIGGER_TIME,
    };
    use windows::Win32::System::Variant::{VariantClear, VARIANT, VT_BSTR};

    struct VariantGuard(VARIANT);
    impl VariantGuard {
        fn from_bstr(value: &BSTR) -> Self {
            let mut variant = VARIANT::default();
            unsafe {
                let inner = &mut *variant.Anonymous.Anonymous;
                inner.vt = VT_BSTR;
                inner.Anonymous.bstrVal = ManuallyDrop::new(value.clone());
            }
            Self(variant)
        }

        fn as_ref(&self) -> &VARIANT {
            &self.0
        }
    }
    impl Drop for VariantGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = VariantClear(&mut self.0);
            }
        }
    }

    let start_boundary = compute_start_boundary_utc_z(delay_ms)?;

    with_task_service(|_service, folder| unsafe {
        let name = BSTR::from(task_name);
        let task = folder.GetTask(&name).map_err(|e| com_error("GetTask failed", e))?;
        let task_def = task
            .Definition()
            .map_err(|e| com_error("Definition failed", e))?;

        // 古いタスク定義でも拾えるように、ここでもStartWhenAvailableを有効化しておく
        if let Ok(settings) = task_def.Settings() {
            let _ = settings.SetStartWhenAvailable(VARIANT_BOOL(1));
        }

        let triggers = task_def
            .Triggers()
            .map_err(|e| com_error("Triggers failed", e))?;

        let trigger = match triggers.get_Item(1) {
            Ok(t) => t,
            Err(_) => triggers
                .Create(TASK_TRIGGER_TIME)
                .map_err(|e| com_error("Create trigger failed", e))?,
        };

        let time_trigger: ITimeTrigger = trigger
            .cast()
            .map_err(|e| com_error("Cast to ITimeTrigger failed", e))?;
        time_trigger
            .SetStartBoundary(&BSTR::from(start_boundary))
            .map_err(|e| com_error("SetStartBoundary failed", e))?;
        let _ = time_trigger.SetEnabled(VARIANT_BOOL(1));

        let user_bstr = BSTR::from("SYSTEM");
        let user = VariantGuard::from_bstr(&user_bstr);
        let password = VARIANT::default();
        let sddl = VARIANT::default();

        folder
            .RegisterTaskDefinition(
                &name,
                &task_def,
                TASK_CREATE_OR_UPDATE.0,
                user.as_ref(),
                &password,
                TASK_LOGON_SERVICE_ACCOUNT,
                &sddl,
            )
            .map_err(|e| com_error("RegisterTaskDefinition failed", e))?;

        Ok(())
    })
}

#[cfg(not(windows))]
fn schedule_task_once_after(_task_name: &str, delay_ms: u32) -> Result<(), DomainError> {
    // 非Windows環境ではスレッドsleepで代替（テスト用）
    std::thread::sleep(Duration::from_millis(delay_ms as u64));
    Ok(())
}

fn run_task_via_com2(task_name: &str) -> Result<(), DomainError> {
    use windows::core::BSTR;
    use windows::Win32::System::Variant::VARIANT;
    with_task_service(|_service, folder| unsafe {
        let name = BSTR::from(task_name);
        let task = folder.GetTask(&name).map_err(|e| com_error("GetTask failed", e))?;
        task.Run(&VARIANT::default())
            .map_err(|e| com_error("Run failed", e))?;
        Ok(())
    })
}

/// 復元専用タスク名
pub const DEFAULT_RESTORE_TASK_NAME: &str = "KaptainhooKRestore";

/// タスクスケジューラアダプター
/// Windows タスクスケジューラで復元専用タスクを管理する。
pub struct TaskSchedulerAdapter {
    task_exe: PathBuf,
}

impl TaskSchedulerAdapter {
    /// 新しいアダプターを作成
    ///
    /// 引数
    /// - task_exe: タスク実行ファイルのパス
    pub fn new(task_exe: impl AsRef<Path>) -> Self {
        Self {
            task_exe: task_exe.as_ref().to_path_buf(),
        }
    }

    /// タスク実行ファイルのパスを取得
    pub fn task_exe(&self) -> &Path {
        &self.task_exe
    }
}

impl TaskScheduler for TaskSchedulerAdapter {
    /// タスクを作成/登録
    ///
    /// COM API でタスクを登録する。
    ///
    /// 設定:
    /// - 過去日時のトリガーで自動実行を抑止
    /// - SYSTEMで最上位特権、オンデマンド実行
    fn create_task(&self, task_name: &str, exe_path: &str) -> Result<(), DomainError> {
        #[cfg(windows)]
        {
            create_task_via_com(task_name, exe_path)?;
            Ok(())
        }

        #[cfg(not(windows))]
        {
            let _ = (task_name, exe_path);
            // 非Windowsでは何もしない（テスト用）
            Ok(())
        }
    }

    /// タスクを削除
    fn delete_task(&self, task_name: &str) -> Result<(), DomainError> {
        #[cfg(windows)]
        {
            delete_task_via_com(task_name)
        }

        #[cfg(not(windows))]
        {
            let _ = task_name;
            Ok(())
        }
    }

    /// タスクが存在するか確認
    fn task_exists(&self, task_name: &str) -> Result<bool, DomainError> {
        #[cfg(windows)]
        {
            task_exists_via_com(task_name)
        }

        #[cfg(not(windows))]
        {
            let _ = task_name;
            Ok(false)
        }
    }

    /// タスクを実行（UAC不要で昇格実行）
    ///
    /// COM API でタスクを即時実行（非同期）。
    fn run_task(&self, task_name: &str) -> Result<(), DomainError> {
        #[cfg(windows)]
        {
            run_task_via_com2(task_name)
        }

        #[cfg(not(windows))]
        {
            // 非Windows環境では直接実行（テスト用）
            let _ = task_name;
            let status = Command::new(&self.task_exe)
                .status()
                .map_err(|e| DomainError::ProcessLaunchFailed(e.to_string()))?;

            if status.success() {
                Ok(())
            } else {
                Err(DomainError::ProcessLaunchFailed(format!(
                    "Task exited with code {}",
                    status.code().unwrap_or(-1)
                )))
            }
        }
    }
}

/// 復元専用タスク実行アダプター
pub struct RestoreTaskRunner {
    task_name: String,
}

impl Default for RestoreTaskRunner {
    fn default() -> Self {
        Self {
            task_name: DEFAULT_RESTORE_TASK_NAME.into(),
        }
    }
}

impl RestoreTaskRunner {
    pub fn new(task_name: impl Into<String>) -> Self {
        Self {
            task_name: task_name.into(),
        }
    }

    pub fn task_name(&self) -> &str {
        &self.task_name
    }
}

impl RestoreKicker for RestoreTaskRunner {
    fn kick_restore_after(&self, delay_ms: u32) -> Result<(), DomainError> {
        if delay_ms == 0 {
            return run_task_via_com(&self.task_name);
        }

        // 先にタスク存在を確認し、同期的にエラーを返せるようにする
        if !task_exists_via_com(&self.task_name)? {
            return Err(DomainError::ProcessLaunchFailed(format!(
                "restore task not found: {}",
                self.task_name
            )));
        }

        #[cfg(windows)]
        {
            schedule_task_once_after(&self.task_name, delay_ms)?;
            return Ok(());
        }

        #[cfg(not(windows))]
        {
            let task_name = self.task_name.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(delay_ms as u64));
                let _ = run_task_via_com(&task_name);
            });
            Ok(())
        }
    }
}

#[cfg(windows)]
fn run_task_via_com(task_name: &str) -> Result<(), DomainError> {
    use windows::core::BSTR;
    use windows::Win32::System::Variant::VARIANT;
    use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, S_FALSE, S_OK};
    use windows::Win32::System::Com::{
        COINIT_MULTITHREADED, CLSCTX_INPROC_SERVER, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler as TASKSERVICE_CLSID};

    unsafe {
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        let did_init = if hr == S_OK || hr == S_FALSE {
            true
        } else if hr == RPC_E_CHANGED_MODE {
            false
        } else {
            return Err(DomainError::ProcessLaunchFailed(format!(
                "COM init failed: 0x{:08x}",
                hr.0 as u32
            )));
        };

        struct CoUninit(bool);
        impl Drop for CoUninit {
            fn drop(&mut self) {
                if self.0 {
                    unsafe { CoUninitialize() }
                }
            }
        }
        let _guard = CoUninit(did_init);

        let service: ITaskService =
            CoCreateInstance(&TASKSERVICE_CLSID, None, CLSCTX_INPROC_SERVER).map_err(|e| {
                DomainError::ProcessLaunchFailed(format!(
                    "CoCreateInstance(TaskScheduler) failed: {e}"
                ))
            })?;
        service
            .Connect(&VARIANT::default(), &VARIANT::default(), &VARIANT::default(), &VARIANT::default())
            .map_err(|e| DomainError::ProcessLaunchFailed(format!("ITaskService::Connect failed: {e}")))?;

        let root = BSTR::from("\\");
        let folder = service
            .GetFolder(&root)
            .map_err(|e| DomainError::ProcessLaunchFailed(format!("GetFolder(\\\\) failed: {e}")))?;
        let name = BSTR::from(task_name);
        let task = folder
            .GetTask(&name)
            .map_err(|e| DomainError::ProcessLaunchFailed(format!("GetTask({task_name}) failed: {e}")))?;

        let _ = task
            .Run(&VARIANT::default())
            .map_err(|e| DomainError::ProcessLaunchFailed(format!("Run({task_name}) failed: {e}")))?;

        Ok(())
    }
}

#[cfg(not(windows))]
fn run_task_via_com(_task_name: &str) -> Result<(), DomainError> {
    Ok(())
}

/// タスクの詳細情報を取得（デバッグ/診断用）
#[cfg(windows)]
pub fn query_task_details(task_name: &str) -> Result<TaskInfo, DomainError> {
    use windows::core::BSTR;
    use windows::Win32::System::TaskScheduler::{
        TASK_RUNLEVEL_HIGHEST, TASK_RUNLEVEL_LUA, TASK_STATE_DISABLED, TASK_STATE_QUEUED,
        TASK_STATE_READY, TASK_STATE_RUNNING, TASK_STATE_UNKNOWN,
    };

    with_task_service(|_service, folder| unsafe {
        let name = BSTR::from(task_name);
        let task = folder.GetTask(&name).map_err(|e| com_error("GetTask failed", e))?;
        let state = task.State().map_err(|e| com_error("State failed", e))?;
        let status = match state {
            TASK_STATE_DISABLED => "Disabled",
            TASK_STATE_READY => "Ready",
            TASK_STATE_RUNNING => "Running",
            TASK_STATE_QUEUED => "Queued",
            TASK_STATE_UNKNOWN => "Unknown",
            _ => "Unknown",
        }
        .to_string();

        let def = task.Definition().map_err(|e| com_error("Definition failed", e))?;
        let principal = def.Principal().map_err(|e| com_error("Principal failed", e))?;
        let mut user = BSTR::new();
        let _ = principal.UserId(&mut user);
        let run_as_user = user.to_string();
        let mut run_level_value = TASK_RUNLEVEL_LUA;
        let _ = principal.RunLevel(&mut run_level_value);
        let run_level = match run_level_value {
            TASK_RUNLEVEL_HIGHEST => "Highest",
            TASK_RUNLEVEL_LUA => "Least",
            _ => "Unknown",
        }
        .to_string();

        let actions = def.Actions().map_err(|e| com_error("Actions failed", e))?;
        let mut task_to_run = String::new();
        if let Ok(action) = actions.get_Item(1) {
            if let Ok(exec) = action.cast::<windows::Win32::System::TaskScheduler::IExecAction>() {
                let mut path = BSTR::new();
                let _ = exec.Path(&mut path);
                task_to_run = path.to_string();
            }
        }

        let last_run_time = match task.LastRunTime() {
            Ok(v) if v > 0.0 => format!("{v:.4}"),
            _ => "".to_string(),
        };
        let last_result = match task.LastTaskResult() {
            Ok(v) => v.to_string(),
            Err(_) => "".to_string(),
        };

        Ok(TaskInfo {
            task_name: task_name.to_string(),
            status,
            run_level,
            run_as_user,
            last_run_time,
            last_result,
            next_run_time: match task.NextRunTime() {
                Ok(v) if v > 0.0 => format!("{v:.4}"),
                _ => "".to_string(),
            },
            task_to_run,
        })
    })
}

/// タスク情報（診断用）
#[derive(Debug, Clone, Default)]
pub struct TaskInfo {
    pub task_name: String,
    pub status: String,
    pub run_level: String,
    pub run_as_user: String,
    pub last_run_time: String,
    pub last_result: String,
    pub next_run_time: String,
    pub task_to_run: String,
}

#[cfg(test)]
impl TaskInfo {
    /// schtasks /Query /V /FO LIST の出力をパース
    fn parse(output: &str) -> Self {
        let mut info = TaskInfo::default();

        for line in output.lines() {
            let line = line.trim();
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim();
                let value = value.trim();

                match key {
                    "TaskName" | "タスク名" => info.task_name = value.to_string(),
                    "Status" | "状態" => info.status = value.to_string(),
                    "Run As User" | "実行するユーザー" => info.run_as_user = value.to_string(),
                    "Logon Mode" | "ログオン モード" => info.run_level = value.to_string(),
                    "Last Run Time" | "前回の実行時刻" => info.last_run_time = value.to_string(),
                    "Last Result" | "前回の結果" => info.last_result = value.to_string(),
                    "Next Run Time" | "次回の実行時刻" => info.next_run_time = value.to_string(),
                    "Task To Run" | "タスクの実行" => info.task_to_run = value.to_string(),
                    _ => {}
                }
            }
        }

        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_creation() {
        let adapter = TaskSchedulerAdapter::new("/path/to/restore.exe");
        assert_eq!(adapter.task_exe().to_str().unwrap(), "/path/to/restore.exe");
    }

    #[test]
    fn task_info_parse() {
        let output = r#"
TaskName:                             \KaptainhooKRestore
Status:                               Ready
Run As User:                          SYSTEM
Task To Run:                          "C:\Program Files\KaptainhooK\kh-restore.exe"
Last Run Time:                        2025-01-15 10:30:00
Last Result:                          0
"#;
        let info = TaskInfo::parse(output);
        assert!(info.task_name.contains("KaptainhooKRestore"));
        assert_eq!(info.status, "Ready");
        assert_eq!(info.run_as_user, "SYSTEM");
        assert!(info.task_to_run.contains("kh-restore.exe"));
    }

    #[cfg(not(windows))]
    mod non_windows {
        use super::*;

        #[test]
        fn create_task_noop_on_non_windows() {
            let adapter = TaskSchedulerAdapter::new("/path/to/restore");
            assert!(adapter.create_task("TestTask", "/path/to/exe").is_ok());
        }

        #[test]
        fn delete_task_noop_on_non_windows() {
            let adapter = TaskSchedulerAdapter::new("/path/to/restore");
            assert!(adapter.delete_task("TestTask").is_ok());
        }

        #[test]
        fn task_exists_false_on_non_windows() {
            let adapter = TaskSchedulerAdapter::new("/path/to/restore");
            assert!(!adapter.task_exists("TestTask").unwrap());
        }
    }
}
