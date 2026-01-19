//! アンインストール/復元のユースケース。

use kh_domain::DomainError;

#[derive(Clone, Debug)]
pub struct RestoreReportItem {
    pub target: String,
    pub view: String,
    pub outcome: String,
    pub detail: String,
    pub read_back_ok: Option<bool>,
}

#[derive(Clone, Debug, Default)]
pub struct RestoreReport {
    pub processed: u32,
    pub items: Vec<RestoreReportItem>,
    pub errors: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub enum ForeignPolicy {
    Skip,
    Force,
    Error,
    Prompt(fn(&str, &str, &str) -> bool),
}

#[derive(Clone, Debug)]
pub struct RestoreOptions {
    pub expected_debugger_path: String,
    pub foreign_policy: ForeignPolicy,
    pub logger: Option<fn(&str)>,
}

pub trait UninstallPort {
    fn restore_ifeo_from_uninstall_state(
        &self,
        options: &RestoreOptions,
    ) -> Result<RestoreReport, DomainError>;
}

pub struct UninstallDeps<'a> {
    pub port: &'a dyn UninstallPort,
}

pub struct UninstallService<'a> {
    deps: UninstallDeps<'a>,
}

impl<'a> UninstallService<'a> {
    pub fn new(deps: UninstallDeps<'a>) -> Self {
        Self { deps }
    }

    pub fn restore_ifeo_from_uninstall_state(
        &self,
        options: &RestoreOptions,
    ) -> Result<RestoreReport, DomainError> {
        self.deps.port.restore_ifeo_from_uninstall_state(options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct StubPort {
        called: Mutex<bool>,
        result: RestoreReport,
    }

    impl UninstallPort for StubPort {
        fn restore_ifeo_from_uninstall_state(
            &self,
            _options: &RestoreOptions,
        ) -> Result<RestoreReport, DomainError> {
            let mut guard = self.called.lock().unwrap();
            *guard = true;
            Ok(self.result.clone())
        }
    }

    #[test]
    fn uninstall_service_delegates_to_port() {
        let port = StubPort {
            called: Mutex::new(false),
            result: RestoreReport {
                processed: 1,
                ..RestoreReport::default()
            },
        };
        let service = UninstallService::new(UninstallDeps { port: &port });
        let options = RestoreOptions {
            expected_debugger_path: "C:\\dummy.exe".into(),
            foreign_policy: ForeignPolicy::Skip,
            logger: None,
        };
        let report = service.restore_ifeo_from_uninstall_state(&options).unwrap();
        assert_eq!(report.processed, 1);
        assert_eq!(*port.called.lock().unwrap(), true);
    }
}
