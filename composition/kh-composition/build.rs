use std::env;

fn main() {
    if cfg!(target_os = "windows") {
        return;
    }
    if is_wsl() {
        panic!("WSL is not supported for building KaptainhooK. Please build on Windows.");
    }
}

fn is_wsl() -> bool {
    if env::var_os("WSL_DISTRO_NAME").is_some() {
        return true;
    }
    if env::var_os("WSL_INTEROP").is_some() {
        return true;
    }
    if env::var_os("WSLENV").is_some() {
        return true;
    }
    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let lower = release.to_lowercase();
        if lower.contains("microsoft") || lower.contains("wsl") {
            return true;
        }
    }
    false
}
