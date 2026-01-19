//! KaptainhooKの既定パス解決

use std::path::PathBuf;

#[cfg(windows)]
fn known_folder_path(id: &windows::core::GUID) -> Option<PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    use windows::core::PWSTR;

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

#[cfg(windows)]
fn pwstr_to_string(pwstr: windows::core::PWSTR) -> String {
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

/// 既定の製品ルートディレクトリ
///
/// - Windows: `C:\ProgramData\KaptainhooK`（既知フォルダ）
/// - その他: `./var`（開発/テスト用）
pub fn default_product_root_dir() -> PathBuf {
    #[cfg(windows)]
    {
        use windows::Win32::UI::Shell::FOLDERID_ProgramData;

        known_folder_path(&FOLDERID_ProgramData)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("KaptainhooK")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("./var")
    }
}

/// 既定のデータディレクトリ
///
/// - Windowsの場合: `C:\ProgramData\KaptainhooK\final`
/// - その他: `./var`
pub fn default_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        default_product_root_dir().join("final")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("./var")
    }
}

/// 設定ファイル用ディレクトリ
pub fn default_config_dir() -> PathBuf {
    default_data_dir().join("config")
}

/// ログファイル用ディレクトリ
pub fn default_log_dir() -> PathBuf {
    default_data_dir().join("logs")
}

/// 既定のユーザールートディレクトリ（ガードログ用）
///
/// - Windows: `%LOCALAPPDATA%\KaptainhooK`
/// - その他: `./var-user`
pub fn default_user_root_dir() -> PathBuf {
    #[cfg(windows)]
    {
        use windows::Win32::UI::Shell::FOLDERID_LocalAppData;

        known_folder_path(&FOLDERID_LocalAppData)
            .or_else(|| std::env::var("LOCALAPPDATA").ok().map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(r"C:\Users\Default\AppData\Local"))
            .join("KaptainhooK")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("./var-user")
    }
}

/// 既定のユーザーデータディレクトリ
pub fn default_user_data_dir() -> PathBuf {
    #[cfg(windows)]
    {
        default_user_root_dir().join("final")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("./var-user")
    }
}

/// 既定のユーザーログディレクトリ
pub fn default_user_log_dir() -> PathBuf {
    default_user_data_dir().join("logs")
}


/// バックアップ用ディレクトリ
pub fn default_backup_dir() -> PathBuf {
    default_data_dir().join("backups")
}

/// 設定ファイルの既定パス
pub fn default_config_path() -> PathBuf {
    default_config_dir().join("config.json")
}

/// 推奨binディレクトリ
///
/// - Windowsの場合: `C:\Program Files\KaptainhooK\bin`
pub fn preferred_bin_dir() -> PathBuf {
    #[cfg(windows)]
    {
        use windows::Win32::UI::Shell::FOLDERID_ProgramFiles;

        known_folder_path(&FOLDERID_ProgramFiles)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
            .join("KaptainhooK")
            .join("bin")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("./bin")
    }
}

pub fn default_bin_dir() -> PathBuf {
    preferred_bin_dir()
}

/// IFEOのデバッガ値向け既定ブートストラップパス
pub fn default_bootstrap_path() -> String {
    #[cfg(windows)]
    {
        return default_bin_dir()
            .join("kh-bootstrap.exe")
            .to_string_lossy()
            .to_string();
    }
    #[cfg(not(windows))]
    {
        "kaptainhook_bootstrap.exe".to_string()
    }
}
