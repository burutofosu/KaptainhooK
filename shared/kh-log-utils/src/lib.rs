//! ログユーティリティ（stdのみ）

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// UTCのRFC3339（ミリ秒付き）。例: 2025-01-15T10:30:00.123Z
pub fn utc_rfc3339_millis() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let (year, month, day, hour, minute, second) = unix_seconds_to_utc_components(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, minute, second, millis
    )
}

/// UTCタイムスタンプ付きのライフサイクル行を作成する。
pub fn lifecycle_line(component: &str, message: &str) -> String {
    let timestamp = utc_rfc3339_millis();
    format!("[{}] [{}] {}\n", timestamp, component, message)
}

/// ライフサイクルログの既定出力先
pub fn default_lifecycle_log_paths() -> Vec<PathBuf> {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let base = PathBuf::from(base).join("KaptainhooK");
    vec![
        base.join("final").join("logs").join("kh-lifecycle.log"),
        base.join("bin").join("kh-lifecycle.log"),
        std::env::temp_dir().join("kh-lifecycle.log"),
    ]
}

/// 指定された出力先のうち、書き込み可能な最初の場所にログを書き込む
pub fn write_line_to_paths(line: &str, paths: &[PathBuf]) {
    for path in paths {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
            return;
        }
    }
}

/// 既定の出力先に1行書き込む
pub fn write_line_to_default_paths(line: &str) {
    let paths = default_lifecycle_log_paths();
    write_line_to_paths(line, &paths);
}

/// 既定の出力先にライフサイクル行を書き込む
pub fn write_lifecycle_line(component: &str, message: &str) {
    let line = lifecycle_line(component, message);
    write_line_to_default_paths(&line);
}

fn unix_seconds_to_utc_components(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let hour = (rem / 3_600) as u32;
    let minute = ((rem % 3_600) / 60) as u32;
    let second = (rem % 60) as u32;
    let (year, month, day) = civil_from_days(days);
    (year, month, day, hour, minute, second)
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    // Howard Hinnant のアルゴリズム
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = mp + if mp < 10 { 3 } else { -9 }; // [1, 12]
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}
