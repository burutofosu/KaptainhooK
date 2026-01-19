//! 時刻・入力トラッキングアダプター
use kh_domain::error::DomainError;
use kh_domain::port::driven::{Clock, KeyboardTracker, MouseTracker, RandomSource};

#[cfg(windows)]
use windows::Win32::Foundation::POINT;
#[cfg(windows)]
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, VK_CONTROL, VK_ESCAPE, VK_MENU, VK_SHIFT, VIRTUAL_KEY,
};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;

#[derive(Debug, Default)]
pub struct ClockAdapter;

impl ClockAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Clock for ClockAdapter {
    fn now_ms(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        now.as_millis() as u64
    }

    fn now_iso8601(&self) -> String {
        utc_rfc3339_now()
    }
}

impl MouseTracker for ClockAdapter {
    fn position(&self) -> (i32, i32) {
        #[cfg(windows)]
        {
            let mut pt = POINT::default();
            let ok = unsafe { GetCursorPos(&mut pt).is_ok() };
            if ok {
                (pt.x, pt.y)
            } else {
                (0, 0)
            }
        }
        #[cfg(not(windows))]
        {
            (0, 0)
        }
    }
}

impl KeyboardTracker for ClockAdapter {
    fn is_emergency_combo_held(&self) -> bool {
        #[cfg(windows)]
        {
            fn key_down(vk: VIRTUAL_KEY) -> bool {
                unsafe { (GetAsyncKeyState(vk.0 as i32) as u16 & 0x8000) != 0 }
            }

            key_down(VK_CONTROL)
                && key_down(VK_SHIFT)
                && key_down(VK_MENU)
                && key_down(VK_ESCAPE)
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

impl RandomSource for ClockAdapter {
    fn next_u64(&self) -> Result<u64, DomainError> {
        #[cfg(windows)]
        {
            use windows::Win32::Security::Cryptography::{
                BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            };
            let mut bytes = [0u8; 8];
            let status = unsafe {
                BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
            };
            if status.is_ok() {
                Ok(u64::from_ne_bytes(bytes))
            } else {
                Err(DomainError::IoError(format!(
                    "BCryptGenRandom failed: 0x{:08x}",
                    status.0 as u32
                )))
            }
        }
        #[cfg(not(windows))]
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let mut v = nanos as u64;
            // xorshift64* を使用
            v ^= v >> 12;
            v ^= v << 25;
            v ^= v >> 27;
            Ok(v.wrapping_mul(0x2545F4914F6CDD1D))
        }
    }
}

fn utc_rfc3339_now() -> String {
    #[cfg(windows)]
    {
        use windows::Win32::System::SystemInformation::GetSystemTime;
        let st = unsafe { GetSystemTime() };
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds
        )
    }
    #[cfg(not(windows))]
    {
        use std::time::{SystemTime, UNIX_EPOCH};
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
}

#[cfg(not(windows))]
fn unix_seconds_to_utc_components(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let hour = (rem / 3_600) as u32;
    let minute = ((rem % 3_600) / 60) as u32;
    let second = (rem % 60) as u32;
    let (year, month, day) = civil_from_days(days);
    (year, month, day, hour, minute, second)
}

#[cfg(not(windows))]
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    // Howard Hinnantの変換アルゴリズム
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
