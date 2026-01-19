//! Windows Hello プロンプト補助

use crate::error::{Result, err};
use crate::dialog::{PromptContext, PromptOutcome};
use kh_ui_common::i18n;

/// Windows Helloの確認プロンプトを表示
#[cfg(target_os = "windows")]
pub fn verify_hello(ctx: &PromptContext) -> Result<PromptOutcome> {
    i18n::set_language(ctx.language);
    use windows::core::HSTRING;
    use windows::Security::Credentials::UI::{
        UserConsentVerifier, UserConsentVerifierAvailability, UserConsentVerificationResult,
    };

    let availability = UserConsentVerifier::CheckAvailabilityAsync()
        .map_err(|e| err(format!("Hello availability check failed: {}", e.message())))?
        .join()
        .map_err(|e| err(format!("Hello availability check failed: {}", e.message())))?;

    if availability != UserConsentVerifierAvailability::Available {
        return Err(err(format!("Windows Hello unavailable: {:?}", availability)));
    }

    let prompt = i18n::t().guard_hello_prompt(&ctx.target);
    let prompt_h = HSTRING::from(prompt);
    let result = UserConsentVerifier::RequestVerificationAsync(&prompt_h)
        .map_err(|e| err(format!("Hello request failed: {}", e.message())))?
        .join()
        .map_err(|e| err(format!("Hello request failed: {}", e.message())))?;

    let (allowed, reason) = match result {
        UserConsentVerificationResult::Verified => (true, "verified by Windows Hello".to_string()),
        UserConsentVerificationResult::DeviceBusy => (false, "Windows Hello device busy".to_string()),
        UserConsentVerificationResult::Canceled => (false, "Windows Hello canceled".to_string()),
        UserConsentVerificationResult::DeviceNotPresent => (false, "Windows Hello device not present".to_string()),
        UserConsentVerificationResult::DisabledByPolicy => (false, "Windows Hello disabled by policy".to_string()),
        UserConsentVerificationResult::NotConfiguredForUser => (false, "Windows Hello not configured".to_string()),
        _ => (false, "Windows Hello verification failed".to_string()),
    };

    Ok(PromptOutcome {
        allowed,
        reason,
        emergency: false,
    })
}

/// 非Windowsのフォールバック
#[cfg(not(target_os = "windows"))]
pub fn verify_hello(_ctx: &PromptContext) -> Result<PromptOutcome> {
    Err(err("Windows Hello is not supported on this platform"))
}
