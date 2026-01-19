//! 署名検証アダプター
//! Windows: WinVerifyTrust で Authenticode 署名を検証
//! 非Windows: 未対応として扱う

use kh_domain::model::SignatureStatus;
use kh_domain::port::driven::SignatureVerifier;

#[derive(Debug, Default)]
pub struct SignatureAdapter;

impl SignatureAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(windows)]
mod win {
    use kh_domain::model::{RevocationStatus, SignatureKind, SignatureStatus, SignatureTrust};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::Cryptography::{
        CERT_FIND_SUBJECT_CERT, CERT_NAME_ISSUER_FLAG, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_CONTENT_TYPE_FLAGS, CERT_QUERY_FORMAT_TYPE_FLAGS,
        CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED, CERT_QUERY_FORMAT_FLAG_BINARY,
        CERT_QUERY_OBJECT_FILE, CertCloseStore, CertFindCertificateInStore,
        CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose, CryptMsgGetParam,
        CryptQueryObject, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, CERT_INFO,
        CERT_QUERY_CONTENT_TYPE, CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_TYPE, HCERTSTORE,
    };
    use windows::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
        WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE, WinVerifyTrust,
    };
    use windows::core::PCWSTR;

    struct CertStoreGuard(HCERTSTORE);
    impl Drop for CertStoreGuard {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                unsafe {
                    let _ = CertCloseStore(Some(self.0), 0);
                }
            }
        }
    }

    struct CryptMsgGuard(*mut core::ffi::c_void);
    impl Drop for CryptMsgGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CryptMsgClose(Some(self.0 as *const _));
                }
            }
        }
    }

    fn get_cert_name_string(cert: *const windows::Win32::Security::Cryptography::CERT_CONTEXT, issuer: bool) -> Option<String> {
        let flags = if issuer { CERT_NAME_ISSUER_FLAG } else { 0 };
        let len = unsafe { CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, None, None) };
        if len <= 1 {
            return None;
        }
        let mut buffer = vec![0u16; len as usize];
        let len = unsafe {
            CertGetNameStringW(
                cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                flags,
                None,
                Some(buffer.as_mut_slice()),
            )
        };
        if len <= 1 {
            return None;
        }
        buffer.truncate((len - 1) as usize);
        Some(String::from_utf16_lossy(&buffer))
    }

    fn extract_subject_issuer(path: &str) -> (Option<String>, Option<String>) {
        let wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut encoding = CERT_QUERY_ENCODING_TYPE(0);
        let mut _content = CERT_QUERY_CONTENT_TYPE(0);
        let mut _format = CERT_QUERY_FORMAT_TYPE(0);
        let mut store = HCERTSTORE::default();
        let mut msg: *mut core::ffi::c_void = std::ptr::null_mut();

        let result = unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                wide.as_ptr() as *const _,
                CERT_QUERY_CONTENT_TYPE_FLAGS(
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED.0
                        | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED.0,
                ),
                CERT_QUERY_FORMAT_TYPE_FLAGS(
                    CERT_QUERY_FORMAT_FLAG_BINARY.0 | CERT_QUERY_FORMAT_FLAG_BASE64_ENCODED.0,
                ),
                0,
                Some(&mut encoding),
                Some(&mut _content),
                Some(&mut _format),
                Some(&mut store),
                Some(&mut msg),
                None,
            )
        };
        if result.is_err() || msg.is_null() || store.0.is_null() {
            return (None, None);
        }

        let _store_guard = CertStoreGuard(store);
        let _msg_guard = CryptMsgGuard(msg);

        let mut signer_info_len = 0u32;
        if unsafe { CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut signer_info_len) }
            .is_err()
            || signer_info_len == 0
        {
            return (None, None);
        }

        let mut buffer = vec![0u8; signer_info_len as usize];
        if unsafe {
            CryptMsgGetParam(
                msg,
                CMSG_SIGNER_INFO_PARAM,
                0,
                Some(buffer.as_mut_ptr() as *mut _),
                &mut signer_info_len,
            )
        }
        .is_err()
        {
            return (None, None);
        }

        let signer_info = unsafe { &*(buffer.as_ptr() as *const CMSG_SIGNER_INFO) };
        let mut cert_info = CERT_INFO::default();
        cert_info.Issuer = signer_info.Issuer;
        cert_info.SerialNumber = signer_info.SerialNumber;

        let cert_ctx = unsafe {
            CertFindCertificateInStore(
                store,
                encoding,
                0,
                CERT_FIND_SUBJECT_CERT,
                Some(&cert_info as *const _ as *const _),
                None,
            )
        };
        if cert_ctx.is_null() {
            return (None, None);
        }

        let subject = get_cert_name_string(cert_ctx, false);
        let issuer = get_cert_name_string(cert_ctx, true);

        unsafe {
            let _ = CertFreeCertificateContext(Some(cert_ctx));
        }

        (subject, issuer)
    }

    pub(super) fn verify_file(path: &str) -> SignatureStatus {
        let wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // WINTRUST_FILE_INFO 構築
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wide.as_ptr()),
            ..Default::default()
        };

        // WINTRUST_DATA 構築
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            dwStateAction: WTD_STATEACTION_VERIFY,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info as *mut _,
            },
            ..Default::default()
        };

        // アクションGUID
        let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // 検証
        let status = unsafe {
            WinVerifyTrust(
                HWND(std::ptr::null_mut()),
                &mut action_guid,
                &mut data as *mut _ as *mut _,
            )
        };

        // 後始末
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = unsafe {
            WinVerifyTrust(
                HWND(std::ptr::null_mut()),
                &mut action_guid,
                &mut data as *mut _ as *mut _,
            )
        };

        let kind = SignatureKind::Authenticode;

        match status as u32 {
            0 => {
                let (subject, issuer) = extract_subject_issuer(path);
                SignatureStatus::Signed {
                    kind,
                    subject,
                    issuer,
                    trust: SignatureTrust::Trusted,
                    revocation: RevocationStatus::Good,
                }
            }
            // 署名なし: TRUST_E_NOSIGNATURE (0x800B0100)
            0x800B0100 => SignatureStatus::Unsigned,
            // 失効: CERT_E_REVOKED (0x800B010C)
            0x800B010C => {
                let (subject, issuer) = extract_subject_issuer(path);
                SignatureStatus::Signed {
                    kind,
                    subject,
                    issuer,
                    trust: SignatureTrust::Untrusted,
                    revocation: RevocationStatus::Revoked,
                }
            }
            // 失効確認失敗: CERT_E_REVOCATION_FAILURE (0x800B010E)
            0x800B010E => {
                let (subject, issuer) = extract_subject_issuer(path);
                SignatureStatus::Signed {
                    kind,
                    subject,
                    issuer,
                    trust: SignatureTrust::Unknown,
                    revocation: RevocationStatus::CheckFailed {
                        reason: "オフライン/到達不可".into(),
                    },
                }
            }
            // 署名不信頼: TRUST_E_SUBJECT_NOT_TRUSTED (0x800B0004)、CERT_E_UNTRUSTEDROOT (0x800B0109)
            0x800B0004 | 0x800B0109 => {
                let (subject, issuer) = extract_subject_issuer(path);
                SignatureStatus::Signed {
                    kind,
                    subject,
                    issuer,
                    trust: SignatureTrust::Untrusted,
                    revocation: RevocationStatus::NotChecked {
                        reason: "signature not trusted".into(),
                    },
                }
            }
            code => SignatureStatus::Error {
                message: format!("WinVerifyTrust failed: 0x{:X}", code),
            },
        }
    }
}

#[cfg(windows)]
impl SignatureVerifier for SignatureAdapter {
    fn verify(&self, path: &str) -> SignatureStatus {
        win::verify_file(path)
    }
}

#[cfg(not(windows))]
impl SignatureVerifier for SignatureAdapter {
    fn verify(&self, _path: &str) -> SignatureStatus {
        SignatureStatus::Unsupported {
            reason: "signature verification not supported on this platform".into(),
        }
    }
}
