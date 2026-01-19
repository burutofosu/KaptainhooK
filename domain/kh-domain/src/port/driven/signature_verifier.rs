//! 署名検証ポート

use crate::model::SignatureStatus;

/// 署名検証ポート
pub trait SignatureVerifier {
    /// ファイル署名を検証
    fn verify(&self, path: &str) -> SignatureStatus;
}
