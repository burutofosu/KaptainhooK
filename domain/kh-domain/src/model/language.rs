//! 言語設定
//!
//! UIの表示言語を制御する。

use std::fmt;

/// サポートする言語
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Language {
    /// 日本語
    #[default]
    Japanese,
    /// 英語
    English,
}

impl Language {
    /// 言語コードから変換
    pub fn from_code(code: &str) -> Self {
        match code.to_lowercase().as_str() {
            "en" | "english" => Language::English,
            "ja" | "jp" | "japanese" => Language::Japanese,
            _ => Language::default(),
        }
    }

    /// 言語コードに変換
    pub fn to_code(&self) -> &'static str {
        match self {
            Language::Japanese => "ja",
            Language::English => "en",
        }
    }

    /// 表示名を取得
    pub fn display_name(&self) -> &'static str {
        match self {
            Language::Japanese => "日本語",
            Language::English => "English",
        }
    }

    /// 全言語リストを取得
    pub fn all() -> &'static [Language] {
        &[Language::Japanese, Language::English]
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_code() {
        assert_eq!(Language::from_code("ja"), Language::Japanese);
        assert_eq!(Language::from_code("JP"), Language::Japanese);
        assert_eq!(Language::from_code("en"), Language::English);
        assert_eq!(Language::from_code("English"), Language::English);
        assert_eq!(Language::from_code("unknown"), Language::Japanese); // 既定
    }

    #[test]
    fn test_to_code() {
        assert_eq!(Language::Japanese.to_code(), "ja");
        assert_eq!(Language::English.to_code(), "en");
    }
}
