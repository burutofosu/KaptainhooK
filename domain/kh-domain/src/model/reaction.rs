use crate::DomainError;
use super::{Target, normalize_exe_name};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactionKind {
    Log,
    Notify,
    Friction,
}

impl ReactionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReactionKind::Log => "log",
            ReactionKind::Notify => "notify",
            ReactionKind::Friction => "friction",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "notify" => ReactionKind::Notify,
            "friction" => ReactionKind::Friction,
            _ => ReactionKind::Log,
        }
    }

    pub fn priority(&self) -> u8 {
        match self {
            ReactionKind::Log => 0,
            ReactionKind::Notify => 1,
            ReactionKind::Friction => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OriginCategory {
    Mail,
    Macro,
    Relay,
}

impl OriginCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            OriginCategory::Mail => "mail",
            OriginCategory::Macro => "macro",
            OriginCategory::Relay => "relay",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForcedCategory {
    None,
    Always,
    Logging,
}

impl ForcedCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ForcedCategory::None => "none",
            ForcedCategory::Always => "always",
            ForcedCategory::Logging => "logging",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "always" => ForcedCategory::Always,
            "logging" => ForcedCategory::Logging,
            _ => ForcedCategory::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactionPreset {
    AllLog,
    Strong,
    Medium,
    Weak,
}

impl ReactionPreset {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReactionPreset::AllLog => "all_log",
            ReactionPreset::Strong => "strong",
            ReactionPreset::Medium => "medium",
            ReactionPreset::Weak => "weak",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "strong" => ReactionPreset::Strong,
            "medium" => ReactionPreset::Medium,
            "weak" => ReactionPreset::Weak,
            "all_log" => ReactionPreset::AllLog,
            _ => ReactionPreset::AllLog,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReactionRule {
    pub mail: ReactionKind,
    pub macro_: ReactionKind,
    pub relay: ReactionKind,
    pub always: ReactionKind,
}

impl ReactionRule {
    pub fn all_log() -> Self {
        Self {
            mail: ReactionKind::Log,
            macro_: ReactionKind::Log,
            relay: ReactionKind::Log,
            always: ReactionKind::Log,
        }
    }

    pub fn from_preset(preset: ReactionPreset) -> Self {
        match preset {
            ReactionPreset::AllLog => Self::all_log(),
            ReactionPreset::Strong => Self {
                mail: ReactionKind::Friction,
                macro_: ReactionKind::Friction,
                relay: ReactionKind::Friction,
                always: ReactionKind::Friction,
            },
            ReactionPreset::Medium => Self {
                mail: ReactionKind::Friction,
                macro_: ReactionKind::Friction,
                relay: ReactionKind::Notify,
                always: ReactionKind::Friction,
            },
            ReactionPreset::Weak => Self {
                mail: ReactionKind::Notify,
                macro_: ReactionKind::Notify,
                relay: ReactionKind::Log,
                always: ReactionKind::Notify,
            },
        }
    }

    pub fn reaction_for_category(&self, category: OriginCategory) -> ReactionKind {
        match category {
            OriginCategory::Mail => self.mail,
            OriginCategory::Macro => self.macro_,
            OriginCategory::Relay => self.relay,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetReaction {
    pub target: String,
    pub forced: ForcedCategory,
    pub rule: ReactionRule,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionConfig {
    pub preset: ReactionPreset,
    pub default_rule: ReactionRule,
    pub overrides: Vec<TargetReaction>,
}

impl Default for ReactionConfig {
    fn default() -> Self {
        let preset = ReactionPreset::AllLog;
        Self {
            preset,
            default_rule: ReactionRule::from_preset(preset),
            overrides: Vec::new(),
        }
    }
}

impl ReactionConfig {
    pub fn validate(&self) -> Result<(), DomainError> {
        for item in &self.overrides {
            Target::validate_name(&item.target)?;
        }
        Ok(())
    }

    pub fn normalize(&mut self) {
        let mut map: BTreeMap<String, TargetReaction> = BTreeMap::new();
        for item in self.overrides.drain(..) {
            // targets と同じ正規化規則に寄せる（引用符/パス入力を許容し、exe名へ縮退）
            let normalized = normalize_exe_name(item.target);
            if Target::validate_name(&normalized).is_err() {
                continue;
            }
            map.insert(
                normalized.clone(),
                TargetReaction {
                    target: normalized,
                    forced: item.forced,
                    rule: item.rule,
                },
            );
        }
        self.overrides = map.into_values().collect();
    }

    pub fn resolve_for_target(&self, normalized_target: &str) -> (ForcedCategory, ReactionRule) {
        let key = normalized_target.to_ascii_lowercase();
        if let Some(item) = self.overrides.iter().find(|o| o.target == key) {
            return (item.forced, item.rule);
        }
        (ForcedCategory::None, self.default_rule)
    }

    pub fn matched_categories_as_strings(categories: &BTreeSet<OriginCategory>) -> Vec<String> {
        categories.iter().map(|c| c.as_str().to_string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reaction_config_normalize_accepts_path_and_quotes_and_dedups() {
        let mut cfg = ReactionConfig {
            preset: ReactionPreset::AllLog,
            default_rule: ReactionRule::all_log(),
            overrides: vec![
                TargetReaction {
                    target: "\"C:\\Windows\\System32\\cmd.exe\"".into(),
                    forced: ForcedCategory::None,
                    rule: ReactionRule::all_log(),
                },
                // 同じ exe を別表記で上書き
                TargetReaction {
                    target: "cmd.exe".into(),
                    forced: ForcedCategory::Always,
                    rule: ReactionRule::from_preset(ReactionPreset::Medium),
                },
            ],
        };

        cfg.normalize();
        assert_eq!(cfg.overrides.len(), 1);
        assert_eq!(cfg.overrides[0].target, "cmd.exe");
        assert_eq!(cfg.overrides[0].forced, ForcedCategory::Always);
    }
}
