//! 反応/通知の判定（純関数）。

use crate::model::{
    ForcedCategory, GuardRequest, OriginCategory, ReactionConfig, ReactionKind, exit_codes,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactionAction {
    Allow,
    Notify,
    Prompt,
    Block { exit_code: u8 },
}

#[derive(Debug, Clone)]
pub struct ReactionDecision {
    pub reaction: ReactionKind,
    pub categories: BTreeSet<OriginCategory>,
    pub forced: ForcedCategory,
    pub action: ReactionAction,
}

/// 起動元のカテゴリ判定（ヒューリスティック）
pub fn classify_origin(req: &GuardRequest) -> BTreeSet<OriginCategory> {
    let mut categories = BTreeSet::new();

    const MAIL_EXES: &[&str] = &["outlook.exe", "thunderbird.exe", "olk.exe"];
    const MACRO_EXES: &[&str] = &["winword.exe", "excel.exe", "powerpnt.exe", "visio.exe"];
    const RELAY_EXES: &[&str] = &[
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "wmic.exe",
        "installutil.exe",
        "msdt.exe",
        "powershell_ise.exe",
        "wt.exe",
        "msiexec.exe",
        "schtasks.exe",
    ];

    if matches_any_exe(&req.parent.name, MAIL_EXES)
        || matches_any_exe(&req.grandparent.name, MAIL_EXES)
    {
        categories.insert(OriginCategory::Mail);
    }
    if matches_any_exe(&req.parent.name, MACRO_EXES)
        || matches_any_exe(&req.grandparent.name, MACRO_EXES)
    {
        categories.insert(OriginCategory::Macro);
    }
    if matches_any_exe(&req.parent.name, RELAY_EXES)
        || matches_any_exe(&req.grandparent.name, RELAY_EXES)
    {
        categories.insert(OriginCategory::Relay);
    }
    if matches_target(req.target.as_str(), RELAY_EXES) {
        categories.insert(OriginCategory::Relay);
    }

    let mut candidates: Vec<&str> = Vec::new();
    candidates.push(req.target.as_str());
    for arg in &req.args {
        candidates.push(arg.as_str());
    }
    if let Some(path) = &req.parent.path {
        candidates.push(path.as_str());
    }
    if let Some(path) = &req.grandparent.path {
        candidates.push(path.as_str());
    }

    if candidates.iter().any(|value| contains_mail_pattern(value)) {
        categories.insert(OriginCategory::Mail);
    }
    if candidates.iter().any(|value| has_macro_extension(value)) {
        categories.insert(OriginCategory::Macro);
    }

    categories
}

/// 反応判定を行い、実行アクション（許可/通知/確認/ブロック）を返す。
pub fn evaluate_reaction(
    req: &GuardRequest,
    config: &ReactionConfig,
    is_protected: bool,
    is_interactive: bool,
    allow_non_interactive: bool,
) -> ReactionDecision {
    let (forced, rule) = config.resolve_for_target(&req.normalized_target);

    if !is_protected {
        return ReactionDecision {
            reaction: ReactionKind::Log,
            categories: BTreeSet::new(),
            forced,
            action: ReactionAction::Allow,
        };
    }

    let mut categories = BTreeSet::new();
    let reaction = match forced {
        ForcedCategory::Always => rule.always,
        ForcedCategory::Logging => ReactionKind::Log,
        ForcedCategory::None => {
            categories = classify_origin(req);
            if categories.is_empty() {
                ReactionKind::Log
            } else {
                categories
                    .iter()
                    .map(|category| rule.reaction_for_category(*category))
                    .max_by_key(|reaction| reaction.priority())
                    .unwrap_or(ReactionKind::Log)
            }
        }
    };

    let action = if !is_interactive && !allow_non_interactive {
        ReactionAction::Block {
            exit_code: exit_codes::POLICY_BLOCKED,
        }
    } else {
        match reaction {
            ReactionKind::Friction => {
                if !is_interactive {
                    ReactionAction::Allow
                } else {
                    ReactionAction::Prompt
                }
            }
            ReactionKind::Notify => ReactionAction::Notify,
            ReactionKind::Log => ReactionAction::Allow,
        }
    };

    ReactionDecision {
        reaction,
        categories,
        forced,
        action,
    }
}

fn contains_mail_pattern(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("\\content.outlook\\")
        || lower.contains("\\inetcache\\")
        || lower.contains("mailto:")
}

fn has_macro_extension(value: &str) -> bool {
    const MACRO_EXTS: &[&str] = &[".docm", ".xlsm", ".pptm", ".dotm"];
    let lower = value
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase();
    MACRO_EXTS.iter().any(|ext| lower.ends_with(ext))
}

fn matches_any_exe(value: &Option<String>, list: &[&str]) -> bool {
    let name = match value {
        Some(name) => crate::model::normalize_exe_name(name.as_str()),
        None => return false,
    };
    list.iter().any(|exe| name == *exe)
}

fn matches_target(value: &str, list: &[&str]) -> bool {
    let name = crate::model::normalize_exe_name(value);
    list.iter().any(|exe| name == *exe)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProcessInfo, ReactionPreset, ReactionRule, SessionInfo};

    fn base_request() -> GuardRequest {
        GuardRequest {
            target: "powershell.exe".to_string(),
            args: Vec::new(),
            normalized_target: "powershell.exe".to_string(),
            session: SessionInfo::default(),
            parent: ProcessInfo::default(),
            grandparent: ProcessInfo::default(),
        }
    }

    #[test]
    fn classify_mail_from_parent_name() {
        let mut req = base_request();
        req.parent.name = Some("Outlook.EXE".to_string());
        let categories = classify_origin(&req);
        assert!(categories.contains(&OriginCategory::Mail));
    }

    #[test]
    fn classify_mail_from_path_hint() {
        let mut req = base_request();
        req.args = vec!["C:\\Users\\a\\AppData\\Local\\Microsoft\\Windows\\INetCache\\x".into()];
        let categories = classify_origin(&req);
        assert!(categories.contains(&OriginCategory::Mail));
    }

    #[test]
    fn classify_macro_from_parent_name() {
        let mut req = base_request();
        req.grandparent.name = Some("winword.exe".into());
        let categories = classify_origin(&req);
        assert!(categories.contains(&OriginCategory::Macro));
    }

    #[test]
    fn classify_macro_from_extension() {
        let mut req = base_request();
        req.args = vec!["C:\\temp\\macro.docm".into()];
        let categories = classify_origin(&req);
        assert!(categories.contains(&OriginCategory::Macro));
    }

    #[test]
    fn classify_relay_from_grandparent() {
        let mut req = base_request();
        req.grandparent.name = Some("CMD.EXE".into());
        let categories = classify_origin(&req);
        assert!(categories.contains(&OriginCategory::Relay));
    }

    #[test]
    fn evaluate_forced_always() {
        let req = base_request();
        let cfg = ReactionConfig {
            preset: ReactionPreset::Strong,
            default_rule: ReactionRule::from_preset(ReactionPreset::Strong),
            overrides: vec![crate::model::TargetReaction {
                target: "powershell.exe".into(),
                forced: ForcedCategory::Always,
                rule: ReactionRule {
                    mail: ReactionKind::Log,
                    macro_: ReactionKind::Notify,
                    relay: ReactionKind::Log,
                    always: ReactionKind::Friction,
                },
            }],
        };
        let decision = evaluate_reaction(&req, &cfg, true, true, false);
        assert_eq!(decision.reaction, ReactionKind::Friction);
        assert!(decision.categories.is_empty());
        assert!(matches!(decision.action, ReactionAction::Prompt));
    }

    #[test]
    fn evaluate_multi_category_priority() {
        let mut req = base_request();
        req.parent.name = Some("outlook.exe".into());
        req.grandparent.name = Some("cmd.exe".into());
        let cfg = ReactionConfig {
            preset: ReactionPreset::Medium,
            default_rule: ReactionRule::from_preset(ReactionPreset::Medium),
            overrides: Vec::new(),
        };
        let decision = evaluate_reaction(&req, &cfg, true, true, false);
        assert_eq!(decision.reaction, ReactionKind::Friction);
        assert!(decision.categories.contains(&OriginCategory::Mail));
        assert!(decision.categories.contains(&OriginCategory::Relay));
        assert!(matches!(decision.action, ReactionAction::Prompt));
    }

    #[test]
    fn evaluate_non_interactive_block() {
        let mut req = base_request();
        req.parent.name = Some("outlook.exe".into());
        let cfg = ReactionConfig::default();
        let decision = evaluate_reaction(&req, &cfg, true, false, false);
        assert!(matches!(decision.action, ReactionAction::Block { .. }));

        let mut cfg_strong = ReactionConfig::default();
        cfg_strong.preset = ReactionPreset::Strong;
        cfg_strong.default_rule = ReactionRule::from_preset(ReactionPreset::Strong);
        let decision = evaluate_reaction(&req, &cfg_strong, true, false, false);
        assert!(matches!(decision.action, ReactionAction::Block { .. }));
    }

    #[test]
    fn evaluate_no_categories_defaults_log() {
        let req = base_request();
        let cfg = ReactionConfig::default();
        let decision = evaluate_reaction(&req, &cfg, true, true, false);
        assert_eq!(decision.reaction, ReactionKind::Log);
        assert!(decision.categories.is_empty());
        assert!(matches!(decision.action, ReactionAction::Allow));
    }
}
