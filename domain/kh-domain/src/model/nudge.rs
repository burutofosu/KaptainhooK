use crate::DomainError;

/// メッセージ識別子。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(String);

impl MessageId {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(DomainError::ValidationError(
                "message_id must not be empty".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for MessageId {
    fn default() -> Self {
        MessageId("default-nudge".into())
    }
}

/// カスタムメッセージ。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NudgeMessage {
    message_id: MessageId,
    text: String,
}

impl NudgeMessage {
    pub fn new(id: MessageId, text: impl Into<String>) -> Result<Self, DomainError> {
        let text = text.into();
        if text.trim().is_empty() {
            return Err(DomainError::ValidationError(
                "nudge text must not be empty".into(),
            ));
        }
        if text.chars().count() > 200 {
            return Err(DomainError::ValidationError(
                "nudge text must be <= 200 characters".into(),
            ));
        }
        Ok(Self {
            message_id: id,
            text,
        })
    }

    pub fn message_id(&self) -> &MessageId {
        &self.message_id
    }

    pub fn text(&self) -> &str {
        &self.text
    }
}

impl Default for NudgeMessage {
    fn default() -> Self {
        Self::new(
            MessageId::default(),
            "不明な場合は IT 管理者に連絡してください。",
        )
        .expect("default nudge should be valid")
    }
}

/// 既定のメッセージ一覧を返す。
pub fn default_nudges() -> Vec<NudgeMessage> {
    vec![NudgeMessage::default()]
}
