use crate::DomainError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseState {
    pub target: String,
    pub expires_at_ms: u64,
}

pub trait LeaseStore {
    fn read_lease(&self) -> Result<Option<LeaseState>, DomainError>;
    fn write_lease(&self, state: &LeaseState) -> Result<(), DomainError>;
    fn clear_lease(&self) -> Result<(), DomainError>;
}
