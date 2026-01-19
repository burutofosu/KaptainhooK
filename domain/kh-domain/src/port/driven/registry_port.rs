use crate::{DomainError, model::Target};

pub type Result<T> = std::result::Result<T, DomainError>;

/// IFEO レジストリへの書き込みに必要な最小ポート。
pub trait RegistryPort {
    fn register(&self, target: &Target) -> Result<()>;
    fn unregister(&self, target: &Target) -> Result<()>;
}
