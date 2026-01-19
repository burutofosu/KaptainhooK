use crate::{
    DomainError,
    model::{GuardConfig, Target},
    port::driven::RegistryPort,
};

pub mod ownership_service;
pub mod reaction_service;
pub mod threat_service;

// 便宜のため所有者サービスの関数を再エクスポート
pub use ownership_service::{UnregisterDecision, decide_unregister, is_owned_debugger};
pub use reaction_service::{ReactionAction, ReactionDecision, classify_origin, evaluate_reaction};

pub type Result<T> = std::result::Result<T, DomainError>;

/// ガード設定をレジストリへ適用する薄いサービス層。
pub struct GuardService<R: RegistryPort> {
    registry: R,
}

impl<R: RegistryPort> GuardService<R> {
    pub fn new(registry: R) -> Self {
        Self { registry }
    }

    /// 有効なターゲットだけ登録し、無効なものは解除する。
    pub fn apply(&self, cfg: &GuardConfig) -> Result<()> {
        cfg.validate()?;
        for target in &cfg.targets {
            self.apply_target(target)?;
        }
        Ok(())
    }

    fn apply_target(&self, target: &Target) -> Result<()> {
        if target.enabled() {
            self.registry.register(target)
        } else {
            self.registry.unregister(target)
        }
    }
}
