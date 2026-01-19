pub trait TargetPathResolver {
    fn resolve_target_path(&self, target: &str, args: &[String]) -> Option<String>;
}
