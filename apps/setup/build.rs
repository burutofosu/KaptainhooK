//! kh-setup 用ビルドスクリプト。
//!
//! Windows アプリケーションのマニフェストとアイコンを埋め込む。

fn main() {
    #[cfg(windows)]
    {
        let _ = embed_resource::compile("resources.rc", embed_resource::NONE);
    }
}
