#![windows_subsystem = "windows"]
//! kh-restore: 復元専用タスクのエントリポイント。

use std::process::ExitCode;
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("kh-restore error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    kh_composition::restore::run_restore()
}
