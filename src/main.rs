mod config;
mod ipc;
mod crypto;
mod scanner;
mod daemon;
mod cli;
mod attachment;
mod secret_store;

/// Hard safety boundary for this fork. Keep this true in public builds.
pub(crate) const SAFE_READONLY: bool = true;

fn main() {
    if std::env::var("WX_DAEMON_MODE").is_ok() {
        daemon::run();
    } else {
        cli::run();
    }
}
