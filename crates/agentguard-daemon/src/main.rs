//! Phylax Daemon — thin binary entry point (crate name agentguard-daemon retained for compat).
//! Delegates to the library `agentguard_daemon::run_daemon()`.

#[tokio::main]
async fn main() {
    agentguard_daemon::run_daemon().await;
}
