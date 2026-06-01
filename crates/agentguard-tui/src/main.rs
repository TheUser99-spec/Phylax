//! Phylax TUI — thin binary entry point (crate name agentguard-tui retained for compat).
//! Delegates to the library `agentguard_tui::run_tui()`.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    agentguard_tui::run_tui().await
}
