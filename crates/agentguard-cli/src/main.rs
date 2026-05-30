#![allow(unsafe_code)]

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod cmd;

#[derive(Parser)]
#[command(
    name = "agentguard",
    about = "OS-level file safety for AI coding agents",
    version = env!("CARGO_PKG_VERSION"),
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize AgentGuard: creates agentguard.toml, starts daemon, registers project
    Init {
        #[arg(long)]
        no_create: bool,
        /// Continue even if deny enforcement audit is unhealthy (insecure)
        #[arg(long, default_value_t = false)]
        allow_unhealthy: bool,
    },
    /// Show daemon status and watched projects
    Status,
    /// Stop the daemon (shortcut for `agentguard daemon stop`)
    Stop,
    /// Project commands
    Project {
        #[command(subcommand)]
        cmd: ProjectCommands,
    },
    /// Daemon commands
    Daemon {
        #[command(subcommand)]
        cmd: DaemonCommands,
    },
    /// Global rules (apply to all projects)
    Global {
        #[command(subcommand)]
        cmd: GlobalCommands,
    },
    /// View audit log history
    Audit {
        #[command(subcommand)]
        cmd: AuditCommands,
    },
    /// Per-agent rules (cursor.exe, claude.exe, etc.)
    Agent {
        #[command(subcommand)]
        cmd: AgentCommands,
    },
    /// Open the TUI dashboard (daemon must be running)
    Ui,
    /// Start daemon + TUI together
    Run,
    /// Check for and install updates from GitHub
    Update {
        /// Only check, don't install
        #[arg(long)]
        check: bool,
    },
}

#[derive(Subcommand)]
pub enum ProjectCommands {
    /// Validate the agentguard.toml in the current directory
    Validate {
        #[arg(long, short, default_value = ".")]
        path: PathBuf,
    },
    /// Dry-run: what decision would apply to a file?
    Check {
        #[arg(long, short)]
        file: PathBuf,
        #[arg(long, short, value_parser = ["read", "write", "delete"])]
        op: String,
    },
    /// Remove project from daemon watch
    Unregister {
        #[arg(long, short, default_value = ".")]
        path: PathBuf,
    },
    /// Show the current project policy
    Show,
    /// Temporarily disable project protections
    Off {
        #[arg(long, short, default_value = ".")]
        path: PathBuf,
    },
    /// Re-enable project protections
    On {
        #[arg(long, short, default_value = ".")]
        path: PathBuf,
    },
    /// Reload agentguard.toml from disk (manual hot-reload)
    Reload {
        #[arg(long, short, default_value = ".")]
        path: PathBuf,
    },
    /// Audit effective protection coverage for [deny] paths
    Verify {
        #[arg(long, short, default_value = ".")]
        path: PathBuf,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum DaemonCommands {
    Start,
    Stop,
    Restart,
    EmergencyStop,
}

#[derive(Subcommand)]
pub enum GlobalCommands {
    /// Add a global rule
    Add {
        /// Bucket: deny, ask, full, delete, write, read
        #[arg(value_parser = ["deny", "ask", "full", "delete", "write", "read"])]
        bucket: String,
        /// Glob pattern (e.g. C:\Users\*\.ssh\**)
        pattern: String,
    },
    /// Remove a global rule by ID
    Remove { id: i64 },
    /// List all global rules
    List,
}

#[derive(Subcommand)]
pub enum AuditCommands {
    /// Show recent audit events
    List {
        #[arg(long, short, default_value = "25")]
        limit: usize,
    },
}

#[derive(Subcommand)]
pub enum AgentCommands {
    /// Add a rule for a specific agent
    Add {
        /// Agent image name (e.g. cursor.exe, claude.exe)
        agent_image: String,
        /// Bucket: deny, ask, full, delete, write, read
        #[arg(value_parser = ["deny", "ask", "full", "delete", "write", "read"])]
        bucket: String,
        /// Glob pattern (e.g. *.env, src/**)
        pattern: String,
    },
    /// Remove an agent rule by ID
    Remove { id: i64 },
    /// List agent rules (all or filtered by image)
    List {
        /// Filter by agent image (optional)
        image: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Init {
            no_create,
            allow_unhealthy,
        } => cmd::init::run(no_create, allow_unhealthy).await,
        Commands::Status => cmd::status::run().await,
        Commands::Stop => cmd::daemon::stop().await,
        Commands::Project { cmd } => match cmd {
            ProjectCommands::Validate { path } => cmd::project::validate(path).await,
            ProjectCommands::Check { file, op } => cmd::project::check(file, op).await,
            ProjectCommands::Unregister { path } => cmd::project::unregister(path).await,
            ProjectCommands::Show => cmd::project::show().await,
            ProjectCommands::Off { path } => cmd::project::off(path).await,
            ProjectCommands::On { path } => cmd::project::on(path).await,
            ProjectCommands::Reload { path } => cmd::project::reload(path).await,
            ProjectCommands::Verify { path, json } => cmd::project::verify(path, json).await,
        },
        Commands::Daemon { cmd } => match cmd {
            DaemonCommands::Start => cmd::daemon::start().await,
            DaemonCommands::Stop => cmd::daemon::stop().await,
            DaemonCommands::Restart => cmd::daemon::restart().await,
            DaemonCommands::EmergencyStop => cmd::daemon::emergency_stop().await,
        },
        Commands::Global { cmd } => match cmd {
            GlobalCommands::Add { bucket, pattern } => cmd::global::add(bucket, pattern).await,
            GlobalCommands::Remove { id } => cmd::global::remove(id).await,
            GlobalCommands::List => cmd::global::list().await,
        },
        Commands::Audit { cmd } => match cmd {
            AuditCommands::List { limit } => cmd::audit::list(limit).await,
        },
        Commands::Agent { cmd } => match cmd {
            AgentCommands::Add {
                agent_image,
                bucket,
                pattern,
            } => cmd::agent::add(agent_image, bucket, pattern).await,
            AgentCommands::Remove { id } => cmd::agent::remove(id).await,
            AgentCommands::List { image } => cmd::agent::list(image).await,
        },
        Commands::Ui => cmd::ui::run().await,
        Commands::Run => cmd::run::run().await,
        Commands::Update { check } => cmd::update::run(check).await,
    };
    if let Err(e) = result {
        eprintln!("\x1b[31merror:\x1b[0m {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_init_default() {
        let cli = Cli::try_parse_from(["agentguard", "init"]).unwrap();
        match cli.command {
            Commands::Init {
                no_create,
                allow_unhealthy,
            } => {
                assert!(!no_create);
                assert!(!allow_unhealthy);
            }
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn parse_init_no_create() {
        let cli = Cli::try_parse_from(["agentguard", "init", "--no-create"]).unwrap();
        match cli.command {
            Commands::Init {
                no_create,
                allow_unhealthy,
            } => {
                assert!(no_create);
                assert!(!allow_unhealthy);
            }
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn parse_init_allow_unhealthy() {
        let cli = Cli::try_parse_from(["agentguard", "init", "--allow-unhealthy"]).unwrap();
        match cli.command {
            Commands::Init {
                no_create,
                allow_unhealthy,
            } => {
                assert!(!no_create);
                assert!(allow_unhealthy);
            }
            _ => panic!("expected Init"),
        }
    }

    #[test]
    fn parse_status() {
        let cli = Cli::try_parse_from(["agentguard", "status"]).unwrap();
        assert!(matches!(cli.command, Commands::Status));
    }

    #[test]
    fn parse_project_validate_default() {
        let cli = Cli::try_parse_from(["agentguard", "project", "validate"]).unwrap();
        match cli.command {
            Commands::Project { cmd } => match cmd {
                ProjectCommands::Validate { path } => {
                    assert_eq!(path, std::path::PathBuf::from("."));
                }
                _ => panic!("expected Validate"),
            },
            _ => panic!("expected Project"),
        }
    }

    #[test]
    fn parse_project_validate_custom_path() {
        let cli = Cli::try_parse_from(["agentguard", "project", "validate", "-p", "/foo"]).unwrap();
        match cli.command {
            Commands::Project { cmd } => match cmd {
                ProjectCommands::Validate { path } => {
                    assert_eq!(path, std::path::PathBuf::from("/foo"));
                }
                _ => panic!("expected Validate"),
            },
            _ => panic!("expected Project"),
        }
    }

    #[test]
    fn parse_project_check() {
        let cli = Cli::try_parse_from([
            "agentguard",
            "project",
            "check",
            "--file",
            "/test/.env",
            "--op",
            "read",
        ])
        .unwrap();
        match cli.command {
            Commands::Project { cmd } => match cmd {
                ProjectCommands::Check { file, op } => {
                    assert_eq!(file, std::path::PathBuf::from("/test/.env"));
                    assert_eq!(op, "read");
                }
                _ => panic!("expected Check"),
            },
            _ => panic!("expected Project"),
        }
    }

    #[test]
    fn parse_project_check_short_flags() {
        let cli =
            Cli::try_parse_from(["agentguard", "project", "check", "-f", "/x", "-o", "write"])
                .unwrap();
        match cli.command {
            Commands::Project { cmd } => match cmd {
                ProjectCommands::Check { file, op } => {
                    assert_eq!(file, std::path::PathBuf::from("/x"));
                    assert_eq!(op, "write");
                }
                _ => panic!("expected Check"),
            },
            _ => panic!("expected Project"),
        }
    }

    #[test]
    fn parse_project_check_rejects_invalid_op() {
        let result = Cli::try_parse_from([
            "agentguard",
            "project",
            "check",
            "-f",
            "/x",
            "-o",
            "execute",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_project_unregister_default() {
        let cli = Cli::try_parse_from(["agentguard", "project", "unregister"]).unwrap();
        match cli.command {
            Commands::Project { cmd } => match cmd {
                ProjectCommands::Unregister { path } => {
                    assert_eq!(path, std::path::PathBuf::from("."));
                }
                _ => panic!("expected Unregister"),
            },
            _ => panic!("expected Project"),
        }
    }

    #[test]
    fn parse_daemon_start() {
        let cli = Cli::try_parse_from(["agentguard", "daemon", "start"]).unwrap();
        match cli.command {
            Commands::Daemon { cmd } => {
                assert!(matches!(cmd, DaemonCommands::Start));
            }
            _ => panic!("expected Daemon"),
        }
    }

    #[test]
    fn parse_daemon_stop() {
        let cli = Cli::try_parse_from(["agentguard", "daemon", "stop"]).unwrap();
        match cli.command {
            Commands::Daemon { cmd } => {
                assert!(matches!(cmd, DaemonCommands::Stop));
            }
            _ => panic!("expected Daemon"),
        }
    }

    #[test]
    fn parse_daemon_restart() {
        let cli = Cli::try_parse_from(["agentguard", "daemon", "restart"]).unwrap();
        match cli.command {
            Commands::Daemon { cmd } => {
                assert!(matches!(cmd, DaemonCommands::Restart));
            }
            _ => panic!("expected Daemon"),
        }
    }

    #[test]
    fn parse_daemon_emergency_stop() {
        let cli = Cli::try_parse_from(["agentguard", "daemon", "emergency-stop"]).unwrap();
        match cli.command {
            Commands::Daemon { cmd } => {
                assert!(matches!(cmd, DaemonCommands::EmergencyStop));
            }
            _ => panic!("expected Daemon"),
        }
    }

    #[test]
    fn parse_unknown_subcommand_fails() {
        let result = Cli::try_parse_from(["agentguard", "bogus"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_help_flag() {
        let result = Cli::try_parse_from(["agentguard", "--help"]);
        // --help causes clap to print help and exit, so parse fails
        assert!(result.is_err());
    }

    #[test]
    fn parse_version_flag() {
        let result = Cli::try_parse_from(["agentguard", "--version"]);
        assert!(result.is_err());
    }

    // ── Global commands ────────────────────────────────────────────────

    #[test]
    fn parse_global_add() {
        let cli = Cli::try_parse_from([
            "agentguard",
            "global",
            "add",
            "deny",
            "C:\\Users\\*\\.ssh\\**",
        ])
        .unwrap();
        match cli.command {
            Commands::Global { cmd } => match cmd {
                GlobalCommands::Add { bucket, pattern } => {
                    assert_eq!(bucket, "deny");
                    assert_eq!(pattern, "C:\\Users\\*\\.ssh\\**");
                }
                _ => panic!("expected Global::Add"),
            },
            _ => panic!("expected Global"),
        }
    }

    #[test]
    fn parse_global_add_rejects_invalid_bucket() {
        let result = Cli::try_parse_from(["agentguard", "global", "add", "bogus", "*.env"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_global_remove() {
        let cli = Cli::try_parse_from(["agentguard", "global", "remove", "42"]).unwrap();
        match cli.command {
            Commands::Global { cmd } => match cmd {
                GlobalCommands::Remove { id } => assert_eq!(id, 42),
                _ => panic!("expected Global::Remove"),
            },
            _ => panic!("expected Global"),
        }
    }

    #[test]
    fn parse_global_list() {
        let cli = Cli::try_parse_from(["agentguard", "global", "list"]).unwrap();
        match cli.command {
            Commands::Global { cmd } => {
                assert!(matches!(cmd, GlobalCommands::List));
            }
            _ => panic!("expected Global"),
        }
    }

    // ── Audit commands ─────────────────────────────────────────────────

    #[test]
    fn parse_audit_list_default() {
        let cli = Cli::try_parse_from(["agentguard", "audit", "list"]).unwrap();
        match cli.command {
            Commands::Audit { cmd } => match cmd {
                AuditCommands::List { limit } => assert_eq!(limit, 25),
            },
            _ => panic!("expected Audit"),
        }
    }

    #[test]
    fn parse_audit_list_custom_limit() {
        let cli = Cli::try_parse_from(["agentguard", "audit", "list", "--limit", "10"]).unwrap();
        match cli.command {
            Commands::Audit { cmd } => match cmd {
                AuditCommands::List { limit } => assert_eq!(limit, 10),
            },
            _ => panic!("expected Audit"),
        }
    }

    #[test]
    fn parse_project_show() {
        let cli = Cli::try_parse_from(["agentguard", "project", "show"]).unwrap();
        match cli.command {
            Commands::Project { cmd } => {
                assert!(matches!(cmd, ProjectCommands::Show));
            }
            _ => panic!("expected Project"),
        }
    }

    #[test]
    fn parse_project_verify_default() {
        let cli = Cli::try_parse_from(["agentguard", "project", "verify"]).unwrap();
        match cli.command {
            Commands::Project { cmd } => match cmd {
                ProjectCommands::Verify { path, json } => {
                    assert_eq!(path, std::path::PathBuf::from("."));
                    assert!(!json);
                }
                _ => panic!("expected Verify"),
            },
            _ => panic!("expected Project"),
        }
    }

    #[test]
    fn parse_project_verify_json() {
        let cli = Cli::try_parse_from(["agentguard", "project", "verify", "--json"]).unwrap();
        match cli.command {
            Commands::Project { cmd } => match cmd {
                ProjectCommands::Verify { path, json } => {
                    assert_eq!(path, std::path::PathBuf::from("."));
                    assert!(json);
                }
                _ => panic!("expected Verify"),
            },
            _ => panic!("expected Project"),
        }
    }

    // ── Agent commands ─────────────────────────────────────────────────

    #[test]
    fn parse_agent_add() {
        let cli =
            Cli::try_parse_from(["agentguard", "agent", "add", "cursor.exe", "deny", "*.env"])
                .unwrap();
        match cli.command {
            Commands::Agent { cmd } => match cmd {
                AgentCommands::Add {
                    agent_image,
                    bucket,
                    pattern,
                } => {
                    assert_eq!(agent_image, "cursor.exe");
                    assert_eq!(bucket, "deny");
                    assert_eq!(pattern, "*.env");
                }
                _ => panic!("expected Agent::Add"),
            },
            _ => panic!("expected Agent"),
        }
    }

    #[test]
    fn parse_agent_remove() {
        let cli = Cli::try_parse_from(["agentguard", "agent", "remove", "7"]).unwrap();
        match cli.command {
            Commands::Agent { cmd } => match cmd {
                AgentCommands::Remove { id } => assert_eq!(id, 7),
                _ => panic!("expected Agent::Remove"),
            },
            _ => panic!("expected Agent"),
        }
    }

    #[test]
    fn parse_agent_list() {
        let cli = Cli::try_parse_from(["agentguard", "agent", "list"]).unwrap();
        match cli.command {
            Commands::Agent { cmd } => {
                assert!(matches!(cmd, AgentCommands::List { image: None }));
            }
            _ => panic!("expected Agent"),
        }
    }

    #[test]
    fn parse_agent_list_filter() {
        let cli = Cli::try_parse_from(["agentguard", "agent", "list", "cursor.exe"]).unwrap();
        match cli.command {
            Commands::Agent { cmd } => match cmd {
                AgentCommands::List { image } => {
                    assert_eq!(image, Some("cursor.exe".to_string()));
                }
                _ => panic!("expected Agent::List"),
            },
            _ => panic!("expected Agent"),
        }
    }

    #[test]
    fn parse_agent_add_rejects_invalid_bucket() {
        let result =
            Cli::try_parse_from(["agentguard", "agent", "add", "cursor.exe", "bogus", "*.env"]);
        assert!(result.is_err());
    }
}
