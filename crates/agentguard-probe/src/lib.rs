//! ETW consumer + SubjectClassifier for AI agent detection.
//!
//! Classification signals:
//!   S1: Known environment variables (CLAUDE_CODE, ANTHROPIC_API_KEY...)
//!   S2: Exact image name (claude.exe, cursor.exe, goose.exe...)
//!   S3: node.exe with cmdline mentioning an agent (claude, cline...)
//!   S4: Process without interactive session (session_id==0, no window station)
//!   S5: Parent inheritance (child of an agent -> Inherited)

#![allow(unsafe_code)]

pub mod classifier;
pub mod etw;
pub mod poller;
pub mod tracker;

pub use classifier::{ClassifierConfig, ProcessInfo, SubjectClassifier};
pub use etw::run_etw_notifier;
pub use poller::{ProcessEvent, ProcessPoller};
pub use tracker::AgentSessionTracker;
