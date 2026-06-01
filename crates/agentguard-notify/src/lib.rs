//! Notifications for the [ask] bucket.
//!
//! Flow:
//!   1. Agent tries to access a file in [ask]
//!   2. Daemon calls Notifier::ask_user_blocking()
//!   3. Windows: MessageBoxW with MB_YESNO (Yes=AllowOnce, No=Deny)
//!      Unix: terminal prompt (y/n)
//!   4. No response / error -> Deny
//!
//! The caller (daemon) must wrap in tokio::task::spawn_blocking
//! + tokio::time::timeout for timeout control.

#![allow(unsafe_code)]

pub mod notifier;

pub use notifier::Notifier;
