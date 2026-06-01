//! Applies DENY ACEs via SetNamedSecurityInfo for filesystem-level containment.
//!
//! Phase 1: DENY ACEs on protected files.
//! ACE cleanup when the agent dies or the project is unregistered.

#![allow(unsafe_code)]

pub mod ace;
pub mod coordinator;

pub use coordinator::{Enforcer, PathProtectionHealth};
