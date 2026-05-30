//! Parser y validador del fichero `agentguard.toml`.
//! Convierte el TOML en un `ProjectManifest` y lo compila
//! a `CompiledManifest` con GlobSets listos para matching O(1).

mod compiled;
mod discovery;
mod mandatory;
mod parser;

pub use compiled::CompiledManifest;
pub use discovery::{auto_detect, detect_language, find_manifest, Language};
pub use mandatory::{enforce_mandatory_denies, missing_mandatory_denies, MANDATORY_DENY_PATTERNS};
pub use parser::ProjectManifest;
