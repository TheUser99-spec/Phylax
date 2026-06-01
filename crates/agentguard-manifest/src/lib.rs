//! Parser and validator for `phylax.toml`.
//! Converts TOML into a `ProjectManifest` and compiles it
//! into a `CompiledManifest` with GlobSets ready for O(1) matching.

mod compiled;
mod discovery;
mod mandatory;
mod parser;

pub use compiled::CompiledManifest;
pub use discovery::{auto_detect, detect_language, find_manifest, Language};
pub use mandatory::{enforce_mandatory_denies, missing_mandatory_denies, MANDATORY_DENY_PATTERNS};
pub use parser::ProjectManifest;
