use agentguard_core::GuardResult;
use agentguard_scanner::{self, ThreatLevel};
use std::path::PathBuf;

pub async fn run(path: PathBuf) -> GuardResult<()> {
    let abs = std::fs::canonicalize(&path).unwrap_or(path);
    println!("\n  === AI Model Security Scan ===\n");
    println!("  Scanning: {}\n", abs.display());

    let results = agentguard_scanner::scan_directory(&abs)?;

    if results.is_empty() {
        println!("  No AI model files found.\n");
        return Ok(());
    }

    let malicious: Vec<_> = results.iter().filter(|r| r.threat_level == ThreatLevel::Malicious).collect();
    let suspicious: Vec<_> = results.iter().filter(|r| r.threat_level == ThreatLevel::Suspicious).collect();
    let clean: Vec<_> = results.iter().filter(|r| r.threat_level == ThreatLevel::Clean).collect();

    println!("  Total models    : {}", results.len());
    println!("  \x1b[31mMalicious       : {}\x1b[0m", malicious.len());
    println!("  \x1b[33mSuspicious      : {}\x1b[0m", suspicious.len());
    println!("  \x1b[32mClean           : {}\x1b[0m", clean.len());
    println!();

    for r in &malicious {
        println!("  \x1b[31m[!]\x1b[0m {} ({})", r.path.display(), r.format);
        for f in &r.findings {
            if f.starts_with("SUSPICIOUS") || f.starts_with("BLOCK") || f.starts_with("HIGH") {
                println!("       \x1b[31m{}\x1b[0m", f);
            } else {
                println!("       {}", f);
            }
        }
    }
    for r in &suspicious {
        println!("  \x1b[33m[?]\x1b[0m {} ({})", r.path.display(), r.format);
        for f in &r.findings {
            println!("       {}", f);
        }
    }

    if !clean.is_empty() {
        println!("  ... {} clean model file(s) not shown\n", clean.len());
    }

    if !malicious.is_empty() {
        println!("  \x1b[31mACTION: Add these paths to [deny] in phylax.toml to block them\x1b[0m\n");
    }

    Ok(())
}
