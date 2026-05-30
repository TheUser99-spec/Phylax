#![allow(unsafe_code)]

mod process;
mod token;

use std::env;
use std::ffi::OsString;
use std::path::PathBuf;
use windows_sys::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};

const AGENT_ENV_VARS: &[&str] = &[
    "CLAUDE_CODE",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CURSOR_SESSION",
    "CURSOR_IPC_HOOK_CLI",
    "OPENAI_API_KEY",
    "CODEX_SESSION",
    "GEMINI_API_KEY",
    "AIDER_MODEL",
    "GOOSE_SESSION",
    "CLINE_SESSION",
    "CLINE_MODE",
    "CONTINUE_SESSION",
    "WINDSURF_SESSION",
    "CODEIUM_SESSION",
    "TABNINE_SESSION",
    "TABNINE_TOKEN",
    "AUGMENT_TOKEN",
    "AMAZON_Q_SESSION",
    "Q_DEVELOPER",
    "CODY_ENDPOINT",
    "REPLIT_SESSION",
    "BLACKBOX_SESSION",
    "PHIND_SESSION",
    "PEARAI_SESSION",
    "TRAE_SESSION",
    "SOURCECRAFT_SESSION",
    "ZED_AI",
    "DEVIN_SESSION",
];

const AGENT_IMAGES: &[&str] = &[
    "cursor.exe",
    "claude.exe",
    "claude-code.exe",
    "opencode.exe",
    "aider.exe",
    "goose.exe",
    "gemini.exe",
    "windsurf.exe",
    "codeium.exe",
    "cody.exe",
    "tabnine.exe",
    "augment.exe",
    "continue.exe",
    "q.exe",
    "q-developer.exe",
    "replit.exe",
    "trae.exe",
    "devin.exe",
    "opendevin.exe",
    "phind.exe",
    "pearai.exe",
    "blackbox.exe",
];

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("agentguard-spawn: <target.exe> [args...]");
        std::process::exit(1);
    }

    let target = PathBuf::from(&args[1]);
    let target_args: Vec<OsString> = args[2..].iter().map(OsString::from).collect();

    let is_agent = classify(&target);

    if is_agent {
        match token::spawn_with_restricted_token(&target, &target_args) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("[agentguard-spawn] restricted launch failed: {e}");
                eprintln!("[agentguard-spawn] FAIL-CLOSED: refusing unprotected launch for detected AI agent.");
                std::process::exit(2);
            }
        }
    }

    spawn_normal(&target, &target_args);
}

fn classify(target: &PathBuf) -> bool {
    // S1: environment variables
    for var in AGENT_ENV_VARS {
        if env::var(var).is_ok() {
            return true;
        }
    }

    // S2: image name
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_lowercase();
    if AGENT_IMAGES.iter().any(|img| name == *img) {
        return true;
    }

    false
}

fn spawn_normal(target: &PathBuf, args: &[OsString]) {
    let wide_target = process::target_wide(target);
    let mut wide_cmd = process::build_command_line(target, args);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessW(
            wide_target.as_ptr(),
            wide_cmd.as_mut_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            process::broker_creation_flags(),
            std::ptr::null_mut(),
            std::ptr::null(),
            &mut si,
            &mut pi,
        )
    };

    if ok != 0 {
        if let Err(e) = process::detach_debugger(&pi) {
            eprintln!("[agentguard-spawn] pass-through detach failed: {e}");
            unsafe {
                process::close_process_info(&pi);
            }
            std::process::exit(1);
        }
        unsafe {
            process::close_process_info(&pi);
        }
        std::process::exit(0);
    } else {
        eprintln!(
            "[agentguard-spawn] pass-through failed for {}: {}",
            target.display(),
            std::io::Error::last_os_error()
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn classify_agent_by_env_var() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::set_var("CLAUDE_CODE", "1");
        let target = PathBuf::from("node.exe");
        assert!(classify(&target));
        env::remove_var("CLAUDE_CODE");
    }

    #[test]
    fn classify_agent_by_image() {
        let target = PathBuf::from("cursor.exe");
        assert!(classify(&target));
    }

    #[test]
    fn classify_agent_by_image_case_insensitive() {
        let target = PathBuf::from("CURSOR.EXE");
        assert!(classify(&target));
    }

    #[test]
    fn classify_non_agent_passes_through() {
        let _lock = ENV_LOCK.lock().unwrap();
        let target = PathBuf::from("notepad.exe");
        assert!(!classify(&target));
    }

    #[test]
    fn token_build_quarantine_sid_does_not_fail() {
        let sid = token::build_quarantine_sid();
        assert!(sid.is_ok(), "build_quarantine_sid should succeed");
    }
}
