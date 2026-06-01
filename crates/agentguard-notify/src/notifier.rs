use agentguard_core::AskResponse;

pub struct Notifier;

impl Notifier {
    pub fn ask_user_blocking(
        agent_name: &str,
        file_path: &str,
        operation: &str,
        _request_id: u64,
    ) -> AskResponse {
        #[cfg(windows)]
        return windows_prompt(agent_name, file_path, operation);

        #[cfg(not(windows))]
        return terminal_prompt(agent_name, file_path, operation);
    }
}

#[cfg(windows)]
fn windows_prompt(agent_name: &str, file_path: &str, operation: &str) -> AskResponse {
    let text: Vec<u16> = format!(
        "Phylax detected an AI agent trying to access a protected file.\n\n\
         Agent : {agent_name}\n\
         File  : {file_path}\n\
         Action: {operation}\n\n\
         Allow this access?\n\
         Yes = Allow once    No = Deny"
    )
    .encode_utf16()
    .chain(std::iter::once(0))
    .collect();

    let caption: Vec<u16> = "Phylax — Permission Required\0"
        .encode_utf16()
        .collect();

    const MB_YESNO: u32 = 0x00000004;
    const MB_ICONQUESTION: u32 = 0x00000020;
    const MB_SYSTEMMODAL: u32 = 0x00001000;
    const MB_TOPMOST: u32 = 0x00040000;
    const IDYES: i32 = 6;

    let flags = MB_YESNO | MB_ICONQUESTION | MB_SYSTEMMODAL | MB_TOPMOST;

    let result =
        unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), flags) };

    if result == IDYES {
        AskResponse::AllowOnce
    } else {
        AskResponse::Deny
    }
}

#[cfg(windows)]
#[link(name = "user32")]
extern "system" {
    fn MessageBoxW(
        h_wnd: *mut std::ffi::c_void,
        lp_text: *const u16,
        lp_caption: *const u16,
        u_type: u32,
    ) -> i32;
}

#[cfg(not(windows))]
fn terminal_prompt(agent_name: &str, file_path: &str, operation: &str) -> AskResponse {
    use std::io::{BufRead, Write};

    println!();
    println!("+----------------------------------------+");
    println!("|  Phylax — Permission Required     |");
    println!("+----------------------------------------+");
    println!("| Agent : {:<30} |", agent_name);
    println!("| File  : {:<30} |", truncate(file_path, 30));
    println!("| Action: {:<30} |", operation);
    println!("+----------------------------------------+");
    print!("  Allow? [y=allow once / n=deny]: ");

    let _ = std::io::stdout().flush();

    let stdin = std::io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_ok() {
        let trimmed = line.trim().to_lowercase();
        if trimmed == "y" || trimmed == "yes" {
            return AskResponse::AllowOnce;
        }
    }

    println!("  -> Denied.");
    AskResponse::Deny
}

#[cfg(not(windows))]
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        format!("{:width$}", s, width = max)
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(windows))]
    fn ask_user_returns_allow_once_or_deny_terminal() {
        let result = Notifier::ask_user_blocking("claude.exe", "/project/.env", "read", 1);
        assert!(matches!(result, AskResponse::AllowOnce | AskResponse::Deny));
    }

    #[test]
    #[cfg(not(windows))]
    fn terminal_prompt_denies_on_eof() {
        let result = terminal_prompt("claude.exe", "/project/.env", "read");
        assert_eq!(result, AskResponse::Deny);
    }

    #[test]
    #[cfg(not(windows))]
    fn ask_user_never_returns_allow_session() {
        let result = Notifier::ask_user_blocking("cursor.exe", "/src/main.rs", "write", 2);
        assert!(!matches!(result, AskResponse::AllowSession));
    }

    #[test]
    #[cfg(windows)]
    #[ignore = "opens a real MessageBoxW dialog; run manually"]
    fn windows_prompt_returns_deny_when_no_user() {
        let result = windows_prompt("test.exe", "/test/file", "read");
        assert_eq!(result, AskResponse::Deny);
    }

    #[test]
    #[cfg(not(windows))]
    fn truncate_short_string() {
        assert_eq!(truncate("hello", 10), "hello     ");
    }

    #[test]
    #[cfg(not(windows))]
    fn truncate_long_string() {
        assert_eq!(truncate("very_long_filename_here.txt", 10), "very_lo...");
    }
}
