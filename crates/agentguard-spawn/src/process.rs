use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    DebugActiveProcessStop, DebugSetProcessKillOnExit,
};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, DEBUG_ONLY_THIS_PROCESS, PROCESS_INFORMATION,
};

pub(crate) fn quote_arg(arg: &OsStr) -> String {
    let s = arg.to_string_lossy();
    if s.is_empty() {
        return "\"\"".to_string();
    }

    let needs_quotes = s.bytes().any(|b| matches!(b, b' ' | b'\t' | b'"'));
    if !needs_quotes {
        return s.into_owned();
    }

    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for ch in s.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                out.push(ch);
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

pub(crate) fn build_command_line(target: &Path, args: &[OsString]) -> Vec<u16> {
    let mut cmd_line = quote_arg(target.as_os_str());
    for arg in args {
        cmd_line.push(' ');
        cmd_line.push_str(&quote_arg(arg));
    }
    OsString::from(cmd_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub(crate) fn target_wide(target: &Path) -> Vec<u16> {
    target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub(crate) fn broker_creation_flags() -> u32 {
    // IFEO Debugger hooks are intentionally bypassed for debugger-created
    // children; detach immediately after CreateProcess* succeeds.
    CREATE_UNICODE_ENVIRONMENT | DEBUG_ONLY_THIS_PROCESS
}

pub(crate) fn detach_debugger(pi: &PROCESS_INFORMATION) -> Result<(), String> {
    unsafe {
        DebugSetProcessKillOnExit(0);
    }
    let ok = unsafe { DebugActiveProcessStop(pi.dwProcessId) };
    if ok == 0 {
        return Err(format!(
            "DebugActiveProcessStop failed for pid {}: {}",
            pi.dwProcessId,
            unsafe { GetLastError() }
        ));
    }
    Ok(())
}

pub(crate) unsafe fn close_process_info(pi: &PROCESS_INFORMATION) {
    close_handle(pi.hProcess);
    close_handle(pi.hThread);
}

pub(crate) unsafe fn close_handle(handle: HANDLE) {
    if !handle.is_null() {
        CloseHandle(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn quote_arg_no_spaces() {
        assert_eq!(quote_arg(OsStr::new("hello")), "hello");
    }

    #[test]
    fn quote_arg_with_spaces() {
        assert_eq!(quote_arg(OsStr::new("hello world")), "\"hello world\"");
    }

    #[test]
    fn quote_arg_empty_string() {
        assert_eq!(quote_arg(OsStr::new("")), "\"\"");
    }

    #[test]
    fn quote_arg_doubles_trailing_backslash_before_closing_quote() {
        assert_eq!(
            quote_arg(OsStr::new("C:\\has space\\")),
            "\"C:\\has space\\\\\""
        );
    }

    #[test]
    fn quote_arg_escapes_quotes_with_preceding_backslashes() {
        assert_eq!(
            quote_arg(OsStr::new("say \\\"hi\"")),
            "\"say \\\\\\\"hi\\\"\""
        );
    }

    #[test]
    fn build_command_line_includes_target_and_args() {
        let target = PathBuf::from("C:\\Program Files\\node.exe");
        let args = vec![OsString::from("--flag"), OsString::from("hello world")];
        let wide = build_command_line(&target, &args);
        let nul = wide.iter().position(|c| *c == 0).unwrap();
        let s = String::from_utf16_lossy(&wide[..nul]);
        assert_eq!(s, "\"C:\\Program Files\\node.exe\" --flag \"hello world\"");
    }
}
