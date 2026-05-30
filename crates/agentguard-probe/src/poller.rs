use crate::classifier::ProcessInfo;
use crate::tracker::AgentSessionTracker;
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct ProcessPoller {
    tracker: Arc<AgentSessionTracker>,
}

#[derive(Debug)]
pub enum ProcessEvent {
    Started(ProcessInfo),
    Exited(u32),
}

impl ProcessPoller {
    pub fn new(
        _classifier: Arc<crate::classifier::SubjectClassifier>,
        tracker: Arc<AgentSessionTracker>,
    ) -> Self {
        Self { tracker }
    }

    pub async fn run(
        self,
        tx: mpsc::Sender<ProcessEvent>,
        mut stop_rx: mpsc::Receiver<()>,
        interval_ms: u64,
    ) {
        #[cfg(not(windows))]
        {
            let _ = (self, tx, interval_ms);
            let _ = stop_rx;
        }

        #[cfg(windows)]
        {
            let _tracker = self.tracker;
            let stopped = Arc::new(AtomicBool::new(false));
            let stopped_flag = stopped.clone();

            let handle = tokio::task::spawn_blocking(move || {
                poll_loop(tx, stopped_flag, interval_ms);
            });

            // Wait for stop signal
            stop_rx.recv().await;

            // Signal poller to stop and wait for it
            stopped.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = handle.await;
        }
    }
}

#[cfg(windows)]
fn poll_loop(tx: mpsc::Sender<ProcessEvent>, stopped: Arc<AtomicBool>, interval_ms: u64) {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let mut prev: HashMap<u32, ProcessSnapshot> = HashMap::new();

    loop {
        if stopped.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            std::thread::sleep(std::time::Duration::from_millis(interval_ms));
            continue;
        }

        let mut current: HashMap<u32, ProcessSnapshot> = HashMap::new();
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..unsafe { std::mem::zeroed() }
        };

        let mut ok = unsafe { Process32FirstW(handle, &mut entry) };
        while ok != 0 {
            let pid = entry.th32ProcessID;
            let parent_pid = entry.th32ParentProcessID;
            let image_name = OsString::from_wide(trim_null(&entry.szExeFile))
                .to_string_lossy()
                .to_string();

            let creation_time = get_creation_time(pid);

            current.insert(pid, ProcessSnapshot { creation_time });

            if let Some(old) = prev.remove(&pid) {
                if old.creation_time != creation_time {
                    if let Some(info) = build_info(pid, &image_name, parent_pid) {
                        let _ = tx.blocking_send(ProcessEvent::Exited(pid));
                        let _ = tx.blocking_send(ProcessEvent::Started(info));
                    }
                }
            } else if let Some(info) = build_info(pid, &image_name, parent_pid) {
                let _ = tx.blocking_send(ProcessEvent::Started(info));
            }

            ok = unsafe { Process32NextW(handle, &mut entry) };
        }

        for (pid, _snap) in prev.drain() {
            let _ = tx.blocking_send(ProcessEvent::Exited(pid));
        }

        prev = current;

        unsafe {
            CloseHandle(handle);
        }

        let mut remaining = interval_ms;
        while remaining > 0 && !stopped.load(std::sync::atomic::Ordering::SeqCst) {
            let chunk = remaining.min(500);
            std::thread::sleep(std::time::Duration::from_millis(chunk));
            remaining -= chunk;
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct ProcessSnapshot {
    creation_time: Option<u64>,
}

#[cfg(windows)]
fn get_creation_time(pid: u32) -> Option<u64> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };

    let ok = unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };

    unsafe {
        CloseHandle(handle);
    }

    if ok == 0 {
        return None;
    }

    Some(((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64))
}

// ── Process info gathering (PEB reading) ────────────────────────────────

#[cfg(windows)]
mod process_info {
    use std::ffi::c_void;

    pub fn get_session_id(pid: u32) -> u32 {
        use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
        let mut session_id: u32 = 0;
        if unsafe { ProcessIdToSessionId(pid, &mut session_id) } == 0 {
            return 1;
        }
        session_id
    }

    pub fn has_visible_window(pid: u32) -> bool {
        use std::cell::Cell;
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindowThreadProcessId, IsWindowVisible,
        };

        thread_local! {
            static RESULT: Cell<bool> = const { Cell::new(false) };
            static TARGET: Cell<u32> = const { Cell::new(0) };
        }

        TARGET.with(|t| t.set(pid));
        RESULT.with(|r| r.set(false));

        unsafe extern "system" fn callback(hwnd: *mut c_void, _lparam: isize) -> i32 {
            if unsafe { IsWindowVisible(hwnd) } == 0 {
                return 1;
            }
            let mut wnd_pid: u32 = 0;
            unsafe { GetWindowThreadProcessId(hwnd, &mut wnd_pid) };
            let target = TARGET.with(|t| t.get());
            if wnd_pid == target {
                RESULT.with(|r| r.set(true));
                return 0;
            }
            1
        }

        unsafe { EnumWindows(Some(callback), 0) };
        RESULT.with(|r| r.get())
    }

    // ── PEB structures (x64 only) ───────────────────────────────────────

    #[cfg(target_pointer_width = "64")]
    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: i32,
        peb_base_address: *mut c_void,
        affinity_mask: usize,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    #[cfg(target_pointer_width = "64")]
    #[repr(C)]
    struct UnicodeString {
        _length: u16,
        _maximum_length: u16,
        buffer: *mut u16,
    }

    #[cfg(target_pointer_width = "64")]
    #[repr(C)]
    struct Curdir {
        _dos_path: UnicodeString,
        _handle: *mut c_void,
    }

    #[cfg(target_pointer_width = "64")]
    #[repr(C)]
    struct RtlUserProcessParameters {
        _maximum_length: u32,
        _length: u32,
        _flags: u32,
        _debug_flags: u32,
        _console_handle: *mut c_void,
        _console_flags: u32,
        _standard_input: *mut c_void,
        _standard_output: *mut c_void,
        _standard_error: *mut c_void,
        _current_directory: Curdir,
        _dll_path: UnicodeString,
        _image_path_name: UnicodeString,
        command_line: UnicodeString,
        _environment: *mut c_void,
    }

    #[cfg(target_pointer_width = "64")]
    #[repr(C)]
    struct Peb {
        _inherited_address_space: u8,
        _read_image_file_exec_options: u8,
        _being_debugged: u8,
        _bit_field: u8,
        _mutant: *mut c_void,
        _image_base_address: *mut c_void,
        _ldr: *mut c_void,
        process_parameters: *mut RtlUserProcessParameters,
    }

    #[cfg(not(target_pointer_width = "64"))]
    pub fn read_cmdline(_pid: u32) -> Option<String> {
        // PEB structures are x64-only. On 32-bit Windows, agent detection
        // falls back to image name matching (S2) and session heuristics (S4).
        // S1 (env vars) and S3 (cmdline) are unavailable.
        None
    }

    #[cfg(not(target_pointer_width = "64"))]
    pub fn read_env_keys(_pid: u32) -> Vec<String> {
        // Same limitation as read_cmdline — x64-only PEB access.
        vec![]
    }

    // ── PEB reading ─────────────────────────────────────────────────────

    #[cfg(target_pointer_width = "64")]
    pub fn read_cmdline(pid: u32) -> Option<String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        };

        let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            return None;
        }

        let result = read_cmdline_inner(handle);

        unsafe { CloseHandle(handle) };
        result
    }

    #[cfg(target_pointer_width = "64")]
    fn read_cmdline_inner(handle: *mut c_void) -> Option<String> {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        const PROCESS_BASIC_INFORMATION: i32 = 0;

        extern "system" {
            fn NtQueryInformationProcess(
                process_handle: *mut c_void,
                process_information_class: i32,
                process_information: *mut c_void,
                process_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
        }

        let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let mut ret_len: u32 = 0;
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                PROCESS_BASIC_INFORMATION,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut ret_len,
            )
        };
        if status < 0 || pbi.peb_base_address.is_null() {
            return None;
        }

        let mut peb: Peb = unsafe { std::mem::zeroed() };
        let mut bytes_read: usize = 0;
        if unsafe {
            ReadProcessMemory(
                handle,
                pbi.peb_base_address as *const c_void,
                &mut peb as *mut _ as *mut c_void,
                std::mem::size_of::<Peb>(),
                &mut bytes_read,
            )
        } == 0
        {
            return None;
        }
        if peb.process_parameters.is_null() {
            return None;
        }

        let mut params: RtlUserProcessParameters = unsafe { std::mem::zeroed() };
        if unsafe {
            ReadProcessMemory(
                handle,
                peb.process_parameters as *const c_void,
                &mut params as *mut _ as *mut c_void,
                std::mem::size_of::<RtlUserProcessParameters>(),
                &mut bytes_read,
            )
        } == 0
        {
            return None;
        }

        let len = params.command_line._length as usize;
        let buf_addr = params.command_line.buffer;
        if len == 0 || len > 32768 || buf_addr.is_null() {
            return None;
        }

        let char_count = len / 2;
        let mut buf: Vec<u16> = vec![0u16; char_count];
        if unsafe {
            ReadProcessMemory(
                handle,
                buf_addr as *const c_void,
                buf.as_mut_ptr() as *mut c_void,
                len,
                &mut bytes_read,
            )
        } == 0
        {
            return None;
        }

        Some(
            OsString::from_wide(&buf[..char_count.min(bytes_read / 2)])
                .to_string_lossy()
                .to_string(),
        )
    }

    #[cfg(target_pointer_width = "64")]
    pub fn read_env_keys(pid: u32) -> Vec<String> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
        };

        let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            return vec![];
        }

        let result = read_env_keys_inner(handle);

        unsafe { CloseHandle(handle) };
        result
    }

    #[cfg(target_pointer_width = "64")]
    fn read_env_keys_inner(handle: *mut c_void) -> Vec<String> {
        use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        const PROCESS_BASIC_INFORMATION: i32 = 0;

        extern "system" {
            fn NtQueryInformationProcess(
                process_handle: *mut c_void,
                process_information_class: i32,
                process_information: *mut c_void,
                process_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
        }

        let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let mut ret_len: u32 = 0;
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                PROCESS_BASIC_INFORMATION,
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut ret_len,
            )
        };
        if status < 0 || pbi.peb_base_address.is_null() {
            return vec![];
        }

        let mut peb: Peb = unsafe { std::mem::zeroed() };
        let mut bytes_read: usize = 0;
        if unsafe {
            ReadProcessMemory(
                handle,
                pbi.peb_base_address as *const c_void,
                &mut peb as *mut _ as *mut c_void,
                std::mem::size_of::<Peb>(),
                &mut bytes_read,
            )
        } == 0
        {
            return vec![];
        }
        if peb.process_parameters.is_null() {
            return vec![];
        }

        let mut params: RtlUserProcessParameters = unsafe { std::mem::zeroed() };
        if unsafe {
            ReadProcessMemory(
                handle,
                peb.process_parameters as *const c_void,
                &mut params as *mut _ as *mut c_void,
                std::mem::size_of::<RtlUserProcessParameters>(),
                &mut bytes_read,
            )
        } == 0
        {
            return vec![];
        }

        let env_ptr = params._environment;
        if env_ptr.is_null() {
            return vec![];
        }

        // Windows max environment block: 32767 chars (65534 bytes).
        // Our 65536 u16 = 131072 bytes buffer is more than double the limit.
        let mut env_block: Vec<u16> = vec![0u16; 65536];
        if unsafe {
            ReadProcessMemory(
                handle,
                env_ptr as *const c_void,
                env_block.as_mut_ptr() as *mut c_void,
                env_block.len() * 2,
                &mut bytes_read,
            )
        } == 0
        {
            return vec![];
        }

        parse_env_keys(&env_block[..bytes_read / 2])
    }

    fn parse_env_keys(wide: &[u16]) -> Vec<String> {
        let mut keys = Vec::new();
        let mut start = 0usize;
        for i in 0..wide.len() {
            if wide[i] == 0 {
                if i == start {
                    break;
                }
                let entry = &wide[start..i];
                if let Some(key) = extract_key(entry) {
                    keys.push(key);
                }
                start = i + 1;
            }
        }
        keys
    }

    fn extract_key(wide: &[u16]) -> Option<String> {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        let s = OsString::from_wide(wide).to_string_lossy().to_string();
        let eq_pos = s.find('=')?;
        if eq_pos == 0 {
            return None;
        }
        Some(s[..eq_pos].to_string())
    }
}

#[cfg(windows)]
fn build_info(pid: u32, image_name: &str, parent_pid: u32) -> Option<ProcessInfo> {
    let session_id = process_info::get_session_id(pid);
    let cmdline = process_info::read_cmdline(pid).unwrap_or_default();
    let env_vars = process_info::read_env_keys(pid);
    let has_window = process_info::has_visible_window(pid);

    Some(ProcessInfo {
        pid,
        image_name: image_name.to_string(),
        cmdline,
        env_vars,
        session_id,
        has_window,
        parent_pid: if parent_pid == 0 {
            None
        } else {
            Some(parent_pid)
        },
    })
}

#[cfg(windows)]
fn trim_null(wide: &[u16; 260]) -> &[u16] {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    &wide[..end]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn poller_creation() {
        let tracker = Arc::new(AgentSessionTracker::new(
            crate::classifier::SubjectClassifier::with_defaults(),
        ));
        let classifier = Arc::new(crate::classifier::SubjectClassifier::with_defaults());
        let _poller = ProcessPoller::new(classifier, tracker);
    }

    #[test]
    fn build_info_self_process_has_session_id() {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        let pid = unsafe { GetCurrentProcessId() };
        let info = build_info(pid, "test.exe", 0).expect("build_info should succeed for self");
        assert!(
            info.session_id > 0,
            "Interactive processes have session_id > 0"
        );
    }

    #[test]
    fn build_info_self_process_has_cmdline() {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        let pid = unsafe { GetCurrentProcessId() };
        let info = build_info(pid, "test.exe", 0).expect("build_info should succeed for self");
        assert!(
            !info.cmdline.is_empty(),
            "Should be able to read own cmdline. Got: '{}'",
            info.cmdline
        );
    }

    #[test]
    fn build_info_self_process_has_env_vars() {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        let pid = unsafe { GetCurrentProcessId() };
        let info = build_info(pid, "test.exe", 0).expect("build_info should succeed for self");
        let has_path = info.env_vars.iter().any(|k| k.eq_ignore_ascii_case("PATH"));
        let has_username = info
            .env_vars
            .iter()
            .any(|k| k.eq_ignore_ascii_case("USERNAME"));
        assert!(
            has_path || has_username,
            "Should read env vars. Got {} keys: {:?}",
            info.env_vars.len(),
            &info.env_vars[..info.env_vars.len().min(10)]
        );
    }

    #[test]
    fn build_info_nonexistent_pid_does_not_panic() {
        let info = build_info(99999999, "ghost.exe", 0).expect("Nonexistent pid should not crash");
        assert!(info.session_id > 0, "session_id defaults to 1");
        assert!(
            info.cmdline.is_empty(),
            "cmdline should be empty for nonexistent pid"
        );
        assert!(
            info.env_vars.is_empty(),
            "env vars should be empty for nonexistent pid"
        );
    }

    #[test]
    fn build_info_parent_pid_is_set() {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        let pid = unsafe { GetCurrentProcessId() };
        let info = build_info(pid, "test.exe", 42).expect("build_info should succeed");
        assert_eq!(info.parent_pid, Some(42));
    }

    #[test]
    fn build_info_zero_parent_pid_is_none() {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        let pid = unsafe { GetCurrentProcessId() };
        let info = build_info(pid, "test.exe", 0).expect("build_info should succeed");
        assert_eq!(info.parent_pid, None);
    }
}
