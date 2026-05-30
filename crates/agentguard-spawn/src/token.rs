#![allow(unsafe_code)]

use std::ffi::OsString;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, PSID, SID_AND_ATTRIBUTES,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessWithTokenW, GetCurrentProcess, OpenProcessToken, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::process;

pub(crate) struct SidPtr(*mut std::ffi::c_void);

impl SidPtr {
    fn as_psid(&self) -> PSID {
        self.0 as PSID
    }
}

impl Drop for SidPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

pub(crate) fn build_quarantine_sid() -> Result<SidPtr, String> {
    let wide: Vec<u16> = OsString::from("S-1-5-12")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sid: PSID = ptr::null_mut();
    let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) };
    if ok == 0 {
        return Err(format!(
            "ConvertStringSidToSidW failed for S-1-5-12: {}",
            unsafe { GetLastError() }
        ));
    }
    Ok(SidPtr(sid as *mut std::ffi::c_void))
}

pub fn spawn_with_restricted_token(target: &PathBuf, args: &[OsString]) -> Result<(), String> {
    let mut token: HANDLE = ptr::null_mut();
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token,
        )
    };
    if ok == 0 {
        return Err(format!("OpenProcessToken failed: {}", unsafe {
            GetLastError()
        }));
    }

    let quarantine_sid = build_quarantine_sid()?;
    let sids = [SID_AND_ATTRIBUTES {
        Sid: quarantine_sid.as_psid(),
        Attributes: 0,
    }];

    let mut restricted_token: HANDLE = ptr::null_mut();
    let ok = unsafe {
        CreateRestrictedToken(
            token,
            DISABLE_MAX_PRIVILEGE,
            0,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            1,
            sids.as_ptr(),
            &mut restricted_token,
        )
    };
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(format!("CreateRestrictedToken failed: {}", unsafe {
            GetLastError()
        }));
    }

    let wide_target = process::target_wide(target);
    let mut wide_cmd = process::build_command_line(target, args);

    let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
    si.cb = mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    let ok = unsafe {
        CreateProcessWithTokenW(
            restricted_token,
            0, // LOGON_WITH_PROFILE unsupported for restricted tokens
            wide_target.as_ptr(),
            wide_cmd.as_mut_ptr(),
            CREATE_UNICODE_ENVIRONMENT, // DEBUG_ONLY_THIS_PROCESS unsupported for CreateProcessWithTokenW
            ptr::null_mut(),
            ptr::null(),
            &mut si,
            &mut pi,
        )
    };

    if ok == 0 {
        let err = unsafe { GetLastError() };
        unsafe { CloseHandle(restricted_token) };
        return Err(format!("CreateProcessWithTokenW failed: {err}"));
    }

    if let Err(e) = process::detach_debugger(&pi) {
        unsafe {
            process::close_process_info(&pi);
            CloseHandle(restricted_token);
        }
        return Err(e);
    }

    unsafe {
        process::close_process_info(&pi);
        CloseHandle(restricted_token);
    }

    Ok(())
}
