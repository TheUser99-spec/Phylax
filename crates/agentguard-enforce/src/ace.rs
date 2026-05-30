use agentguard_core::{GuardError, GuardResult};
use std::path::Path;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::DELETE;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProtectionHealth {
    pub exists: bool,
    pub content_deny: bool,
    pub metadata_deny: bool,
}

impl ProtectionHealth {
    pub fn healthy(&self) -> bool {
        self.exists && self.content_deny && self.metadata_deny
    }
}

pub fn apply_deny_ace(path: &Path) -> GuardResult<()> {
    apply_with_masks(path, &[0x001101FF, DELETE])
}

pub fn apply_write_deny_ace(path: &Path) -> GuardResult<()> {
    apply_with_masks(path, &[0x40000000])
}

pub fn apply_delete_deny_ace(path: &Path) -> GuardResult<()> {
    apply_with_masks(path, &[DELETE])
}

pub fn apply_readonly_deny_ace(path: &Path) -> GuardResult<()> {
    apply_with_masks(path, &[0x40000000, DELETE])
}

fn apply_with_masks(path: &Path, masks: &[u32]) -> GuardResult<()> {
    if !path.exists() { return Ok(()); }
    #[cfg(windows)]
    {
        const MAX_RETRIES: u32 = 3;
        let mut last_err = None;
        for attempt in 1..=MAX_RETRIES {
            match win_api::apply_ace_impl(path, masks) {
                Ok(()) => return Ok(()),
                Err(e) => { last_err = Some(e); if attempt < MAX_RETRIES { std::thread::sleep(std::time::Duration::from_millis(10)); } }
            }
        }
        Err(last_err.unwrap_or_else(|| GuardError::EnforcementFailed { path: path.display().to_string(), reason: "ACE application failed after retries".into() }))
    }
    #[cfg(not(windows))]
    return dev::mark_denied(path);
}

pub fn remove_deny_ace(path: &Path) -> GuardResult<()> {
    #[cfg(windows)]
    return win_api::remove_deny_ace_impl(path);

    #[cfg(not(windows))]
    return dev::unmark_denied(path);
}

pub fn verify_ace(path: &Path) -> GuardResult<ProtectionHealth> {
    #[cfg(windows)]
    return win_api::verify_ace_impl(path);

    #[cfg(not(windows))]
    return Ok(dev::health(path));
}

#[cfg(windows)]
mod win_api {
    use super::*;
    use std::ffi::c_void;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
        DENY_ACCESS, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID,
        TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        AddAce, EqualSid, GetAce, InitializeAcl, ACCESS_DENIED_ACE, ACE_HEADER, ACL, ACL_REVISION,
        DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, UNPROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::DELETE;

    const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
    const MAXDWORD: u32 = u32::MAX;

    fn to_wide_str(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn to_wide(path: &Path) -> Vec<u16> {
        to_wide_str(&path.to_string_lossy())
    }

    #[derive(Debug)]
    struct LocalPtr(*mut c_void);

    impl LocalPtr {
        fn new(ptr: *mut c_void) -> Self {
            Self(ptr)
        }

        fn as_psid(&self) -> PSID {
            self.0 as PSID
        }
    }

    impl Drop for LocalPtr {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    fn everyone_sid_ptr() -> GuardResult<LocalPtr> {
        let sid_str = to_wide_str("S-1-1-0");
        let mut sid: PSID = std::ptr::null_mut();
        let ok = unsafe { ConvertStringSidToSidW(sid_str.as_ptr(), &mut sid) };
        if ok == 0 {
            return Err(GuardError::EnforcementFailed {
                path: "S-1-1-0".into(),
                reason: "ConvertStringSidToSidW failed for Everyone".into(),
            });
        }
        Ok(LocalPtr::new(sid))
    }

    pub fn apply_ace_impl(path: &Path, masks: &[u32]) -> GuardResult<()> {
        let wide = to_wide(path);
        let mut p_dacl: *mut ACL = std::ptr::null_mut();
        let mut p_sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let r = unsafe { GetNamedSecurityInfoW(wide.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), &mut p_dacl, std::ptr::null_mut(), &mut p_sd) };
        let _sd = LocalPtr::new(p_sd);
        if r != 0 { return Err(GuardError::EnforcementFailed { path: path.display().to_string(), reason: format!("GetNamedSecurityInfoW: {r}") }); }

        let sid = everyone_sid_ptr()?;
        let cleaned_dacl = acl_without_agentguard_deny(p_dacl, sid.as_psid(), (masks.len() * std::mem::size_of::<EXPLICIT_ACCESS_W>()) as u32)?;

        let mut entries: Vec<EXPLICIT_ACCESS_W> = masks.iter().map(|&mask| EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask, grfAccessMode: DENY_ACCESS, grfInheritance: NO_INHERITANCE, Trustee: trustee_for_sid(sid.as_psid()),
        }).collect();

        let mut new_dacl: *mut ACL = std::ptr::null_mut();
        let r = unsafe { SetEntriesInAclW(entries.len() as u32, entries.as_mut_ptr(), cleaned_dacl.as_ptr() as *mut ACL, &mut new_dacl) };
        let new_dacl = LocalPtr::new(new_dacl as *mut c_void);
        if r != 0 { return Err(GuardError::EnforcementFailed { path: path.display().to_string(), reason: format!("SetEntriesInAclW: {r}") }); }

        let r = unsafe { SetNamedSecurityInfoW(wide.as_ptr(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), new_dacl.0 as *mut ACL, std::ptr::null()) };
        if r != 0 { return Err(GuardError::EnforcementFailed { path: path.display().to_string(), reason: format!("SetNamedSecurityInfoW DACL: {r}") }); }
        Ok(())
    }

    pub fn remove_deny_ace_impl(path: &Path) -> GuardResult<()> {
        let wide = to_wide(path);

        let sid = everyone_sid_ptr()?;

        let mut p_dacl: *mut ACL = std::ptr::null_mut();
        let mut p_sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

        let r = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut p_dacl,
                std::ptr::null_mut(),
                &mut p_sd,
            )
        };
        let _sd = LocalPtr::new(p_sd);
        if r != 0 {
            return Err(GuardError::EnforcementFailed {
                path: path.display().to_string(),
                reason: format!("GetNamedSecurityInfoW remove DACL: {r}"),
            });
        }

        let cleaned_dacl = acl_without_agentguard_deny(p_dacl, sid.as_psid(), 0)?;

        let r = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                cleaned_dacl.as_ptr() as *mut ACL,
                std::ptr::null(),
            )
        };
        if r != 0 {
            return Err(GuardError::EnforcementFailed {
                path: path.display().to_string(),
                reason: format!("SetNamedSecurityInfoW remove: {r}"),
            });
        }

        Ok(())
    }

    pub fn verify_ace_impl(path: &Path) -> GuardResult<ProtectionHealth> {
        let sid = everyone_sid_ptr()?;
        verify_sid_ace(path, sid.as_psid())
    }

    fn verify_sid_ace(path: &Path, sid: PSID) -> GuardResult<ProtectionHealth> {
        let wide = to_wide(path);

        let mut p_dacl: *mut ACL = std::ptr::null_mut();
        let mut p_sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();

        let r = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut p_dacl,
                std::ptr::null_mut(),
                &mut p_sd,
            )
        };
        let _sd = LocalPtr::new(p_sd);
        if r != 0 {
            const ERROR_FILE_NOT_FOUND: u32 = 2;
            const ERROR_PATH_NOT_FOUND: u32 = 3;
            if r == ERROR_FILE_NOT_FOUND || r == ERROR_PATH_NOT_FOUND {
                return Ok(ProtectionHealth {
                    exists: false,
                    ..ProtectionHealth::default()
                });
            }
            return Err(GuardError::EnforcementFailed {
                path: path.display().to_string(),
                reason: format!("GetNamedSecurityInfoW verify: {r}"),
            });
        }

        Ok(ProtectionHealth {
            exists: true,
            content_deny: has_content_deny(p_dacl, sid)?,
            metadata_deny: has_metadata_deny(p_dacl, sid)?,
        })
    }

    fn trustee_for_sid(sid: PSID) -> TRUSTEE_W {
        TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: sid as *mut u16,
        }
    }

    fn acl_without_agentguard_deny(
        acl: *const ACL,
        sid: PSID,
        extra_bytes: u32,
    ) -> GuardResult<Vec<u8>> {
        copy_acl_without(acl, extra_bytes, |ace| {
            is_agentguard_deny_ace(ace, sid).unwrap_or(false)
        })
    }

    fn copy_acl_without<F>(
        acl: *const ACL,
        extra_bytes: u32,
        mut should_remove: F,
    ) -> GuardResult<Vec<u8>>
    where
        F: FnMut(*const ACE_HEADER) -> bool,
    {
        let base_size = if acl.is_null() {
            std::mem::size_of::<ACL>() as u32
        } else {
            unsafe { (*acl).AclSize as u32 }
        };
        let new_size = base_size.saturating_add(extra_bytes);
        let mut buffer = vec![0u8; new_size as usize];
        let new_acl = buffer.as_mut_ptr() as *mut ACL;

        let ok = unsafe { InitializeAcl(new_acl, new_size, ACL_REVISION) };
        if ok == 0 {
            return Err(GuardError::EnforcementFailed {
                path: "ACL".into(),
                reason: "InitializeAcl failed".into(),
            });
        }

        if acl.is_null() {
            return Ok(buffer);
        }

        let ace_count = unsafe { (*acl).AceCount as u32 };
        for i in 0..ace_count {
            let mut ace: *mut c_void = std::ptr::null_mut();
            let ok = unsafe { GetAce(acl, i, &mut ace) };
            if ok == 0 {
                return Err(GuardError::EnforcementFailed {
                    path: "ACL".into(),
                    reason: format!("GetAce failed at index {i}"),
                });
            }

            let header = ace as *const ACE_HEADER;
            if !should_remove(header) {
                let ace_size = unsafe { (*header).AceSize as u32 };
                let ok = unsafe { AddAce(new_acl, ACL_REVISION, MAXDWORD, ace, ace_size) };
                if ok == 0 {
                    return Err(GuardError::EnforcementFailed {
                        path: "ACL".into(),
                        reason: format!("AddAce failed at index {i}"),
                    });
                }
            }
        }

        Ok(buffer)
    }

    fn has_content_deny(acl: *const ACL, sid: PSID) -> GuardResult<bool> {
        find_ace(acl, |ace| {
            let Some(mask) = access_denied_mask_for_sid(ace, sid)? else {
                return Ok(false);
            };
            Ok(mask & 0x40000000 != 0 || mask == 0x001101FF)
        })
    }

    fn has_metadata_deny(acl: *const ACL, sid: PSID) -> GuardResult<bool> {
        find_ace(acl, |ace| {
            let Some(mask) = access_denied_mask_for_sid(ace, sid)? else {
                return Ok(false);
            };
            Ok((mask & DELETE) == DELETE)
        })
    }

    fn find_ace<F>(acl: *const ACL, mut predicate: F) -> GuardResult<bool>
    where
        F: FnMut(*const ACE_HEADER) -> GuardResult<bool>,
    {
        if acl.is_null() {
            return Ok(false);
        }

        let ace_count = unsafe { (*acl).AceCount as u32 };
        for i in 0..ace_count {
            let mut ace: *mut c_void = std::ptr::null_mut();
            let ok = unsafe { GetAce(acl, i, &mut ace) };
            if ok == 0 {
                return Err(GuardError::EnforcementFailed {
                    path: "ACL".into(),
                    reason: format!("GetAce failed at index {i}"),
                });
            }
            if predicate(ace as *const ACE_HEADER)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn is_agentguard_deny_ace(ace: *const ACE_HEADER, sid: PSID) -> GuardResult<bool> {
        access_denied_mask_for_sid(ace, sid).map(|m| m.is_some())
    }

    fn access_denied_mask_for_sid(ace: *const ACE_HEADER, sid: PSID) -> GuardResult<Option<u32>> {
        if ace.is_null() || unsafe { (*ace).AceType } != ACCESS_DENIED_ACE_TYPE {
            return Ok(None);
        }

        let deny = unsafe { &*(ace as *const ACCESS_DENIED_ACE) };
        let ace_sid = (&deny.SidStart as *const u32) as PSID;
        let ok = unsafe { EqualSid(ace_sid, sid) };
        if ok == 0 {
            return Ok(None);
        }
        Ok(Some(deny.Mask))
    }
}

#[cfg(not(windows))]
mod dev {
    use super::*;

    fn marker_path(path: &Path) -> std::path::PathBuf {
        let name = format!(
            ".agentguard-deny-{}",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        path.parent().unwrap_or(path).join(name)
    }

    pub fn mark_denied(path: &Path) -> GuardResult<()> {
        let marker = marker_path(path);
        std::fs::write(&marker, path.to_string_lossy().as_bytes()).map_err(|e| {
            GuardError::EnforcementFailed {
                path: path.display().to_string(),
                reason: e.to_string(),
            }
        })
    }

    pub fn unmark_denied(path: &Path) -> GuardResult<()> {
        let marker = marker_path(path);
        if marker.exists() {
            std::fs::remove_file(&marker).map_err(|e| GuardError::EnforcementFailed {
                path: path.display().to_string(),
                reason: e.to_string(),
            })?;
        }
        Ok(())
    }

    pub fn is_denied(path: &Path) -> bool {
        marker_path(path).exists()
    }

    pub fn health(path: &Path) -> ProtectionHealth {
        let denied = is_denied(path);
        ProtectionHealth {
            exists: path.exists(),
            content_deny: denied,
            metadata_deny: denied,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn health_all_layers_required() {
        let health = ProtectionHealth {
            exists: true,
            content_deny: true,
            metadata_deny: false,
        };
        assert!(!health.healthy());
    }

    #[test]
    fn health_is_healthy_when_all_present() {
        let health = ProtectionHealth {
            exists: true,
            content_deny: true,
            metadata_deny: true,
        };
        assert!(health.healthy());
    }

    #[test]
    fn missing_file_is_unhealthy() -> Result<(), Box<dyn Error>> {
        let health = verify_ace(Path::new("__agentguard_missing_file__"))?;
        assert!(!health.exists);
        assert!(!health.healthy());
        Ok(())
    }

    #[test]
    fn unprotected_existing_file_is_unhealthy() -> Result<(), Box<dyn Error>> {
        let file = tempfile::NamedTempFile::new()?;
        let health = verify_ace(file.path())?;

        assert!(health.exists);
        assert!(!health.healthy());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn apply_and_verify_protection() -> Result<(), Box<dyn Error>> {
        let file = tempfile::NamedTempFile::new()?;

        apply_deny_ace(file.path())?;
        let health = verify_ace(file.path())?;

        assert!(health.healthy(), "{health:?}");
        remove_deny_ace(file.path())?;
        Ok(())
    }
}
