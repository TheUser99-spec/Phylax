#![allow(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub pid: u32,
    pub protocol: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexCheckResult {
    pub active_agents_online: Vec<AgentNetworkReport>,
    pub usb_devices: Vec<UsbDevice>,
    pub total_connections: usize,
    pub suspicious_connections: usize,
    pub risk_level: DexRiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentNetworkReport {
    pub pid: u32,
    pub image_name: String,
    pub connections: Vec<NetworkConnection>,
    pub has_external: bool,
    pub risk_factors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DexRiskLevel {
    Safe,
    Warning,
    Critical,
}

impl DexRiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            DexRiskLevel::Safe => "safe",
            DexRiskLevel::Warning => "warning",
            DexRiskLevel::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbDevice {
    pub drive_letter: String,
    pub volume_name: String,
    pub is_removable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexMonitor {
    pub monitored_pids: HashSet<u32>,
}

impl DexMonitor {
    pub fn new() -> Self {
        Self { monitored_pids: HashSet::new() }
    }

    pub fn track_agent(&mut self, pid: u32) { self.monitored_pids.insert(pid); }
    pub fn untrack_agent(&mut self, pid: u32) { self.monitored_pids.remove(&pid); }

    pub fn check_all(&self) -> DexCheckResult {
        let all_connections = enumerate_network_connections();
        let usb = enumerate_usb_devices();

        let mut agent_reports: Vec<AgentNetworkReport> = Vec::new();
        let mut seen_pids: HashSet<u32> = HashSet::new();
        let mut total_conns = 0usize;
        let mut suspicious = 0usize;

        for pid in &self.monitored_pids {
            let pid_conns: Vec<_> = all_connections.iter()
                .filter(|c| c.pid == *pid)
                .cloned()
                .collect();

            if pid_conns.is_empty() { continue; }

            seen_pids.insert(*pid);
            total_conns += pid_conns.len();

            let has_external = pid_conns.iter().any(|c| is_external_ip(&c.remote_addr));
            let mut risk_factors = Vec::new();
            let exts: Vec<_> = pid_conns.iter().filter(|c| is_external_ip(&c.remote_addr)).collect();

            if has_external {
                risk_factors.push(format!("External connection: {} hosts", exts.len()));
                suspicious += 1;
            }
            if exts.len() > 5 {
                risk_factors.push("High volume external connections — possible exfiltration".into());
            }

            let image_name = resolve_process_name_fast(*pid);
            agent_reports.push(AgentNetworkReport {
                pid: *pid,
                image_name,
                connections: pid_conns,
                has_external,
                risk_factors,
            });
        }

        let risk = if suspicious > 2 { DexRiskLevel::Critical }
            else if suspicious > 0 || !usb.is_empty() { DexRiskLevel::Warning }
            else { DexRiskLevel::Safe };

        DexCheckResult {
            active_agents_online: agent_reports,
            usb_devices: usb,
            total_connections: total_conns,
            suspicious_connections: suspicious,
            risk_level: risk,
        }
    }
}

#[cfg(windows)]
pub fn enumerate_network_connections() -> Vec<NetworkConnection> {
    let output = std::process::Command::new("netstat")
        .args(["-ano"])
        .output();
    
    match output {
        Ok(o) => parse_netstat_output(&String::from_utf8_lossy(&o.stdout)),
        Err(e) => {
            eprintln!("[dex] netstat unavailable: {e}");
            Vec::new()
        }
    }
}

#[cfg(windows)]
fn parse_netstat_output(output: &str) -> Vec<NetworkConnection> {
    let mut results = Vec::new();
    for line in output.lines().skip(4) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { continue; }
        let proto = parts[0].to_string();
        if proto != "TCP" && proto != "UDP" { continue; }
        let local = parts[1].to_string();
        let remote = parts[2].to_string();
        let state = if proto == "TCP" { parts.get(3).unwrap_or(&"UNKNOWN").to_string() } else { "OPEN".to_string() };
        let pid: u32 = parts.last().and_then(|p| p.parse().ok()).unwrap_or(0);

        if pid > 0 && remote != "0.0.0.0:0" && remote != "*:*" {
            results.push(NetworkConnection { pid, protocol: proto, local_addr: local, remote_addr: remote, state });
        }
    }
    results
}

#[cfg(not(windows))]
pub fn enumerate_network_connections() -> Vec<NetworkConnection> { Vec::new() }

fn is_external_ip(addr: &str) -> bool {
    let ip_str = addr.split(':').next().unwrap_or(addr);
    if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
        let o = ip.octets();
        !ip.is_loopback() && o[0] != 10 && !(o[0] == 172 && o[1] >= 16 && o[1] <= 31)
            && !(o[0] == 192 && o[1] == 168) && o != [0,0,0,0] && o != [255,255,255,255]
    } else { false }
}

#[cfg(windows)]
fn resolve_process_name_fast(pid: u32) -> String {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() { return format!("pid_{pid}"); }

    let mut buf: [u16; 260] = [0; 260];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) };
    unsafe { CloseHandle(handle) };

    if ok != 0 {
        let full = OsString::from_wide(&buf[..len as usize]).to_string_lossy().to_string();
        std::path::Path::new(&full).file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("pid_{pid}"))
    } else {
        format!("pid_{pid}")
    }
}

#[cfg(not(windows))]
fn resolve_process_name_fast(pid: u32) -> String { format!("pid_{pid}") }

#[cfg(windows)]
pub fn enumerate_usb_devices() -> Vec<UsbDevice> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetLogicalDriveStringsW, GetVolumeInformationW, GetDriveTypeW,
    };
    use windows_sys::Win32::System::WindowsProgramming::DRIVE_REMOVABLE;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let mut buf: [u16; 512] = [0; 512];
    let len = unsafe { GetLogicalDriveStringsW(buf.len() as u32, buf.as_mut_ptr()) as usize };
    if len == 0 || len > buf.len() { return Vec::new(); }

    let mut results = Vec::new();
    let mut i = 0;
    while i < len - 1 {
        let end = buf[i..].iter().position(|&c| c == 0).unwrap_or(0);
        if end > 0 {
            let drive = OsString::from_wide(&buf[i..i + end]).to_string_lossy().to_string();
            let drive_type = unsafe { GetDriveTypeW(buf[i..].as_ptr()) };
            if drive_type == DRIVE_REMOVABLE {
                let mut vol_buf: [u16; 260] = [0; 260];
                let vol_name = unsafe {
                    if GetVolumeInformationW(buf[i..].as_ptr(), vol_buf.as_mut_ptr(), vol_buf.len() as u32,
                        std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0) != 0
                    {
                        let end_pos = vol_buf.iter().position(|&c| c == 0).unwrap_or(vol_buf.len());
                        OsString::from_wide(&vol_buf[..end_pos]).to_string_lossy().to_string()
                    } else { "Removable Drive".to_string() }
                };
                results.push(UsbDevice { drive_letter: drive, volume_name: vol_name, is_removable: true });
            }
            i += end + 1;
        } else { break; }
    }
    results
}

#[cfg(not(windows))]
pub fn enumerate_usb_devices() -> Vec<UsbDevice> { Vec::new() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dex_monitor_creation() {
        let m = DexMonitor::new();
        assert!(m.monitored_pids.is_empty());
    }

    #[test]
    fn track_and_untrack() {
        let mut m = DexMonitor::new();
        m.track_agent(1234);
        assert!(m.monitored_pids.contains(&1234));
        m.untrack_agent(1234);
        assert!(!m.monitored_pids.contains(&1234));
    }

    #[test]
    fn is_external_ip_private() {
        assert!(!is_external_ip("127.0.0.1"));
        assert!(!is_external_ip("192.168.1.1"));
        assert!(!is_external_ip("10.0.0.1"));
    }

    #[test]
    fn is_external_ip_public() {
        assert!(is_external_ip("8.8.8.8"));
        assert!(is_external_ip("1.1.1.1"));
    }

    #[test]
    fn check_all_no_agents() {
        let m = DexMonitor::new();
        let r = m.check_all();
        assert!(r.active_agents_online.is_empty());
    }
}
