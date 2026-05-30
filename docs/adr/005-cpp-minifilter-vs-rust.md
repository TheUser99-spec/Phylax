# ADR-005: C++ Minifilter for Phase 2 Kernel Driver

**Status**: Tentative (confirmed for Phase 2 implementation)

## Context

Phase 2 of AgentGuard introduces a kernel-mode file system minifilter driver for
tamper-proof enforcement. This driver must intercept all file I/O requests (create,
read, write, delete) before they reach user mode, making decisions based on
AgentGuard policy.

Two language options were evaluated for the kernel driver:
1. **C++ with Windows Driver Kit (WDK)** — the officially supported path
2. **Rust with Windows Kernel FFI** — experimental community efforts

## Decision

Use **C++ with WDK** for the Phase 2 minifilter driver. Rust is not used in kernel
mode.

## Rationale

### WDK Official Support
- Microsoft's WDK officially supports C and C++. The minifilter API (`FltMgr`) has
  exhaustive C/C++ documentation, samples, and debugging tools.
- Microsoft provides `minifilter` sample code in C that can be adapted directly.

### Rust Kernel Limitations
- Rust kernel development on Windows requires the `windows-kernel-rs` crate, which is
  community-maintained and has incomplete bindings for the minifilter API.
- The Rust compiler does not produce kernel-mode compatible binaries without
  significant build system customization.
- Debugging a Rust kernel driver is significantly harder than C++ — WinDbg has
  first-class C++ support.
- A kernel crash (BSOD) from a Rust driver would be extremely difficult to diagnose
  without mature tooling.

### Separation of Concerns
- Phase 1 daemon is 100% Rust (user mode). Phase 2 adds a C++ kernel driver alongside
  the existing Rust daemon.
- The daemon communicates with the driver via IOCTLs on a device interface. This is a
  well-defined C ABI boundary — Rust calls `DeviceIoControl` (via `windows-sys`), C++
  handles the request.
- No Rust-to-C++ FFI in kernel mode; all cross-process communication is via IOCTLs.

## Consequences

- Two languages in the repository (Rust for user mode, C++ for kernel mode).
  Mitigated by strict separation: `driver/` directory is self-contained.
- Kernel driver requires EV code signing certificate ($300-500/year) for distribution
  outside test-signing mode.
- Driver installation requires admin privileges and a reboot (standard for all kernel
  drivers).
- The C++ driver is optional — Phase 1 works entirely in user mode. Users who don't
  need kernel-level tamper-proofing can stay on Phase 1.

## Alternatives Considered

1. **Pure Rust kernel driver**: Rejected — the ecosystem is not mature enough for
   production kernel code in 2026. Risk of unstable BSODs from Rust-specific issues.
2. **No kernel driver (user-mode only forever)**: Rejected — user-mode ACEs can be
   removed by an admin process. For enterprise security use cases (finance, healthcare),
   kernel-level enforcement is a hard requirement.
3. **Windows Filtering Platform (WFP) driver**: Rejected — WFP is for network filtering,
   not file system interception. Using WFP for file I/O would require creative abuse
   of the API.
4. **eBPF for Windows**: Rejected — too new (preview in 2025-2026), not stable for
   production, limited file system hook points.
