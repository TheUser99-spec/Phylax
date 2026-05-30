param(
    [string]$Workspace = "C:\Users\omkde\AgentGuard"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$checks = @()

function Add-Check {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Detail
    )
    $script:checks += [pscustomobject]@{
        Name   = $Name
        Status = $Status
        Detail = $Detail
    }
}

function Is-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-RestrictedDenyAce {
    param([string]$AclText)
    if ([string]::IsNullOrWhiteSpace($AclText)) { return $false }

    # Locale-agnostic best-effort patterns:
    # - SID literal if shown
    # - English account name
    # - Spanish account name
    return ($AclText -match "S-1-5-12") -or
           ($AclText -match "NT AUTHORITY\\RESTRICTED:\(DENY\)") -or
           ($AclText -match "NT AUTHORITY\\RESTRINGIDO:\(DENY\)")
}

Write-Host "AgentGuard Doctor"
Write-Host "Workspace: $Workspace"
Write-Host ""

# 1) Privilege level
if (Is-Admin) {
    Add-Check "admin_session" "PASS" "Running with Administrator privileges."
} else {
    Add-Check "admin_session" "WARN" "Not running as Administrator. HKLM IFEO checks and some ACL diagnostics may be limited."
}

# 2) Daemon process count
try {
    $daemons = Get-Process -Name "agentguard-daemon" -ErrorAction SilentlyContinue
    $count = @($daemons).Count
    if ($count -eq 0) {
        Add-Check "daemon_count" "WARN" "No daemon process found."
    } elseif ($count -eq 1) {
        Add-Check "daemon_count" "PASS" "Single daemon process running."
    } else {
        Add-Check "daemon_count" "FAIL" "Detected $count daemon processes. Split-brain risk."
    }
} catch {
    Add-Check "daemon_count" "FAIL" $_.Exception.Message
}

# 3) Named pipe presence
try {
    $pipe = Get-ChildItem -Path \\.\pipe\ | Where-Object { $_.Name -eq "agentguard" }
    if ($pipe) {
        Add-Check "ipc_pipe" "PASS" "\\.\pipe\agentguard is present."
    } else {
        Add-Check "ipc_pipe" "WARN" "\\.\pipe\agentguard not found."
    }
} catch {
    Add-Check "ipc_pipe" "WARN" $_.Exception.Message
}

# 4) CLI IPC health
try {
    $cli = Join-Path $Workspace "target\debug\agentguard.exe"
    if (-not (Test-Path $cli)) {
        Add-Check "cli_status" "WARN" "CLI binary not found at $cli."
    } else {
        $out = & $cli status 2>&1
        $code = $LASTEXITCODE
        if ($code -eq 0) {
            Add-Check "cli_status" "PASS" "CLI status IPC call succeeded."
        } else {
            $first = ($out | Select-Object -First 1)
            Add-Check "cli_status" "FAIL" "CLI status failed (exit $code): $first"
        }
    }
} catch {
    Add-Check "cli_status" "FAIL" $_.Exception.Message
}

# 4b) Policy validation must be strict-pass
try {
    $cli = Join-Path $Workspace "target\debug\agentguard.exe"
    if (-not (Test-Path $cli)) {
        Add-Check "cli_validate" "WARN" "CLI binary not found at $cli."
    } else {
        $out = & $cli project validate 2>&1
        $code = $LASTEXITCODE
        if ($code -eq 0) {
            Add-Check "cli_validate" "PASS" "project validate succeeded."
        } else {
            $first = ($out | Select-Object -First 1)
            Add-Check "cli_validate" "FAIL" "project validate failed (exit $code): $first"
        }
    }
} catch {
    Add-Check "cli_validate" "FAIL" $_.Exception.Message
}

# 4c) Protection verification must report full effective deny coverage
try {
    $cli = Join-Path $Workspace "target\debug\agentguard.exe"
    if (-not (Test-Path $cli)) {
        Add-Check "cli_verify" "WARN" "CLI binary not found at $cli."
    } else {
        $out = & $cli project verify --json 2>&1
        $code = $LASTEXITCODE
        $raw = ($out -join "`n")
        $json = $null
        try {
            $json = $raw | ConvertFrom-Json -ErrorAction Stop
        } catch {
            $json = $null
        }

        if ($null -ne $json) {
            $schema = [int]$json.schema_version
            $total = [int]$json.total_deny_paths
            $effective = [int]$json.effective_deny_paths
            if ($schema -ne 1) {
                Add-Check "cli_verify" "FAIL" "unexpected verify schema_version=$schema (expected 1)."
            } elseif ($total -eq 0) {
                Add-Check "cli_verify" "WARN" "project verify JSON reports zero deny paths."
            } elseif ($effective -eq $total) {
                Add-Check "cli_verify" "PASS" "effective deny coverage is complete ($effective/$total)."
            } else {
                Add-Check "cli_verify" "FAIL" "effective deny coverage incomplete ($effective/$total)."
            }
        } elseif ($code -eq 0) {
            Add-Check "cli_verify" "PASS" "project verify succeeded (non-JSON fallback)."
        } else {
            $first = ($out | Select-Object -First 1)
            Add-Check "cli_verify" "FAIL" "project verify failed (exit $code): $first"
        }
    }
} catch {
    Add-Check "cli_verify" "FAIL" $_.Exception.Message
}

# 5) IFEO hooks
$ifeoTargets = @("node.exe", "python.exe", "python3.exe", "pythonw.exe", "goose.exe", "opencode.exe",
    "cursor.exe", "claude.exe", "claude-code.exe", "aider.exe", "gemini.exe", "windsurf.exe",
    "codeium.exe", "cody.exe", "tabnine.exe", "augment.exe", "continue.exe", "q.exe",
    "q-developer.exe", "replit.exe", "trae.exe", "devin.exe", "opendevin.exe", "phind.exe",
    "pearai.exe", "blackbox.exe")
$ifeoBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
$spawnExpected = Join-Path $Workspace "target\debug\agentguard-spawn.exe"

foreach ($t in $ifeoTargets) {
    $key = Join-Path $ifeoBase $t
    try {
        $dbg = (Get-ItemProperty -Path $key -Name "Debugger" -ErrorAction Stop).Debugger
        if ($dbg -eq $spawnExpected) {
            Add-Check "ifeo_$t" "PASS" "Debugger -> $dbg"
        } else {
            Add-Check "ifeo_$t" "FAIL" "Unexpected Debugger value: $dbg"
        }
    } catch {
        Add-Check "ifeo_$t" "FAIL" "Missing IFEO Debugger key."
    }
}

# 6) ACL policy checks
$toml = Join-Path $Workspace "agentguard.toml"
$envf = Join-Path $Workspace ".env"

foreach ($f in @($toml, $envf)) {
    try {
        if (-not (Test-Path $f)) {
            Add-Check "acl_$([IO.Path]::GetFileName($f))" "WARN" "File not found."
            continue
        }
        $aclText = (icacls $f | Out-String)
        if (Test-RestrictedDenyAce -AclText $aclText) {
            Add-Check "acl_$([IO.Path]::GetFileName($f))" "PASS" "Restricted SID DENY ACE present."
        } else {
            Add-Check "acl_$([IO.Path]::GetFileName($f))" "FAIL" "Restricted SID DENY ACE missing."
        }
    } catch {
        Add-Check "acl_$([IO.Path]::GetFileName($f))" "FAIL" $_.Exception.Message
    }
}

# 7) Current token restricted SID
try {
    $groups = (whoami /groups | Out-String)
    if ($groups -match "S-1-5-12|RESTRINGIDO") {
        Add-Check "token_restricted_sid" "PASS" "Current token includes restricted SID."
        $tokenRestricted = $true
    } else {
        Add-Check "token_restricted_sid" "WARN" "Current token is not restricted. Restricted-only ACLs will not block this process."
        $tokenRestricted = $false
    }
} catch {
    Add-Check "token_restricted_sid" "WARN" $_.Exception.Message
    $tokenRestricted = $false
}

# 8) Read behavior check
try {
    Get-Content -LiteralPath $toml -ErrorAction Stop | Out-Null
    if ($tokenRestricted) {
        Add-Check "toml_read_current_proc" "FAIL" "Read succeeded even with restricted token."
    } else {
        Add-Check "toml_read_current_proc" "WARN" "Read succeeded from unrestricted token (expected in dev shell)."
    }
} catch {
    if ($tokenRestricted) {
        Add-Check "toml_read_current_proc" "PASS" "Read denied under restricted token."
    } else {
        Add-Check "toml_read_current_proc" "PASS" "Read denied."
    }
}

# 9) Spawn restricted-token self-test
try {
    $spawn = Join-Path $Workspace "target\debug\agentguard-spawn.exe"
    if (-not (Test-Path $spawn)) {
        Add-Check "spawn_selftest" "FAIL" "agentguard-spawn.exe not found."
    } else {
        $tmpGroups = Join-Path ([IO.Path]::GetTempPath()) ("agentguard-spawn-groups-{0}.txt" -f ([guid]::NewGuid()))
        $old = $env:OPENAI_API_KEY
        $env:OPENAI_API_KEY = "doctor-check"
        & $spawn "C:\Windows\System32\cmd.exe" "/c" "whoami /groups > `"$tmpGroups`"" | Out-Null
        $code = $LASTEXITCODE
        if ($null -eq $old) { Remove-Item Env:OPENAI_API_KEY -ErrorAction SilentlyContinue } else { $env:OPENAI_API_KEY = $old }

        $deadline = (Get-Date).AddSeconds(5)
        while ((Get-Date) -lt $deadline -and -not (Test-Path $tmpGroups)) {
            Start-Sleep -Milliseconds 100
        }

        if ($code -ne 0) {
            if ($code -eq 2) {
                Add-Check "spawn_selftest" "FAIL" "Fail-closed triggered: restricted token creation failed."
            } else {
                Add-Check "spawn_selftest" "FAIL" "Unexpected spawn exit code: $code"
            }
        } elseif (-not (Test-Path $tmpGroups)) {
            Add-Check "spawn_selftest" "FAIL" "Restricted child did not write token group output."
        } else {
            $childGroups = Get-Content -LiteralPath $tmpGroups -Raw
            if ($childGroups -match "S-1-5-12|RESTRICTED|RESTRINGIDO") {
                Add-Check "spawn_selftest" "PASS" "Restricted launcher child token includes S-1-5-12."
            } else {
                Add-Check "spawn_selftest" "FAIL" "Child token did not include restricted SID. Output: $($childGroups.Substring(0, [Math]::Min(240, $childGroups.Length)))"
            }
        }

        if (Test-Path $tmpGroups) {
            Remove-Item -LiteralPath $tmpGroups -Force -ErrorAction SilentlyContinue
        }
    }
} catch {
    Add-Check "spawn_selftest" "FAIL" $_.Exception.Message
}

Write-Host ""
Write-Host "Results"
Write-Host "-------"

$pass = 0
$warn = 0
$fail = 0

foreach ($c in $checks) {
    switch ($c.Status) {
        "PASS" { $pass++ }
        "WARN" { $warn++ }
        "FAIL" { $fail++ }
    }
    Write-Host ("[{0}] {1}: {2}" -f $c.Status, $c.Name, $c.Detail)
}

Write-Host ""
Write-Host ("Summary: PASS={0} WARN={1} FAIL={2}" -f $pass, $warn, $fail)

if ($fail -gt 0) {
    exit 1
}
exit 0
