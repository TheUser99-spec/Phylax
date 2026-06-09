$token = $env:GITHUB_TOKEN
if (-not $token) { Write-Error "GITHUB_TOKEN environment variable not set"; exit 1 }
$repo = "TheUser99-spec/AgentGuard"
$tag = "v0.1.2"

$body = @{
    tag_name = $tag
    name = "AgentGuard $tag"
    body = "English CLI, agentguard stop command, Q in TUI kills daemon, improved docs."
    draft = $false
    prerelease = $false
} | ConvertTo-Json

Write-Host "Creating release v0.1.2..."
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases" `
    -Method Post `
    -Headers @{Authorization = "token $token"; Accept = "application/vnd.github+json"} `
    -Body $body `
    -ContentType "application/json"

$uploadUrl = $release.upload_url -replace '\{[\w,]+\}$', ''

Write-Host "Uploading agentguard.exe..."
Invoke-RestMethod -Uri "$uploadUrl`?name=agentguard.exe" `
    -Method Post `
    -Headers @{Authorization = "token $token"; Accept = "application/vnd.github+json"} `
    -ContentType "application/octet-stream" `
    -InFile "agentguard.exe"

Write-Host "Uploading agentguard-daemon.exe..."
Invoke-RestMethod -Uri "$uploadUrl`?name=agentguard-daemon.exe" `
    -Method Post `
    -Headers @{Authorization = "token $token"; Accept = "application/vnd.github+json"} `
    -ContentType "application/octet-stream" `
    -InFile "agentguard-daemon.exe"

Write-Host "Release published: $($release.html_url)" -ForegroundColor Green
