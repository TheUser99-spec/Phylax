$token = $env:GITHUB_TOKEN
if (-not $token) { Write-Error "GITHUB_TOKEN environment variable not set"; exit 1 }
$headers = @{Authorization = "token $token"; Accept = "application/vnd.github+json"}
$user = "TheUser99-spec"
$repo = "winget-pkgs"
$ver = "0.1.2"
$base = "manifests/t/TheUser99-spec/AgentGuard/$ver"
$srcDir = "C:\Users\omkde\AgentGuard\winget"

$files = @(
    "TheUser99-spec.AgentGuard.yaml",
    "TheUser99-spec.AgentGuard.installer.yaml",
    "TheUser99-spec.AgentGuard.locale.en-US.yaml"
)

foreach ($file in $files) {
    $content = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((Get-Content "$srcDir\$file" -Raw)))
    $body = @{message = "Add AgentGuard v$ver"; content = $content; branch = "master"} | ConvertTo-Json
    $path = "$base/$file"
    $url = "https://api.github.com/repos/$user/$repo/contents/$path"
    try {
        Invoke-RestMethod -Uri $url -Method Put -Headers $headers -Body $body -ContentType "application/json" | Out-Null
        Write-Host "OK: $path"
    } catch {
        Write-Host "FAIL: $path - $_"
    }
}

Write-Host "All files pushed to https://github.com/$user/$repo" -ForegroundColor Green
