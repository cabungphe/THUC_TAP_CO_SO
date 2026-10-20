$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$agent3Cli = Join-Path $PSScriptRoot '..\.tools\agy\agy.exe'
if (-not (Test-Path -LiteralPath $agent3Cli)) {
    $agent3Cli = Join-Path $env:LOCALAPPDATA 'agy\bin\agy.exe'
}
if (-not (Test-Path -LiteralPath $agent3Cli)) {
    throw 'Install Antigravity CLI: https://antigravity.google/docs/cli/install/'
}
Write-Host 'Complete Google sign-in if requested, then enter /quit.'
& $agent3Cli --model gemini-3.1-pro-high --effort high
