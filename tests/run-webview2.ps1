[CmdletBinding()]
param(
    [Parameter()]
    [string] $ReportPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "The WebView2 acceptance harness requires Windows."
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $fileName = "rpackit-webview2-$([guid]::NewGuid().ToString('N')).json"
    $ReportPath = Join-Path $env:TEMP $fileName
}
$ReportPath = [System.IO.Path]::GetFullPath($ReportPath)
$targetDirectory = Join-Path $env:TEMP "rpackit-tauri-target"

$previousTargetDirectory = $env:CARGO_TARGET_DIR
try {
    $env:CARGO_TARGET_DIR = $targetDirectory
    Push-Location $repositoryRoot
    try {
        & cargo run -p rpackit-windows-spike --locked -- --report $ReportPath
        $harnessExit = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
}
finally {
    $env:CARGO_TARGET_DIR = $previousTargetDirectory
}

if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf)) {
    throw "The WebView2 harness did not create its report."
}
$report = Get-Content -Raw -LiteralPath $ReportPath | ConvertFrom-Json
if ($harnessExit -ne 0 -or -not $report.development_gates_passed) {
    throw "A required development-runtime transport gate failed. Report: $ReportPath"
}

Write-Output "WebView2 development-runtime gates passed."
Write-Output "Report: $ReportPath"
