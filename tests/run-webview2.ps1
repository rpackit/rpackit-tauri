[CmdletBinding()]
param(
    [Parameter()]
    [string] $ReportPath,

    [Parameter()]
    [string] $FixedRuntimePath,

    [Parameter()]
    [string] $TargetDirectory,

    [Parameter()]
    [switch] $Release
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
if ([string]::IsNullOrWhiteSpace($TargetDirectory)) {
    if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
        $TargetDirectory = Join-Path $repositoryRoot "target"
    }
    else {
        $TargetDirectory = $env:CARGO_TARGET_DIR
    }
}
$TargetDirectory = [System.IO.Path]::GetFullPath($TargetDirectory)

$cargoArguments = @(
    "run",
    "-p",
    "rpackit-windows-spike",
    "--locked"
)
if ($Release) {
    $cargoArguments += "--release"
}
$cargoArguments += @(
    "--",
    "--report",
    $ReportPath
)

$fixedMode = -not [string]::IsNullOrWhiteSpace($FixedRuntimePath)
if ($fixedMode) {
    $FixedRuntimePath = (Resolve-Path -LiteralPath $FixedRuntimePath -ErrorAction Stop).Path
    $cargoArguments += @(
        "--fixed-runtime",
        $FixedRuntimePath
    )
}

$previousTargetDirectory = $env:CARGO_TARGET_DIR
try {
    $env:CARGO_TARGET_DIR = $TargetDirectory
    Push-Location $repositoryRoot
    try {
        & cargo @cargoArguments
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

if ($fixedMode) {
    if (
        -not $report.phase1_release_ready -or
        $report.runtime.mode -ne "reviewed-fixed" -or
        -not $report.runtime.fixed_runtime_identity_verified -or
        -not $report.runtime.actual_version_matches_supported_minimum -or
        -not $report.runtime.reviewed_fixed_minimum_proven
    ) {
        throw "A required reviewed fixed-runtime gate failed. Report: $ReportPath"
    }
    Write-Output "WebView2 reviewed fixed-runtime gates passed."
}
else {
    if ($report.runtime.mode -ne "development") {
        throw "The development-runtime harness reported an unexpected runtime mode."
    }
    Write-Output "WebView2 development-runtime gates passed."
}
Write-Output "Cargo target: $TargetDirectory"
Write-Output "Report: $ReportPath"
