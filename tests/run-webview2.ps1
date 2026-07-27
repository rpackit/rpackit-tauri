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

function Remove-OwnedCargoTargetDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "Refusing to remove a Cargo target reparse point."
    }
    $resolved = [System.IO.Path]::GetFullPath(
        (Resolve-Path -LiteralPath $item.FullName -ErrorAction Stop).Path
    )
    $tempRoot = [System.IO.Path]::GetFullPath(
        (Get-Item -LiteralPath (
            [System.IO.Path]::GetTempPath()
        ) -Force -ErrorAction Stop).FullName
    ).TrimEnd("\") + "\"
    $leaf = Split-Path -Leaf $resolved
    if (
        -not $resolved.StartsWith(
            $tempRoot,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not $leaf.StartsWith(
            "rpackit-webview2-cargo-",
            [System.StringComparison]::Ordinal
        )
    ) {
        throw "Refusing to remove an unverified Cargo target directory."
    }
    $attemptLimit = 30
    for ($attempt = 1; $attempt -le $attemptLimit; $attempt++) {
        try {
            [System.IO.Directory]::Delete($resolved, $true)
            return
        }
        catch [System.UnauthorizedAccessException] {
            if (-not [System.IO.Directory]::Exists($resolved)) {
                return
            }
            if ($attempt -eq $attemptLimit) {
                throw
            }
        }
        catch [System.IO.IOException] {
            if (-not [System.IO.Directory]::Exists($resolved)) {
                return
            }
            if ($attempt -eq $attemptLimit) {
                throw
            }
        }
        Start-Sleep -Seconds 1
    }
}

$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $fileName = "rpackit-webview2-$([guid]::NewGuid().ToString('N')).json"
    $ReportPath = Join-Path $env:TEMP $fileName
}
$ReportPath = [System.IO.Path]::GetFullPath($ReportPath)
$ownsTargetDirectory = $false
if ([string]::IsNullOrWhiteSpace($TargetDirectory)) {
    if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) {
        $TargetDirectory = Join-Path $env:TEMP (
            "rpackit-webview2-cargo-" + [guid]::NewGuid().ToString("N")
        )
        $ownsTargetDirectory = $true
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
    if ($ownsTargetDirectory) {
        Remove-OwnedCargoTargetDirectory -Path $TargetDirectory
    }
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
