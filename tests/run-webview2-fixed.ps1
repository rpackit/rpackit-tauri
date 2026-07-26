[CmdletBinding()]
param(
    [Parameter()]
    [string] $ReportDirectory,

    [Parameter()]
    [string] $PreparedRuntimePath,

    [Parameter()]
    [string] $TargetDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "The fixed WebView2 acceptance matrix requires Windows."
}

function Get-RpackitTreeSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Root
    )

    # GitHub-hosted Windows runners can expose TEMP through an 8.3 alias such
    # as RUNNER~1 while Get-ChildItem expands FullName to the long form. Use
    # the provider's canonical spelling on both sides before slicing relative
    # paths so the alias length cannot shift the substring boundary.
    $Root = (Get-Item -LiteralPath $Root -Force).FullName.TrimEnd("\")
    $relativePaths = [string[]](
        Get-ChildItem -LiteralPath $Root -Recurse -File |
            ForEach-Object {
                $_.FullName.Substring($Root.Length + 1).Replace("\", "/")
            }
    )
    [Array]::Sort($relativePaths, [System.StringComparer]::Ordinal)

    $hasher = [System.Security.Cryptography.IncrementalHash]::CreateHash(
        [System.Security.Cryptography.HashAlgorithmName]::SHA256
    )
    try {
        $domain = [System.Text.Encoding]::UTF8.GetBytes(
            "rpackit-webview2-tree-v1`0"
        )
        $hasher.AppendData($domain)
        $buffer = New-Object byte[] (1024 * 1024)
        foreach ($relativePath in $relativePaths) {
            $pathBytes = [System.Text.Encoding]::UTF8.GetBytes($relativePath)
            $hasher.AppendData(
                [System.BitConverter]::GetBytes([uint32] $pathBytes.Length)
            )
            $hasher.AppendData($pathBytes)
            $fullPath = Join-Path $Root $relativePath.Replace("/", "\")
            $length = (Get-Item -LiteralPath $fullPath).Length
            $hasher.AppendData(
                [System.BitConverter]::GetBytes([uint64] $length)
            )
            $stream = [System.IO.File]::OpenRead($fullPath)
            try {
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $hasher.AppendData($buffer, 0, $read)
                }
            }
            finally {
                $stream.Dispose()
            }
        }
        $digest = $hasher.GetHashAndReset()
        return [System.BitConverter]::ToString($digest).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
}

function Remove-VerifiedRuntimeWorkDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $resolved = [System.IO.Path]::GetFullPath($Path)
    $tempRoot = [System.IO.Path]::GetFullPath(
        [System.IO.Path]::GetTempPath()
    ).TrimEnd("\") + "\"
    $leaf = Split-Path -Leaf $resolved
    if (
        -not $resolved.StartsWith(
            $tempRoot,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not $leaf.StartsWith(
            "rpackit-webview2-fixed-",
            [System.StringComparison]::Ordinal
        )
    ) {
        throw "Refusing to remove an unverified runtime work directory."
    }

    # WebView2 subprocesses can release runtime DLL mappings shortly after the
    # harness process exits. Keep cleanup bounded and fail the matrix if the
    # verified temporary tree still cannot be removed after the grace period.
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
$manifestPath = Join-Path $PSScriptRoot "webview2-fixed-runtime.json"
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if (
    $manifest.schema_version -ne 1 -or
    $manifest.architecture -ne "x64" -or
    $manifest.tree_hash_algorithm -ne "rpackit-webview2-tree-v1"
) {
    throw "The reviewed fixed WebView2 manifest is invalid."
}
$archiveUri = [System.Uri] $manifest.archive_url
if (
    $archiveUri.Scheme -ne "https" -or
    $archiveUri.Host -ne "msedge.sf.dl.delivery.mp.microsoft.com" -or
    [System.IO.Path]::GetFileName($archiveUri.AbsolutePath) -ne $manifest.archive_file
) {
    throw "The reviewed fixed WebView2 source is not an approved Microsoft URL."
}

if ([string]::IsNullOrWhiteSpace($ReportDirectory)) {
    $ReportDirectory = Join-Path $env:TEMP "rpackit-webview2-fixed-evidence"
}
$ReportDirectory = [System.IO.Path]::GetFullPath($ReportDirectory)
New-Item -ItemType Directory -Force -Path $ReportDirectory | Out-Null

$workDirectory = $null
$ownsRuntime = $false
$previousProgressPreference = $ProgressPreference
try {
    if ([string]::IsNullOrWhiteSpace($PreparedRuntimePath)) {
        $workDirectory = Join-Path $env:TEMP (
            "rpackit-webview2-fixed-" + [guid]::NewGuid().ToString("N")
        )
        $archivePath = Join-Path $workDirectory $manifest.archive_file
        $extractRoot = Join-Path $workDirectory "expanded"
        New-Item -ItemType Directory -Path $extractRoot | Out-Null
        $ownsRuntime = $true
        $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest -UseBasicParsing -Uri $archiveUri -OutFile $archivePath
        $archive = Get-Item -LiteralPath $archivePath
        $archiveSha256 = (
            Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath
        ).Hash.ToLowerInvariant()
        if (
            $archive.Length -ne [long] $manifest.archive_bytes -or
            $archiveSha256 -ne $manifest.archive_sha256
        ) {
            throw "The downloaded fixed WebView2 archive failed identity verification."
        }
        & "$env:SystemRoot\System32\expand.exe" `
            $archivePath `
            "-F:*" `
            $extractRoot |
            Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "expand.exe failed with exit code $LASTEXITCODE."
        }
        $runtimePath = Join-Path $extractRoot $manifest.package_directory
    }
    else {
        $runtimePath = (
            Resolve-Path -LiteralPath $PreparedRuntimePath -ErrorAction Stop
        ).Path
    }

    $runtimePath = (
        Resolve-Path -LiteralPath $runtimePath -ErrorAction Stop
    ).Path
    if (
        (Split-Path -Leaf $runtimePath) -ne $manifest.package_directory -or
        -not (Test-Path -LiteralPath $runtimePath -PathType Container)
    ) {
        throw "The fixed WebView2 runtime root does not match the reviewed package."
    }

    $runtimeFiles = @(
        Get-ChildItem -LiteralPath $runtimePath -Recurse -File
    )
    $runtimeBytes = (
        $runtimeFiles | Measure-Object -Property Length -Sum
    ).Sum
    if (
        $runtimeFiles.Count -ne [int] $manifest.expanded_file_count -or
        $runtimeBytes -ne [long] $manifest.expanded_bytes
    ) {
        throw "The expanded fixed WebView2 runtime has an unexpected shape."
    }
    $treeSha256 = Get-RpackitTreeSha256 -Root $runtimePath
    if ($treeSha256 -ne $manifest.expanded_tree_sha256) {
        throw "The expanded fixed WebView2 runtime failed tree verification."
    }

    $runtimeExecutable = Join-Path $runtimePath $manifest.executable
    $executableSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $runtimeExecutable
    ).Hash.ToLowerInvariant()
    $fileVersion = (
        [System.Diagnostics.FileVersionInfo]::GetVersionInfo(
            $runtimeExecutable
        )
    ).FileVersion
    $signature = Get-AuthenticodeSignature -LiteralPath $runtimeExecutable
    if (
        $executableSha256 -ne $manifest.executable_sha256 -or
        $fileVersion -ne $manifest.supported_minimum_runtime -or
        $signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -ne $manifest.expected_signer_subject -or
        $signature.SignerCertificate.Thumbprint -ne $manifest.expected_signer_thumbprint
    ) {
        throw "The fixed WebView2 executable failed publisher or version verification."
    }

    $debugReport = Join-Path $ReportDirectory "webview2-fixed-debug.json"
    $releaseReport = Join-Path $ReportDirectory "webview2-fixed-release.json"
    $runner = Join-Path $PSScriptRoot "run-webview2.ps1"

    & $runner `
        -ReportPath $debugReport `
        -FixedRuntimePath $runtimePath `
        -TargetDirectory $TargetDirectory
    & $runner `
        -ReportPath $releaseReport `
        -FixedRuntimePath $runtimePath `
        -TargetDirectory $TargetDirectory `
        -Release

    $manifestSha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $manifestPath
    ).Hash.ToLowerInvariant()
    foreach ($reportPath in @($debugReport, $releaseReport)) {
        $report = Get-Content -Raw -LiteralPath $reportPath | ConvertFrom-Json
        if (
            -not $report.development_gates_passed -or
            -not $report.phase1_release_ready -or
            $report.webview2_runtime -ne $manifest.supported_minimum_runtime -or
            $report.runtime.manifest_sha256 -ne $manifestSha256 -or
            $report.runtime.archive_sha256 -ne $manifest.archive_sha256 -or
            $report.runtime.expanded_tree_sha256 -ne $manifest.expanded_tree_sha256 -or
            -not $report.runtime.reviewed_fixed_minimum_proven
        ) {
            throw "The fixed WebView2 report failed final evidence verification: $reportPath"
        }
    }

    Write-Output "WebView2 fixed-runtime debug and release matrices passed."
    Write-Output "Runtime: $($manifest.supported_minimum_runtime) $($manifest.architecture)"
    Write-Output "Reports: $ReportDirectory"
}
finally {
    $ProgressPreference = $previousProgressPreference
    if ($ownsRuntime -and $null -ne $workDirectory) {
        Remove-VerifiedRuntimeWorkDirectory -Path $workDirectory
    }
}
