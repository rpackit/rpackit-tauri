[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$WorkRoot,

  [Parameter(Mandatory = $true)]
  [string]$RpackitSource,

  [Parameter(Mandatory = $true)]
  [string]$ExamplesSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($env:GITHUB_ACTIONS -ne "true") {
  throw "Released-runtime preparation is restricted to GitHub Actions."
}

function Get-RequiredEnvironment {
  param([Parameter(Mandatory = $true)][string]$Name)

  $value = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($value)) {
    throw "$Name is not configured."
  }
  $value
}

function Assert-LastExitCode {
  param([Parameter(Mandatory = $true)][string]$Operation)

  if ($LASTEXITCODE -ne 0) {
    throw "$Operation failed with exit code $LASTEXITCODE."
  }
}

function Resolve-ExistingDirectory {
  param([Parameter(Mandatory = $true)][string]$Path)

  $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
  if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
    throw "Expected an existing directory."
  }
  [IO.Path]::GetFullPath($resolved)
}

$runnerTemp = Resolve-ExistingDirectory -Path (Get-RequiredEnvironment "RUNNER_TEMP")
$resolvedWorkRoot = [IO.Path]::GetFullPath($WorkRoot)
$runnerPrefix = $runnerTemp.TrimEnd(
  [IO.Path]::DirectorySeparatorChar,
  [IO.Path]::AltDirectorySeparatorChar
) + [IO.Path]::DirectorySeparatorChar
if ($resolvedWorkRoot -eq $runnerTemp -or
    -not $resolvedWorkRoot.StartsWith(
      $runnerPrefix,
      [StringComparison]::OrdinalIgnoreCase
    )) {
  throw "WorkRoot must be a dedicated child of RUNNER_TEMP."
}
if (Test-Path -LiteralPath $resolvedWorkRoot) {
  throw "The released-runtime work directory already exists."
}

$resolvedRpackitSource = Resolve-ExistingDirectory -Path $RpackitSource
$resolvedExamplesSource = Resolve-ExistingDirectory -Path $ExamplesSource
$helloShiny = Resolve-ExistingDirectory -Path (
  Join-Path $resolvedExamplesSource "hello-shiny"
)

$runtimeVersion = Get-RequiredEnvironment "RPACKIT_RUNTIME_VERSION"
$runtimeUrl = Get-RequiredEnvironment "RPACKIT_RUNTIME_URL"
$runtimeSha256 = (
  Get-RequiredEnvironment "RPACKIT_RUNTIME_SHA256"
).ToLowerInvariant()
$runtimeHomeName = Get-RequiredEnvironment "RPACKIT_RUNTIME_HOME"
if ($runtimeSha256 -notmatch "^[0-9a-f]{64}$") {
  throw "RPACKIT_RUNTIME_SHA256 is malformed."
}
if ($runtimeUrl -notmatch "^https://github[.]com/rpackit/runtime-win/releases/") {
  throw "The runtime URL is outside the reviewed GitHub Release."
}
if ($runtimeHomeName -notmatch "^[A-Za-z0-9._-]+$") {
  throw "RPACKIT_RUNTIME_HOME is malformed."
}

$null = New-Item -ItemType Directory -Path $resolvedWorkRoot
$archivePath = Join-Path $resolvedWorkRoot "portable-r.zip"
$extractRoot = Join-Path $resolvedWorkRoot "released runtime"
$bundlePath = Join-Path $resolvedWorkRoot "hello-shiny bundle"
$systemLibrary = Join-Path $resolvedWorkRoot "system R library"
$rTemp = Join-Path $resolvedWorkRoot "rtemp"
$evidenceDirectory = Join-Path $resolvedWorkRoot "evidence"
$bundleEvidence = Join-Path $evidenceDirectory "bundle-provenance.json"
$sessionParent = Join-Path $resolvedWorkRoot "private sessions"
$hostileProfile = Join-Path $resolvedWorkRoot "hostile ambient profile.R"
$hostileEnvironment = Join-Path $resolvedWorkRoot "hostile ambient Renviron"

foreach ($directory in @(
  $extractRoot,
  $systemLibrary,
  $rTemp,
  $evidenceDirectory,
  $sessionParent
)) {
  $null = New-Item -ItemType Directory -Path $directory
}

Invoke-WebRequest -Uri $runtimeUrl -OutFile $archivePath
$actualSha256 = (
  Get-FileHash -LiteralPath $archivePath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($actualSha256 -cne $runtimeSha256) {
  throw "The released portable-R archive failed SHA-256 verification."
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($archivePath)
try {
  $extractPrefix = [IO.Path]::GetFullPath($extractRoot).TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
  ) + [IO.Path]::DirectorySeparatorChar
  $entryPrefix = "$runtimeHomeName/"
  foreach ($entry in $archive.Entries) {
    $entryName = $entry.FullName.Replace("\", "/")
    if (-not $entryName.StartsWith(
      $entryPrefix,
      [StringComparison]::Ordinal
    )) {
      throw "The runtime archive contains an unexpected top-level entry."
    }
    $entryTarget = [IO.Path]::GetFullPath(
      (Join-Path $extractRoot $entry.FullName)
    )
    if (-not $entryTarget.StartsWith(
      $extractPrefix,
      [StringComparison]::OrdinalIgnoreCase
    )) {
      throw "The runtime archive contains an escaping path."
    }
  }
}
finally {
  $archive.Dispose()
}

Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot
$runtimeHome = Resolve-ExistingDirectory -Path (
  Join-Path $extractRoot $runtimeHomeName
)
$bundledRscript = Join-Path $runtimeHome "bin\Rscript.exe"
if (-not (Test-Path -LiteralPath $bundledRscript -PathType Leaf)) {
  throw "The verified runtime did not contain bin\Rscript.exe."
}

$rscriptCommand = Get-Command "Rscript.exe" -CommandType Application |
  Select-Object -First 1
$rCommand = Get-Command "R.exe" -CommandType Application |
  Select-Object -First 1
if ($null -eq $rscriptCommand -or $null -eq $rCommand) {
  throw "System R was not available after setup-r."
}
$env:RPACKIT_GATE_SYSTEM_LIBRARY = $systemLibrary
$env:R_LIBS_USER = $systemLibrary
$env:TEMP = $rTemp
$env:TMP = $rTemp
$env:TMPDIR = $rTemp

$installExpression = @'
library_path <- Sys.getenv("RPACKIT_GATE_SYSTEM_LIBRARY")
packages <- c("cli", "digest", "jsonlite", "openssl", "processx", "ps", "zip")
options(timeout = 600)
install.packages(
  packages,
  lib = library_path,
  repos = c(CRAN = Sys.getenv("RPACKIT_CRAN_REPOSITORY")),
  dependencies = NA
)
missing <- setdiff(packages, rownames(installed.packages(lib.loc = library_path)))
if (length(missing)) {
  stop("System-R dependency preparation was incomplete.", call. = FALSE)
}
'@
& $rscriptCommand.Source --vanilla -e $installExpression
Assert-LastExitCode -Operation "System-R dependency preparation"

& $rCommand.Source CMD INSTALL "--library=$systemLibrary" $resolvedRpackitSource
Assert-LastExitCode -Operation "Pinned rpackit installation"

$prepareScript = Join-Path $PSScriptRoot "prepare-released-runtime.R"
& $rscriptCommand.Source --vanilla $prepareScript `
  $helloShiny `
  $runtimeHome `
  $bundlePath `
  $bundleEvidence
Assert-LastExitCode -Operation "Released hello-shiny bundle preparation"

@(
  "marker <- Sys.getenv('RPACKIT_PROFILE_MARKER')",
  "if (nzchar(marker)) writeLines('executed', marker)",
  "stop('Ambient R profile executed', call. = FALSE)"
) | Set-Content -LiteralPath $hostileProfile -Encoding ASCII
@(
  "RPACKIT_SESSION_TOKEN=ambient-legacy-token-must-not-survive",
  "R_LIBS_USER=Z:/rpackit-invalid-ambient-library"
) | Set-Content -LiteralPath $hostileEnvironment -Encoding ASCII

foreach ($requiredPath in @(
  $bundlePath,
  $bundleEvidence,
  $sessionParent,
  $hostileProfile,
  $hostileEnvironment
)) {
  if (-not (Test-Path -LiteralPath $requiredPath)) {
    throw "Released-runtime preparation omitted a required gate input."
  }
}

Write-Host "Prepared verified portable R $runtimeVersion in runner-scoped temporary storage."
