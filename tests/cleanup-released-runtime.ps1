[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$WorkRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
  throw "RUNNER_TEMP is not configured."
}
if (-not (Test-Path -LiteralPath $WorkRoot)) {
  Write-Host "Released-runtime work directory is already absent."
  exit 0
}

$runnerTemp = [IO.Path]::GetFullPath(
  (Resolve-Path -LiteralPath $env:RUNNER_TEMP -ErrorAction Stop).Path
)
$workItem = Get-Item -LiteralPath $WorkRoot -Force -ErrorAction Stop
if (($workItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw "Refusing to recursively remove a reparse-point work directory."
}
$resolvedWorkRoot = [IO.Path]::GetFullPath(
  (Resolve-Path -LiteralPath $workItem.FullName -ErrorAction Stop).Path
)
$runnerPrefix = $runnerTemp.TrimEnd(
  [IO.Path]::DirectorySeparatorChar,
  [IO.Path]::AltDirectorySeparatorChar
) + [IO.Path]::DirectorySeparatorChar
if ($resolvedWorkRoot -eq $runnerTemp -or
    -not $resolvedWorkRoot.StartsWith(
      $runnerPrefix,
      [StringComparison]::OrdinalIgnoreCase
    )) {
  throw "Refusing to remove a path outside the dedicated runner temp child."
}

Remove-Item -LiteralPath $resolvedWorkRoot -Recurse -Force
if (Test-Path -LiteralPath $resolvedWorkRoot) {
  throw "Released-runtime temporary cleanup was incomplete."
}
Write-Host "Removed the complete released-runtime runner workspace."
