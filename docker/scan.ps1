<#
.SYNOPSIS
  Windows'ta bir projeyi Docker imajıyla tarar (ör. fabrika ağındaki C# projeleri).

.EXAMPLE
  .\scan.ps1 -Path C:\Projeler\DurusMerkezi
  .\scan.ps1 -Path . -FailOn critical -Image ghcr.io/OWNER/security-toolkit:dotnet
#>
param(
  [string]$Path = ".",
  [ValidateSet("critical", "high", "medium", "low", "none")]
  [string]$FailOn = "high",
  [string]$Image = "ghcr.io/OWNER/security-toolkit:dotnet",
  [string]$Skip = ""
)

$ErrorActionPreference = "Stop"
$full = (Resolve-Path $Path).Path

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Error "Docker Desktop kurulu değil veya PATH'te değil."
}

$scanArgs = @("--fail-on", $FailOn)
if ($Skip) { $scanArgs += @("--skip", $Skip) }

docker run --rm -v "${full}:/src" $Image @scanArgs
$code = $LASTEXITCODE

$summary = Join-Path $full "security-reports\summary.md"
if (Test-Path $summary) { Write-Host "`nÖzet: $summary" }
exit $code
