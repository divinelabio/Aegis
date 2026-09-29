param(
    [string]$Version = 'dev',
    [string]$OutputDir = 'dist'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = Join-Path $root $OutputDir
New-Item -ItemType Directory -Path $output -Force | Out-Null
$buildDate = (Get-Date).ToUniversalTime().ToString('o')

$hasWindres = [bool](Get-Command windres.exe -ErrorAction SilentlyContinue)

$serverSyso = Join-Path $root 'cmd/aegis-server/rsrc_windows_amd64.syso'
$updaterSyso = Join-Path $root 'cmd/aegis-updater/rsrc_windows_amd64.syso'
try {
    if ($hasWindres) {
        Write-Host "Embedding Windows version resources via windres.exe..."
        & windres.exe (Join-Path $root 'packaging/windows/aegis-server.rc') -O coff -o $serverSyso
        & windres.exe (Join-Path $root 'packaging/windows/aegis-updater.rc') -O coff -o $updaterSyso
    } else {
        Write-Warning "windres.exe not found in PATH. Building binaries without embedded PE resources."
    }
    $env:CGO_ENABLED = '0'
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $serverFlags = "-s -w -X main.Version=$Version -X main.BuildDate=$buildDate -X github.com/divinelab-io/aegis/internal/core/admin.Version=$Version -X github.com/divinelab-io/aegis/internal/core/admin.BuildDate=$buildDate"
    & go build -trimpath -ldflags $serverFlags -o (Join-Path $output 'aegis.exe') ./cmd/aegis-server
    & go build -trimpath -ldflags "-s -w -X main.Version=$Version -X main.BuildDate=$buildDate" -o (Join-Path $output 'aegis-updater.exe') ./cmd/aegis-updater
    & go build -trimpath -ldflags "-s -w -X main.Version=$Version -X main.BuildDate=$buildDate" -o (Join-Path $output 'aegisctl.exe') ./cmd/aegisctl
} finally {
    Remove-Item -LiteralPath $serverSyso,$updaterSyso -Force -ErrorAction SilentlyContinue
}

Get-FileHash (Join-Path $output '*.exe') -Algorithm SHA256 | ForEach-Object { "$($_.Hash)  $([IO.Path]::GetFileName($_.Path))" } | Set-Content (Join-Path $output 'SHA256SUMS.txt')
& node (Join-Path $root 'scripts/generate-sbom.mjs') (Join-Path $output 'sbom.cdx.json')
