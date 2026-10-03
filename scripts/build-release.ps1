param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$')]
    [string]$Version,
    [string]$OutputDir = 'dist'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$Version = $Version.TrimStart('v')
$output = Join-Path $root $OutputDir
New-Item -ItemType Directory -Path $output -Force | Out-Null
$buildDate = (Get-Date).ToUniversalTime().ToString('o')

$hasWindres = [bool](Get-Command windres.exe -ErrorAction SilentlyContinue)

$serverSyso = Join-Path $root 'cmd/aegis-server/rsrc_windows_amd64.syso'
$updaterSyso = Join-Path $root 'cmd/aegis-updater/rsrc_windows_amd64.syso'
$savedBuildEnv = @{}
foreach ($name in @('CGO_ENABLED', 'GOOS', 'GOARCH')) { $savedBuildEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$generatedResources = @()
function New-VersionResource {
    param([string]$Template, [string]$Destination)
    $coreVersion = ($Version -split '[-+]')[0].Split('.')
    foreach ($part in $coreVersion) {
        if ([System.Numerics.BigInteger]::Parse($part) -gt 65535) { throw 'Windows PE version components must not exceed 65535.' }
    }
    $numericVersion = ($coreVersion -join ',') + ',0'
    $content = Get-Content -Raw -LiteralPath $Template
    $content = $content -replace '(?m)^FILEVERSION .*$', "FILEVERSION $numericVersion"
    $content = $content -replace '(?m)^PRODUCTVERSION .*$', "PRODUCTVERSION $numericVersion"
    $content = $content -replace '(VALUE "(?:FileVersion|ProductVersion)", ")[^"\r\n]*', ('${1}' + $Version + '\0')
    Set-Content -LiteralPath $Destination -Value $content -Encoding ascii
}
Push-Location $root
try {
    if ($hasWindres) {
        if ((Test-Path -LiteralPath $serverSyso) -or (Test-Path -LiteralPath $updaterSyso)) { throw 'Existing Windows resource files must be preserved; remove or move them before a release build.' }
        $serverResource = Join-Path $output ("server-$([guid]::NewGuid()).rc")
        $updaterResource = Join-Path $output ("updater-$([guid]::NewGuid()).rc")
        $generatedResources += @($serverResource, $updaterResource)
        New-VersionResource -Template (Join-Path $root 'packaging/windows/aegis-server.rc') -Destination $serverResource
        New-VersionResource -Template (Join-Path $root 'packaging/windows/aegis-updater.rc') -Destination $updaterResource
        Write-Host "Embedding Windows version resources via windres.exe..."
        & windres.exe $serverResource -O coff -o $serverSyso
        $generatedResources += $serverSyso
        if ($LASTEXITCODE -ne 0) { throw 'Server Windows resource build failed.' }
        & windres.exe $updaterResource -O coff -o $updaterSyso
        $generatedResources += $updaterSyso
        if ($LASTEXITCODE -ne 0) { throw 'Updater Windows resource build failed.' }
    } else {
        Write-Warning "windres.exe not found in PATH. Building binaries without embedded PE resources."
    }
    $env:CGO_ENABLED = '0'
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $serverFlags = "-s -w -X main.Version=$Version -X main.BuildDate=$buildDate -X github.com/divinelabio/aegis/internal/core/admin.Version=$Version -X github.com/divinelabio/aegis/internal/core/admin.BuildDate=$buildDate"
    & go build -buildvcs=false -trimpath -ldflags $serverFlags -o (Join-Path $output 'aegis.exe') ./cmd/aegis-server
    if ($LASTEXITCODE -ne 0) { throw 'Server release build failed.' }
    & go build -buildvcs=false -trimpath -ldflags "-s -w -X main.Version=$Version -X main.BuildDate=$buildDate" -o (Join-Path $output 'aegis-updater.exe') ./cmd/aegis-updater
    if ($LASTEXITCODE -ne 0) { throw 'Updater release build failed.' }
    & go build -buildvcs=false -trimpath -ldflags "-s -w -X main.Version=$Version -X main.BuildDate=$buildDate" -o (Join-Path $output 'aegisctl.exe') ./cmd/aegisctl
    if ($LASTEXITCODE -ne 0) { throw 'CLI release build failed.' }
} finally {
    foreach ($resource in $generatedResources) { Remove-Item -LiteralPath $resource -Force -ErrorAction SilentlyContinue }
    foreach ($name in $savedBuildEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $savedBuildEnv[$name], 'Process') }
    Pop-Location
}

Get-FileHash (Join-Path $output '*.exe') -Algorithm SHA256 | ForEach-Object { "$($_.Hash)  $([IO.Path]::GetFileName($_.Path))" } | Set-Content (Join-Path $output 'SHA256SUMS.txt')
Push-Location $root
try {
    & node (Join-Path $root 'scripts/generate-sbom.mjs') (Join-Path $output 'sbom.cdx.json')
    if ($LASTEXITCODE -ne 0) { throw 'Release SBOM generation failed.' }
} finally { Pop-Location }
