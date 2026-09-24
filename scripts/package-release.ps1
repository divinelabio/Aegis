param(
    [string]$OutputFile = "..\aegis-community.zip"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$zipPath = [System.IO.Path]::GetFullPath((Join-Path $root $OutputFile))

if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)

$excludePrefixes = @(
    "node_modules",
    "bin",
    "dist",
    ".tmp",
    "logs",
    "scratch",
    "data/pgdata",
    "data\pgdata",
    "data/license",
    "data\license",
    "data/tls",
    "data\tls",
    ".git"
)

$excludeFiles = @(
    "aegis.env",
    "aegis.exe",
    "aegis-server.exe",
    "alerts-state.json",
    "cookies.txt",
    "test_output.txt"
)

$count = 0
Get-ChildItem -Path $root -Recurse -File | ForEach-Object {
    $relative = $_.FullName.Substring($root.Length).TrimStart('\', '/')
    $relativePosix = $relative.Replace('\', '/')

    $skip = $false
    foreach ($prefix in $excludePrefixes) {
        if ($relativePosix.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $skip = $true
            break
        }
    }
    if (-not $skip) {
        $filename = [System.IO.Path]::GetFileName($relative)
        if ($excludeFiles -contains $filename) {
            $skip = $true
        }
        if ($relativePosix -match '(?i)\.(log|out|crt|key|tmp|exe|exe~|zip|tar\.gz)$') {
            $skip = $true
        }
    }

    if (-not $skip) {
        $entryName = "aegis-community/" + $relativePosix
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $_.FullName, $entryName, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
        $count++
    }
}

$zip.Dispose()
Write-Output "Successfully packaged $count files into clean release archive: $zipPath"
