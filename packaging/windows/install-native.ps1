[CmdletBinding()]
param(
    [string]$PackageDir = $PSScriptRoot,
    [string]$ConfigPath = (Join-Path $PackageDir 'config.yaml'),
    [string]$InstallDir = (Join-Path $env:ProgramData 'Aegis'),
    [string]$HealthURL = 'http://127.0.0.1:8080/health'
)

$ErrorActionPreference = 'Stop'
$administrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $administrator) { throw 'Run the native installer in an elevated PowerShell window.' }
$PackageDir = (Resolve-Path -LiteralPath $PackageDir).Path
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
foreach ($name in 'aegis.exe','aegisctl.exe','aegis-updater.exe') {
    $binary = Get-Item -LiteralPath (Join-Path $PackageDir $name)
    if ($binary.Length -eq 0) { throw "Empty release binary: $name" }
}
$info = & (Join-Path $PackageDir 'aegis.exe') --build-info | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $info.version -or -not $info.build_tier) { throw 'Release build information is invalid.' }
$current = Join-Path $InstallDir 'current'
if (Test-Path -LiteralPath $current) { throw 'Aegis is already installed here. Use the release updater to preserve rollback state.' }
$initial = Join-Path $InstallDir ('releases\initial-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $initial -Force | Out-Null
foreach ($name in 'aegis.exe','aegisctl.exe','aegis-updater.exe') {
    Copy-Item -LiteralPath (Join-Path $PackageDir $name) -Destination (Join-Path $initial $name)
}
Copy-Item -LiteralPath (Join-Path $PackageDir 'aegis-updater.exe') -Destination (Join-Path $InstallDir 'aegis-updater.exe')
foreach ($name in 'data','rules','web') {
    $asset = Join-Path $PackageDir $name
    if (Test-Path -LiteralPath $asset) { Copy-Item -LiteralPath $asset -Destination $InstallDir -Recurse }
}
New-Item -ItemType Directory -Path (Join-Path $InstallDir 'data'),(Join-Path $InstallDir 'logs') -Force | Out-Null
New-Item -ItemType SymbolicLink -Path $current -Target $initial | Out-Null
$yamlPath = $InstallDir.Replace("'", "''")
$updaterSettings = @"
updater:
  socket_path: '\\.\pipe\aegis-updater'
  mode: native
  state_path: '$yamlPath\updater-state.json'
  releases_root: '$yamlPath\releases'
  current_link: '$yamlPath\current'
  service_name: 'task:Aegis Server'
  health_url: '$HealthURL'
"@
$config = [IO.File]::ReadAllText($ConfigPath)
$config = [regex]::Replace($config, '(?m)^updater:[ \t]*\r?\n(?:^[ \t][^\r\n]*(?:\r?\n|$)|^\r?\n)*', '')
[IO.File]::WriteAllText((Join-Path $InstallDir 'config.yaml'), $config.TrimEnd()+"`n"+$updaterSettings+"`n")
[IO.File]::WriteAllText((Join-Path $InstallDir 'updater.yaml'), $updaterSettings+"`n")
& icacls.exe $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict installation permissions.' }
& (Join-Path $current 'aegis.exe') config check --config (Join-Path $InstallDir 'config.yaml')
if ($LASTEXITCODE -ne 0) { throw 'Correct the Aegis configuration before starting the runtime.' }
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable
$trigger = New-ScheduledTaskTrigger -AtStartup
$action = New-ScheduledTaskAction -Execute (Join-Path $current 'aegis.exe') -Argument ('run --config "'+(Join-Path $InstallDir 'config.yaml')+'"') -WorkingDirectory $InstallDir
Register-ScheduledTask -TaskName 'Aegis Server' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
$updaterAction = New-ScheduledTaskAction -Execute (Join-Path $InstallDir 'aegis-updater.exe') -Argument ('serve --config "'+(Join-Path $InstallDir 'updater.yaml')+'"') -WorkingDirectory $InstallDir
Register-ScheduledTask -TaskName 'Aegis Release Updater' -Action $updaterAction -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'Aegis Release Updater'
Start-ScheduledTask -TaskName 'Aegis Server'
Write-Host "Installed Aegis $($info.version) $($info.build_tier) in $InstallDir. Check $HealthURL before enabling traffic."
