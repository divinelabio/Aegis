[CmdletBinding()]
param(
    [string]$InstallDir = $(
        if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'aegis-updater.exe') -PathType Leaf) {
            $PSScriptRoot
        } else {
            Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        }
    ),
    [switch]$SkipAdminCheck
)

$ErrorActionPreference = 'Stop'

if (-not $SkipAdminCheck) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "Administrator privileges are required to register scheduled tasks. Please run PowerShell as Administrator."
    }
}

$updater = Join-Path $InstallDir 'aegis-updater.exe'
$config = Join-Path $InstallDir 'updater.yaml'
if (-not (Test-Path -LiteralPath $config)) { $config = Join-Path $InstallDir 'config.yaml' }
if (-not (Test-Path -LiteralPath $updater -PathType Leaf)) { throw "Missing signed updater: $updater" }
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) { throw "Missing config: $config" }

$daemonAction = New-ScheduledTaskAction -Execute $updater -Argument "serve --config `"$config`"" -WorkingDirectory $InstallDir
$daemonTrigger = New-ScheduledTaskTrigger -AtStartup
$daemonPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$daemonSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 10 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable
Register-ScheduledTask -TaskName 'Aegis Release Updater' -Action $daemonAction -Trigger $daemonTrigger -Principal $daemonPrincipal -Settings $daemonSettings -Force | Out-Null
Start-ScheduledTask -TaskName 'Aegis Release Updater'

$geoAction = New-ScheduledTaskAction -Execute $updater -Argument "geo --config `"$config`"" -WorkingDirectory $InstallDir
$geoTrigger = New-ScheduledTaskTrigger -Daily -At 3am
Register-ScheduledTask -TaskName 'Aegis GeoIP Update' -Action $geoAction -Trigger $geoTrigger -RunLevel Highest -Force | Out-Null

$proxyAction = New-ScheduledTaskAction -Execute $updater -Argument "proxies --config `"$config`"" -WorkingDirectory $InstallDir
$proxyTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddHours(1) -RepetitionInterval (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName 'Aegis Trusted Proxy Update' -Action $proxyAction -Trigger $proxyTrigger -RunLevel Highest -Force | Out-Null

Write-Host 'Aegis updater tasks installed.'
