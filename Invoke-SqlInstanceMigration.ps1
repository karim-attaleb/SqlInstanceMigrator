<#
.SYNOPSIS
    CLI entry point for SqlInstanceMigrator.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SourceInstance,
    [Parameter(Mandatory)][string]$TargetInstance,
    [string]$SharedPath,
    [string]$ConfigPath,
    [string]$LogPath
    
)

$modulePath = Join-Path $PSScriptRoot "Modules\SqlInstanceMigrator.psd1"
Import-Module $modulePath -Force

$Params = @{
    SourceInstance = $SourceInstance
    TargetInstance = $TargetInstance
}
if ($SharedPath) { $Params.SharedPath = $SharedPath }
if ($ConfigPath) { $Params.ConfigPath = $ConfigPath }
if ($LogPath) { $Params.LogPath = $LogPath }
#if ($WhatIf) { $Params.WhatIf = $true }

Start-SqlInstanceMigration @Params
