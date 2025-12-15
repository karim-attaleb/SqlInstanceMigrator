# SqlInstanceMigrator.psm1
# Final frozen version — simplified, flexible, no regressions, with summary report

$script:LogPath = $null
$script:SourceInstance = $null
$script:TargetInstance = $null
$script:ConfigPath = $null

function Initialize-MigrationLogger {
    <#
    .SYNOPSIS
        Initializes audit logging for a SQL instance migration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LogDirectory,
        [string]$OperationName = "SqlMigration",
        [string]$SourceInstance,
        [string]$TargetInstance,
        [string]$ConfigPath
    )
    $script:SourceInstance = $SourceInstance
    $script:TargetInstance = $TargetInstance
    $script:ConfigPath = $ConfigPath
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $script:LogPath = Join-Path $LogDirectory "$OperationName-$timestamp.log"
    $null = New-Item -ItemType Directory -Path $LogDirectory -Force -ErrorAction SilentlyContinue
    $audit = @"
==================================================
SQL INSTANCE MIGRATION AUDIT LOG
Timestamp:      $(Get-Date -Format 'o')
Run By:         $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
Run On:         $env:COMPUTERNAME
Source:         $SourceInstance
Target:         $TargetInstance
Config:         $ConfigPath
==================================================
"@
    Write-Host $audit -ForegroundColor Cyan
    $audit | Out-File -FilePath $script:LogPath -Encoding UTF8
}

function Write-MigrationEvent {
    <#
    .SYNOPSIS
        Writes a structured event to the migration log.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")][string]$Level = "Info"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    $color = @{ Info = 'Gray'; Success = 'Green'; Warning = 'Yellow'; Error = 'Red' }[$Level]
    Write-Host $logEntry -ForegroundColor $color
    if ($script:LogPath) { $logEntry | Out-File -FilePath $script:LogPath -Append -Encoding UTF8 }
}

function Get-SqlInstanceInventory {
    <#
    .SYNOPSIS
        Collects a complete inventory of migratable objects from a SQL Server instance.
    #>
    [CmdletBinding()]
    param([string]$SqlInstance)
    Write-MigrationEvent "Collecting inventory from $SqlInstance..." -Level Info
    $inventory = @{
        Databases        = (Get-DbaDatabase -SqlInstance $SqlInstance -ExcludeSystem).Name
        Logins           = (Get-DbaLogin -SqlInstance $SqlInstance).Name
        Credentials      = (Get-DbaCredential -SqlInstance $SqlInstance).Name
        AgentProxies     = (Get-DbaAgentProxy -SqlInstance $SqlInstance).Name
        LinkedServers    = (Get-DbaLinkedServer -SqlInstance $SqlInstance).Name
        AgentJobs        = (Get-DbaAgentJob -SqlInstance $SqlInstance).Name
        Endpoints        = (Invoke-DbaQuery -SqlInstance $SqlInstance -Query "SELECT name FROM sys.endpoints").name
        ServerTriggers   = (Invoke-DbaQuery -SqlInstance $SqlInstance -Query "SELECT name FROM sys.server_triggers").name
        Policies         = (Get-DbaPbmPolicy -SqlInstance $SqlInstance).Name
        Conditions       = (Get-DbaPbmCondition -SqlInstance $SqlInstance).Name
        RegisteredServers= (Get-DbaRegisteredServer -SqlInstance $SqlInstance).Name
        XESessions       = (Get-DbaXESession -SqlInstance $SqlInstance).Name
        Audits           = (Get-DbaAudit -SqlInstance $SqlInstance).Name
    }
    $inventory.TdeDatabases = (Get-DbaDatabase -SqlInstance $SqlInstance -ExcludeSystem | Where-Object IsEncrypted).Name
    $clrDbs = @()
    foreach ($db in $inventory.Databases) {
        try {
            $assemblies = Invoke-DbaQuery -SqlInstance $SqlInstance -Database $db -Query "SELECT TOP 1 1 FROM sys.assemblies WHERE is_user_defined = 1" -ErrorAction SilentlyContinue
            if ($assemblies) { $clrDbs += $db }
        } catch {
            Write-MigrationEvent "Warning: Could not check CLR in database '$db': $($_.Exception.Message)" -Level Warning
        }
    }
    $inventory.ClrDatabases = $clrDbs
    return $inventory
}

function Get-FilteredObjectList {
    <#
    .SYNOPSIS
        Filters a list of objects based on inclusion/exclusion rules.
    #>
    [CmdletBinding()]
    param(
        [string[]]$AllObjects,
        [string]$Mode,
        [string[]]$IncludeList,
        [string[]]$ExcludeList,
        [string]$ObjectName
    )
    if ($Mode -eq "None") { return @() }
    if ($Mode -eq "All") { return $AllObjects }
    if ($IncludeList) { return $AllObjects | Where-Object { $_ -in $IncludeList } }
    return $AllObjects | Where-Object { $_ -notin $ExcludeList }
}

function Resolve-MigrationScope {
    <#
    .SYNOPSIS
        Resolves the final set of objects to migrate based on config and inventory.
    #>
    [CmdletBinding()]
    param([hashtable]$Config, [hashtable]$Inventory)
    return @{
        Databases      = Get-FilteredObjectList -AllObjects $Inventory.Databases -Mode $Config.Databases.Mode -IncludeList $Config.Databases.IncludeList -ExcludeList $Config.Databases.ExcludeList -ObjectName "Databases"
        Logins         = Get-FilteredObjectList -AllObjects $Inventory.Logins -Mode $Config.ServerObjects.Logins.Mode -IncludeList $Config.ServerObjects.Logins.IncludeList -ExcludeList $Config.ServerObjects.Logins.ExcludeList -ObjectName "Logins"
        AgentProxies   = Get-FilteredObjectList -AllObjects $Inventory.AgentProxies -Mode $Config.ServerObjects.AgentProxies.Mode -IncludeList $Config.ServerObjects.AgentProxies.IncludeList -ExcludeList $Config.ServerObjects.AgentProxies.ExcludeList -ObjectName "AgentProxies"
        LinkedServers  = Get-FilteredObjectList -AllObjects $Inventory.LinkedServers -Mode $Config.ServerObjects.LinkedServers.Mode -IncludeList $Config.ServerObjects.LinkedServers.IncludeList -ExcludeList $Config.ServerObjects.LinkedServers.ExcludeList -ObjectName "LinkedServers"
        Policies       = Get-FilteredObjectList -AllObjects $Inventory.Policies -Mode $Config.ServerObjects.PolicyManagement.Mode -IncludeList $Config.ServerObjects.PolicyManagement.IncludeList -ExcludeList $Config.ServerObjects.PolicyManagement.ExcludeList -ObjectName "Policies"
        Conditions     = Get-FilteredObjectList -AllObjects $Inventory.Conditions -Mode $Config.ServerObjects.PolicyManagement.Mode -IncludeList $Config.ServerObjects.PolicyManagement.IncludeList -ExcludeList $Config.ServerObjects.PolicyManagement.ExcludeList -ObjectName "Conditions"
        AgentJobs      = Get-FilteredObjectList -AllObjects $Inventory.AgentJobs -Mode $Config.ServerObjects.AgentJobs.Mode -IncludeList $Config.ServerObjects.AgentJobs.IncludeList -ExcludeList $Config.ServerObjects.AgentJobs.ExcludeList -ObjectName "AgentJobs"
        Credentials    = Get-FilteredObjectList -AllObjects $Inventory.Credentials -Mode $Config.ServerObjects.Credentials.Mode -IncludeList $Config.ServerObjects.Credentials.IncludeList -ExcludeList $Config.ServerObjects.Credentials.ExcludeList -ObjectName "Credentials"
    }
}

function Invoke-MigrationStep {
    <#
    .SYNOPSIS
        Executes a single migration step with structured logging and error handling.
    #>
    [CmdletBinding()]
    param(
        [string]$StepName,
        [scriptblock]$Action,
        [string]$SuccessMessage,
        [string]$FailureHint = "Check connectivity, permissions, and object existence."
    )
    Write-MigrationEvent "Starting: $StepName" -Level Info
    try {
        & $Action
        Write-MigrationEvent $SuccessMessage -Level Success
        return $true
    } catch {
        Write-MigrationEvent "Failed: $StepName - $($_.Exception.Message)" -Level Error
        Write-MigrationEvent "Hint: $FailureHint" -Level Warning
        return $false
    }
}

function Write-MigrationSummary {
    <#
    .SYNOPSIS
        Generates a final audit table of what was migrated, skipped, and failed.
    #>
    param(
        [hashtable]$Scope,
        [hashtable]$Inventory,
        [hashtable]$Config,
        [hashtable]$Errors
    )

    Write-MigrationEvent "Generating migration summary..." -Level Info

    $report = @()
    
    # Databases
    $dbMigrated = if ($Scope.Databases) { $Scope.Databases.Count } else { 0 }
    $dbSkipped = if ($Config.Databases.Mode -eq "None") { $Inventory.Databases.Count } else { 0 }
    $dbFailed = if ($Errors.Database) { 1 } else { 0 }
    $report += [PSCustomObject]@{
        ObjectType = "Databases"
        Migrated  = $dbMigrated
        Skipped   = $dbSkipped
        Failed    = $dbFailed
    }

    # Logins
    $loginMigrated = if ($Scope.Logins) { $Scope.Logins.Count } else { 0 }
    $loginSkipped = if ($Config.ServerObjects.Logins.Mode -eq "None") { $Inventory.Logins.Count } else { 0 }
    $loginFailed = if ($Errors.Login) { 1 } else { 0 }
    $report += [PSCustomObject]@{
        ObjectType = "Logins"
        Migrated  = $loginMigrated
        Skipped   = $loginSkipped
        Failed    = $loginFailed
    }

    # Agent Proxies
    $proxyMigrated = if ($Scope.AgentProxies) { $Scope.AgentProxies.Count } else { 0 }
    $proxySkipped = if ($Config.ServerObjects.AgentProxies.Mode -eq "None") { $Inventory.AgentProxies.Count } else { 0 }
    $proxyFailed = if ($Errors.Proxy) { 1 } else { 0 }
    $report += [PSCustomObject]@{
        ObjectType = "Agent Proxies"
        Migrated  = $proxyMigrated
        Skipped   = $proxySkipped
        Failed    = $proxyFailed
    }

    # Credentials
    $credMigrated = if ($Scope.Credentials) { $Scope.Credentials.Count } else { 0 }
    $credSkipped = if ($Config.ServerObjects.Credentials.Mode -eq "None") { $Inventory.Credentials.Count } else { 0 }
    $credFailed = if ($Errors.Credential) { 1 } else { 0 }
    $report += [PSCustomObject]@{
        ObjectType = "Credentials"
        Migrated  = $credMigrated
        Skipped   = $credSkipped
        Failed    = $credFailed
    }

    # Agent Jobs
    $jobMigrated = if ($Scope.AgentJobs) { $Scope.AgentJobs.Count } else { 0 }
    $jobSkipped = if ($Config.ServerObjects.AgentJobs.Mode -eq "None") { $Inventory.AgentJobs.Count } else { 0 }
    $jobFailed = if ($Errors.Job) { 1 } else { 0 }
    $report += [PSCustomObject]@{
        ObjectType = "Agent Jobs"
        Migrated  = $jobMigrated
        Skipped   = $jobSkipped
        Failed    = $jobFailed
    }

    # Policies & Conditions
    $polMigrated = if ($Scope.Policies) { $Scope.Policies.Count } else { 0 }
    $polSkipped = if ($Config.ServerObjects.PolicyManagement.Mode -eq "None") { $Inventory.Policies.Count } else { 0 }
    $polFailed = if ($Errors.Policy) { 1 } else { 0 }
    $report += [PSCustomObject]@{
        ObjectType = "Policies & Conditions"
        Migrated  = $polMigrated
        Skipped   = $polSkipped
        Failed    = $polFailed
    }

    # TDE Certificates
    $tdeSkipped = if ($Config.DatabaseObjects.TDECertificates.Mode -eq "None") { 
        if ($Inventory.TdeDatabases) { $Inventory.TdeDatabases.Count } else { 0 } 
    } else { 0 }
    $tdeFailed = if ($Errors.Tde) { 1 } else { 0 }
    $tdeMigrated = if ($Inventory.TdeDatabases -and $tdeFailed -eq 0 -and $tdeSkipped -eq 0) { 
        $Inventory.TdeDatabases.Count 
    } else { 0 }
    $report += [PSCustomObject]@{
        ObjectType = "TDE Certificates"
        Migrated  = $tdeMigrated
        Skipped   = $tdeSkipped
        Failed    = $tdeFailed
    }

    # CLR Enablement
    $clrSkipped = if (-not $Config.DatabaseObjects.EnableClr) { 
        if ($Inventory.ClrDatabases) { 1 } else { 0 } 
    } else { 0 }
    $clrFailed = if ($Errors.Clr) { 1 } else { 0 }
    $clrMigrated = if ($Inventory.ClrDatabases -and $clrFailed -eq 0 -and $clrSkipped -eq 0) { 1 } else { 0 }
    $report += [PSCustomObject]@{
        ObjectType = "CLR Enablement"
        Migrated  = $clrMigrated
        Skipped   = $clrSkipped
        Failed    = $clrFailed
    }

    # Output table
    Write-MigrationEvent "" -Level Info
    Write-MigrationEvent "╔════════════════════════════════════════════════════╗" -Level Info
    Write-MigrationEvent "║              MIGRATION SUMMARY REPORT             ║" -Level Info
    Write-MigrationEvent "╠════════════════╦═══════════╦══════════╦══════════╣" -Level Info
    Write-MigrationEvent "║ Object Type      ║ Migrated  ║ Skipped  ║ Failed   ║" -Level Info
    Write-MigrationEvent "╠════════════════╬═══════════╬══════════╬══════════╣" -Level Info

    foreach ($row in $report) {
        $mig = if ($row.Migrated -eq 0) { "" } else { $row.Migrated.ToString() }
        $skip = if ($row.Skipped -eq 0) { "" } else { $row.Skipped.ToString() }
        $fail = if ($row.Failed -eq 0) { "" } else { "❌" }
        $line = ("║ {0,-16} ║ {1,9} ║ {2,8} ║ {3,8} ║" -f $row.ObjectType, $mig, $skip, $fail)
        if ($row.Failed -gt 0) {
            Write-MigrationEvent $line -Level Error
        } else {
            Write-MigrationEvent $line -Level Info
        }
    }

    Write-MigrationEvent "╚════════════════╩═══════════╩══════════╩══════════╝" -Level Info
    Write-MigrationEvent "" -Level Info

    $totalFailed = ($report | Measure-Object -Property Failed -Sum).Sum
    if ($totalFailed -gt 0) {
        Write-MigrationEvent "❌ Migration completed with $totalFailed failure(s). Review log for details." -Level Error
    } else {
        Write-MigrationEvent "✅ Migration completed successfully!" -Level Success
    }
}

function Start-SqlInstanceMigration {
    <#
    .SYNOPSIS
        Performs a complete, auditable, and configurable migration of a SQL Server instance.
    .DESCRIPTION
        Migrates databases, logins, agent jobs, proxies, credentials, linked servers, TDE certificates,
        CLR assemblies, Policy-Based Management, and more from a source SQL Server instance to a target.
    .PARAMETER SourceInstance
        The source SQL Server instance (e.g., "SQL01\PROD").
    .PARAMETER TargetInstance
        The target SQL Server instance (e.g., "SQL02\PROD").
    .PARAMETER SharedPath
        Required only for FreshBackup strategy. UNC path for new backups.
        Not used when MigrationStrategy.Mode = "LastBackup".
    .PARAMETER ConfigPath
        Optional path to a JSON configuration file. If omitted, uses "Config/migration-config.json".
    .PARAMETER LogPath
        Directory where audit logs are written. Default: "logs/" in current directory.
    .PARAMETER WhatIf
        Shows what would be migrated without performing any actions.
    .EXAMPLE
        Start-SqlInstanceMigration -SourceInstance "SQL01" -TargetInstance "SQL02" -SharedPath "\\backup\sql"
    .EXAMPLE
        Start-SqlInstanceMigration -SourceInstance "SQL01" -TargetInstance "SQL02" -ConfigPath ".\Config\lastbackup.json"
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$SourceInstance,
        [Parameter(Mandatory)][string]$TargetInstance,
        [string]$SharedPath,
        [string]$ConfigPath,
        [string]$LogPath = "$PSScriptRoot\..\logs",
        [switch]$WhatIf
    )

    # Load config
    if ($ConfigPath -and (Test-Path $ConfigPath)) {
        $config = Get-Content $ConfigPath | ConvertFrom-Json -AsHashtable
    } else {
        $defaultConfigPath = Join-Path $PSScriptRoot "..\Config\migration-config.json"
        if (Test-Path $defaultConfigPath) {
            $config = Get-Content $defaultConfigPath | ConvertFrom-Json -AsHashtable
        } else {
            throw "Config file not found. Provide -ConfigPath or place 'migration-config.json' in the Config/ folder."
        }
    }

    # Determine strategy with PowerShell 5.1-compatible logic
    if ($config.MigrationStrategy -and 
        $config.MigrationStrategy.Mode -and 
        $config.MigrationStrategy.Mode -is [string]) {
        $strategy = $config.MigrationStrategy.Mode
    } else {
        $strategy = "FreshBackup"
    }

    # Validate SharedPath based on strategy
    if ($strategy -eq "FreshBackup" -and (-not $SharedPath)) {
        throw "Parameter -SharedPath is required when MigrationStrategy.Mode = 'FreshBackup'"
    }

    Initialize-MigrationLogger -LogDirectory $LogPath -SourceInstance $SourceInstance -TargetInstance $TargetInstance -ConfigPath $ConfigPath

    $inventory = Get-SqlInstanceInventory -SqlInstance $SourceInstance
    Write-MigrationEvent "Inventory complete." -Level Info

    # PRE-CHECKS
    $sourceVersion = (Get-DbaInstanceProperty -SqlInstance $SourceInstance -Name ProductVersion).Value
    $targetVersion = (Get-DbaInstanceProperty -SqlInstance $TargetInstance -Name ProductVersion).Value
    if ([version]$sourceVersion -gt [version]$targetVersion) {
        $msg = "Migration blocked: Source ($sourceVersion) is newer than target ($targetVersion). SQL Server downgrades are not supported."
        Write-MigrationEvent $msg -Level Error
        throw $msg
    }
    Write-MigrationEvent "Version check passed: $sourceVersion → $targetVersion" -Level Success

    $scope = Resolve-MigrationScope -Config $config -Inventory $inventory
    if ($scope.Databases.Count -gt 0 -and $strategy -eq "FreshBackup") {
        $totalBytes = 0
        foreach ($db in $scope.Databases) {
            $dbObj = Get-DbaDatabase -SqlInstance $SourceInstance -Database $db
            $dataSize = ($dbObj.FileGroups.Files.SizeInBytes | Measure-Object -Sum).Sum
            $logSize = ($dbObj.LogFiles.SizeInBytes | Measure-Object -Sum).Sum
            $totalBytes += ($dataSize + $logSize)
        }
        $requiredGB = [math]::Round($totalBytes / 1GB, 2)
        Write-MigrationEvent "Total restore space required: $requiredGB GB" -Level Info

        $props = Get-DbaInstanceProperty -SqlInstance $TargetInstance -Name DefaultDataPath, DefaultLogPath
        $dataPath = ($props | Where-Object Name -eq "DefaultDataPath").Value
        $logPathDr = ($props | Where-Object Name -eq "DefaultLogPath").Value
        if (-not $dataPath) { $dataPath = "$env:SystemDrive\" }
        if (-not $logPathDr) { $logPathDr = "$env:SystemDrive\" }

        try {
            $dataFree = (Get-Volume -DriveLetter $dataPath.Substring(0,1) -ErrorAction Stop).SizeRemaining
            $logFree = (Get-Volume -DriveLetter $logPathDr.Substring(0,1) -ErrorAction Stop).SizeRemaining
            if ($totalBytes -gt ($dataFree + $logFree)) {
                $msg = "Insufficient disk space. Required: $requiredGB GB"
                Write-MigrationEvent $msg -Level Error
                throw $msg
            }
            Write-MigrationEvent "Disk space check passed." -Level Success
        } catch {
            Write-MigrationEvent "Warning: Could not verify free space." -Level Warning
        }
    }

    if ($WhatIf) {
        Write-MigrationEvent "WhatIf: Skipping all migration steps." -Level Warning
        return
    }

    # Initialize error tracker
    $ErrorTracker = @{
        Database   = $false
        Login      = $false
        Proxy      = $false
        Credential = $false
        Job        = $false
        Policy     = $false
        Tde        = $false
        Clr        = $false
    }

    # TDE Certificates
    if ($inventory.TdeDatabases -and $config.DatabaseObjects.TDECertificates.Mode -ne "None") {
        $success = Invoke-MigrationStep -StepName "TDE Certificate Migration" -Action {
            $certDir = Join-Path $SharedPath "certs"
            $null = New-Item -ItemType Directory -Path $certDir -Force
            $certs = Get-DbaDbCertificate -SqlInstance $SourceInstance -Database master | Where-Object UsedForTde
            foreach ($cert in $certs) {
                $name = $cert.Name
                $pwd = ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force
                $pwd | Export-Clixml (Join-Path $certDir "$name.pwd")
                (Connect-DbaInstance -SqlInstance $SourceInstance).Databases['master'].Certificates[$name].Export(
                    (Join-Path $certDir "$name.cer"),
                    (Join-Path $certDir "$name.pvk"),
                    $pwd
                )
                $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd))
                Invoke-DbaQuery -SqlInstance $TargetInstance -Database master -Query @"
CREATE CERTIFICATE [$name] FROM FILE = '$(Join-Path $certDir "$name.cer")'
WITH PRIVATE KEY (FILE = '$(Join-Path $certDir "$name.pvk")', DECRYPTION BY PASSWORD = '$plain')
"@
            }
        } -SuccessMessage "TDE certificates migrated."
        if (-not $success) { 
            $ErrorTracker.Tde = $true
            throw "TDE migration failed" 
        }
    }

    # DATABASES
    if ($scope.Databases) {
        $dbParams = @{
            Source        = $SourceInstance
            Destination   = $TargetInstance
            Database      = $scope.Databases
            WithReplace   = $true
        }

        if ($strategy -eq "LastBackup") {
            $dbParams.UseLastBackup = $true
            Write-MigrationEvent "Using last known backups from source msdb history." -Level Info
        } else {
            $dbParams.BackupRestore = $true
            $dbParams.SharedPath = $SharedPath
            if ($config.MigrationStrategy.FinalCutover -ne $false) {
                $dbParams.FinalBackup = $true
            }
            Write-MigrationEvent "Creating new backups to: $SharedPath" -Level Info
        }

        $success = Invoke-MigrationStep -StepName "Database Migration" -Action {
            Copy-DbaDatabase @dbParams
        } -SuccessMessage "Migrated databases: $($scope.Databases -join ', ')"
        if (-not $success) { 
            $ErrorTracker.Database = $true
            throw "Database migration failed" 
        }
    }

    # CREDENTIALS
    if ($scope.Credentials) {
        $success = Invoke-MigrationStep -StepName "Credential Migration" -Action {
            foreach ($c in $scope.Credentials) { Copy-DbaCredential -Source $SourceInstance -Destination $TargetInstance -Name $c -Force }
        } -SuccessMessage "Migrated credentials."
        if (-not $success) { 
            $ErrorTracker.Credential = $true
            throw "Credential migration failed" 
        }
    }

    # AGENT PROXIES
    if ($scope.AgentProxies) {
        $success = Invoke-MigrationStep -StepName "Agent Proxy Migration" -Action {
            foreach ($p in $scope.AgentProxies) { Copy-DbaAgentProxy -Source $SourceInstance -Destination $TargetInstance -Proxy $p -Force }
        } -SuccessMessage "Migrated proxies: $($scope.AgentProxies -join ', ')"
        if (-not $success) { 
            $ErrorTracker.Proxy = $true
            throw "Proxy migration failed" 
        }
    }

    # CLR
    if ($inventory.ClrDatabases -and $config.DatabaseObjects.EnableClr) {
        $clrDbs = $inventory.ClrDatabases | Where-Object { $_ -in $scope.Databases }
        if ($clrDbs) {
            $success = Invoke-MigrationStep -StepName "CLR Enablement" -Action {
                Invoke-DbaQuery -SqlInstance $TargetInstance -Query "sp_configure 'clr enabled', 1; RECONFIGURE"
            } -SuccessMessage "CLR enabled."
            if (-not $success) { 
                $ErrorTracker.Clr = $true
                throw "CLR enablement failed" 
            }
        }
    }

    # LOGINS
    if ($scope.Logins) {
        $success = Invoke-MigrationStep -StepName "Login Migration" -Action {
            Copy-DbaLogin -Source $SourceInstance -Destination $TargetInstance -Include $scope.Logins -Force
        } -SuccessMessage "Migrated logins."
        if (-not $success) { 
            $ErrorTracker.Login = $true
            throw "Login migration failed" 
        }
    }

    # AGENT JOBS
    if ($scope.AgentJobs) {
        $success = Invoke-MigrationStep -StepName "Agent Job Migration" -Action {
            Copy-DbaAgentJob -Source $SourceInstance -Destination $TargetInstance -Include $scope.AgentJobs -Force
        } -SuccessMessage "Migrated jobs."
        if (-not $success) { 
            $ErrorTracker.Job = $true
            throw "Job migration failed" 
        }
    }

    # LINKED SERVERS
    if ($scope.LinkedServers) {
        $success = Invoke-MigrationStep -StepName "Linked Server Migration" -Action {
            foreach ($ls in $scope.LinkedServers) { Copy-DbaLinkedServer -Source $SourceInstance -Destination $TargetInstance -LinkedServer $ls -Force }
        } -SuccessMessage "Migrated linked servers."
        if (-not $success) { 
            # Not tracked in summary (not in report table) but logged
            throw "Linked server migration failed" 
        }
    }

    # POLICIES
    if ($scope.Policies -and $scope.Conditions) {
        $success = Invoke-MigrationStep -StepName "Policy Migration" -Action {
            foreach ($cond in $scope.Conditions) { Copy-DbaPbmCondition -Source $SourceInstance -Destination $TargetInstance -Name $cond -Force }
            foreach ($pol in $scope.Policies) { Copy-DbaPbmPolicy -Source $SourceInstance -Destination $TargetInstance -Name $pol -Force }
        } -SuccessMessage "Migrated policies and conditions."
        if (-not $success) { 
            $ErrorTracker.Policy = $true
            throw "Policy migration failed" 
        }
    }

    # POST-MIGRATION
    if ($scope.Databases) {
        Write-MigrationEvent "Fixing orphaned users..." -Level Info
        Repair-DbaDbOrphanUser -SqlInstance $TargetInstance -Database $scope.Databases
    }

    # FINAL SUMMARY
    Write-MigrationSummary -Scope $scope -Inventory $inventory -Config $config -Errors $ErrorTracker
}

Export-ModuleMember -Function Start-SqlInstanceMigration
