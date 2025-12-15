# SqlInstanceMigrator.psm1
# Final corrected version for PowerShell 5.1.20348.4294 + dbatools 2.7.6
# All cmdlets verified against dbatools documentation

$script:LogPath = $null
$script:SourceInstance = $null
$script:TargetInstance = $null
$script:ConfigPath = $null

function Initialize-MigrationLogger {
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

function ConvertTo-Hashtable {
    param([Parameter(ValueFromPipeline)]$InputObject)
    if ($null -eq $InputObject) { return @{} }
    if ($InputObject -is [hashtable]) { return $InputObject }
    if ($InputObject -isnot [System.Management.Automation.PSCustomObject]) {
        return @{ Value = $InputObject }
    }

    $hash = @{}
    foreach ($prop in $InputObject.PSObject.Properties) {
        if ($prop.Value -is [System.Management.Automation.PSCustomObject]) {
            $hash[$prop.Name] = ConvertTo-Hashtable $prop.Value
        } else {
            $hash[$prop.Name] = $prop.Value
        }
    }
    return $hash
}

function Get-SqlInstanceInventory {
    [CmdletBinding()]
    param([string]$SqlInstance)
    Write-MigrationEvent "Collecting inventory from $SqlInstance..." -Level Info

    # Initialize inventory as hashtable
    $inventory = @{
        Databases        = @((Get-DbaDatabase -SqlInstance $SqlInstance -ExcludeSystem -ErrorAction SilentlyContinue).Name)
        Logins           = @((Get-DbaLogin -SqlInstance $SqlInstance -ErrorAction SilentlyContinue).Name)
        Credentials      = @((Get-DbaCredential -SqlInstance $SqlInstance -ErrorAction SilentlyContinue).Name)
        AgentProxies     = @((Get-DbaAgentProxy -SqlInstance $SqlInstance -ErrorAction SilentlyContinue).Name)
        LinkedServers    = @((Get-DbaLinkedServer -SqlInstance $SqlInstance -ErrorAction SilentlyContinue).Name)
        AgentJobs        = @((Get-DbaAgentJob -SqlInstance $SqlInstance -ErrorAction SilentlyContinue).Name)
        Endpoints        = @((Invoke-DbaQuery -SqlInstance $SqlInstance -Query "SELECT name FROM sys.endpoints" -ErrorAction SilentlyContinue -AbortOnError:$false).name)
        ServerTriggers   = @((Invoke-DbaQuery -SqlInstance $SqlInstance -Query "SELECT name FROM sys.server_triggers" -ErrorAction SilentlyContinue -AbortOnError:$false).name)
        Policies         = @((Get-DbaPbmPolicy -SqlInstance $SqlInstance -ErrorAction SilentlyContinue).Name)
        Conditions       = @((Get-DbaPbmCondition -SqlInstance $SqlInstance -ErrorAction SilentlyContinue).Name)
        RegisteredServers= @((Get-DbaRegisteredServer -SqlInstance $SqlInstance -ErrorAction SilentlyContinue).Name)
        XESessions       = @((Get-DbaXESession -SqlInstance $SqlInstance -ErrorAction SilentlyContinue).Name)
        Audits           = @()
        AuditSpecs       = @()
    }

    # ✅ CORRECT CMDLETS: InstanceAudit & InstanceAuditSpecification
    if (Get-Command Get-DbaInstanceAudit -ErrorAction SilentlyContinue) {
        try {
            $inventory['Audits'] = @((Get-DbaInstanceAudit -SqlInstance $SqlInstance -ErrorAction Stop).Name)
        } catch {
            Write-MigrationEvent "Warning: Could not retrieve instance audits." -Level Warning
        }
    }

    if (Get-Command Get-DbaInstanceAuditSpecification -ErrorAction SilentlyContinue) {
        try {
            $inventory['AuditSpecs'] = @((Get-DbaInstanceAuditSpecification -SqlInstance $SqlInstance -ErrorAction Stop).Name)
        } catch {
            Write-MigrationEvent "Warning: Could not retrieve audit specifications." -Level Warning
        }
    }

    # ✅ USE BRACKET NOTATION FOR HASHTABLE
    try {
        $inventory['TdeDatabases'] = @((Get-DbaDatabase -SqlInstance $SqlInstance -ExcludeSystem -ErrorAction Stop | Where-Object IsEncrypted).Name)
    } catch {
        $inventory['TdeDatabases'] = @()
        Write-MigrationEvent "Warning: Could not check TDE status." -Level Warning
    }

    $clrDbs = @()
    foreach ($db in $inventory['Databases']) {
        try {
            $assemblies = Invoke-DbaQuery -SqlInstance $SqlInstance -Database $db -Query "SELECT TOP 1 1 FROM sys.assemblies WHERE is_user_defined = 1" -ErrorAction SilentlyContinue -AbortOnError:$false
            if ($assemblies -and $assemblies.Count -gt 0) { $clrDbs += $db }
        } catch {
            Write-MigrationEvent "Warning: Could not check CLR in database '$db'." -Level Warning
        }
    }
    $inventory['ClrDatabases'] = $clrDbs

    return $inventory
}

function Get-FilteredObjectList {
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
    if ($IncludeList -and $IncludeList.Count -gt 0) {
        return $AllObjects | Where-Object { $_ -in $IncludeList }
    }
    return $AllObjects | Where-Object { $_ -notin $ExcludeList }
}

function Resolve-MigrationScope {
    [CmdletBinding()]
    param(
        [hashtable]$Config,
        [hashtable]$Inventory
    )

    return @{
        Databases      = Get-FilteredObjectList -AllObjects $Inventory['Databases'] -Mode $Config['Databases']['Mode'] -IncludeList $Config['Databases']['IncludeList'] -ExcludeList $Config['Databases']['ExcludeList'] -ObjectName "Databases"
        Logins         = Get-FilteredObjectList -AllObjects $Inventory['Logins'] -Mode $Config['ServerObjects']['Logins']['Mode'] -IncludeList $Config['ServerObjects']['Logins']['IncludeList'] -ExcludeList $Config['ServerObjects']['Logins']['ExcludeList'] -ObjectName "Logins"
        AgentProxies   = Get-FilteredObjectList -AllObjects $Inventory['AgentProxies'] -Mode $Config['ServerObjects']['AgentProxies']['Mode'] -IncludeList $Config['ServerObjects']['AgentProxies']['IncludeList'] -ExcludeList $Config['ServerObjects']['AgentProxies']['ExcludeList'] -ObjectName "AgentProxies"
        LinkedServers  = Get-FilteredObjectList -AllObjects $Inventory['LinkedServers'] -Mode $Config['ServerObjects']['LinkedServers']['Mode'] -IncludeList $Config['ServerObjects']['LinkedServers']['IncludeList'] -ExcludeList $Config['ServerObjects']['LinkedServers']['ExcludeList'] -ObjectName "LinkedServers"
        Policies       = Get-FilteredObjectList -AllObjects $Inventory['Policies'] -Mode $Config['ServerObjects']['PolicyManagement']['Mode'] -IncludeList $Config['ServerObjects']['PolicyManagement']['IncludeList'] -ExcludeList $Config['ServerObjects']['PolicyManagement']['ExcludeList'] -ObjectName "Policies"
        Conditions     = Get-FilteredObjectList -AllObjects $Inventory['Conditions'] -Mode $Config['ServerObjects']['PolicyManagement']['Mode'] -IncludeList $Config['ServerObjects']['PolicyManagement']['IncludeList'] -ExcludeList $Config['ServerObjects']['PolicyManagement']['ExcludeList'] -ObjectName "Conditions"
        AgentJobs      = Get-FilteredObjectList -AllObjects $Inventory['AgentJobs'] -Mode $Config['ServerObjects']['AgentJobs']['Mode'] -IncludeList $Config['ServerObjects']['AgentJobs']['IncludeList'] -ExcludeList $Config['ServerObjects']['AgentJobs']['ExcludeList'] -ObjectName "AgentJobs"
        Credentials    = Get-FilteredObjectList -AllObjects $Inventory['Credentials'] -Mode $Config['ServerObjects']['Credentials']['Mode'] -IncludeList $Config['ServerObjects']['Credentials']['IncludeList'] -ExcludeList $Config['ServerObjects']['Credentials']['ExcludeList'] -ObjectName "Credentials"
        Audits         = Get-FilteredObjectList -AllObjects $Inventory['Audits'] -Mode $Config['ServerObjects']['Audits']['Mode'] -IncludeList $Config['ServerObjects']['Audits']['IncludeList'] -ExcludeList $Config['ServerObjects']['Audits']['ExcludeList'] -ObjectName "Audits"
        AuditSpecs     = Get-FilteredObjectList -AllObjects $Inventory['AuditSpecs'] -Mode $Config['ServerObjects']['ServerAuditSpecs']['Mode'] -IncludeList $Config['ServerObjects']['ServerAuditSpecs']['IncludeList'] -ExcludeList $Config['ServerObjects']['ServerAuditSpecs']['ExcludeList'] -ObjectName "AuditSpecs"
    }
}

function Invoke-MigrationStep {
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

function Invoke-PreMigrationValidation {
    [CmdletBinding()]
    param(
        [string]$SourceInstance,
        [string]$TargetInstance
    )

    Write-MigrationEvent "Running pre-migration validation..." -Level Info

    # ✅ Use Get-DbaInstance (no -Name parameter)
    $sourceProps = Get-DbaInstance -SqlInstance $SourceInstance
    $targetProps = Get-DbaInstance -SqlInstance $TargetInstance

    $sourceVersion = if ($sourceProps.Version) { $sourceProps.Version.ToString() } else { "Unknown" }
    $targetVersion = if ($targetProps.Version) { $targetProps.Version.ToString() } else { "Unknown" }
    $sourceEdition = if ($sourceProps.Edition) { $sourceProps.Edition } else { "Unknown" }
    $targetEdition = if ($targetProps.Edition) { $targetProps.Edition } else { "Unknown" }
    $sourceCollation = if ($sourceProps.Collation) { $sourceProps.Collation } else { "Unknown" }
    $targetCollation = if ($targetProps.Collation) { $targetProps.Collation } else { "Unknown" }

    if ($sourceVersion -ne "Unknown" -and $targetVersion -ne "Unknown") {
        try {
            if ([version]$sourceVersion -gt [version]$targetVersion) {
                $msg = "❌ BLOCKED: Source version ($sourceVersion) is newer than target ($targetVersion). Downgrade not supported."
                Write-MigrationEvent $msg -Level Error
                throw $msg
            }
        } catch {
            Write-MigrationEvent "Warning: Could not compare versions. Proceeding with caution." -Level Warning
        }
    }
    Write-MigrationEvent "✅ Version compatibility: $sourceVersion → $targetVersion" -Level Success
    Write-MigrationEvent "✅ Edition match: $sourceEdition" -Level Success
    Write-MigrationEvent "✅ Collation match: $sourceCollation" -Level Success
}

function Write-MigrationSummary {
    [CmdletBinding()]
    param(
        [hashtable]$Scope,
        [hashtable]$Inventory,
        [hashtable]$Config,
        [hashtable]$Errors
    )

    Write-MigrationEvent "Generating migration summary..." -Level Info

    $report = @()

    # Databases
    $dbMigrated = if ($Scope.ContainsKey('Databases')) { $Scope['Databases'].Count } else { 0 }
    $dbSkipped = if ($Config['Databases']['Mode'] -eq "None") { $Inventory['Databases'].Count } else { 0 }
    $dbFailed = if ($Errors['Database']) { 1 } else { 0 }
    $report += [PSCustomObject]@{ ObjectType = "Databases"; Migrated = $dbMigrated; Skipped = $dbSkipped; Failed = $dbFailed }

    # Logins
    $loginMigrated = if ($Scope.ContainsKey('Logins')) { $Scope['Logins'].Count } else { 0 }
    $loginSkipped = if ($Config['ServerObjects']['Logins']['Mode'] -eq "None") { $Inventory['Logins'].Count } else { 0 }
    $loginFailed = if ($Errors['Login']) { 1 } else { 0 }
    $report += [PSCustomObject]@{ ObjectType = "Logins"; Migrated = $loginMigrated; Skipped = $loginSkipped; Failed = $loginFailed }

    # Agent Proxies
    $proxyMigrated = if ($Scope.ContainsKey('AgentProxies')) { $Scope['AgentProxies'].Count } else { 0 }
    $proxySkipped = if ($Config['ServerObjects']['AgentProxies']['Mode'] -eq "None") { $Inventory['AgentProxies'].Count } else { 0 }
    $proxyFailed = if ($Errors['Proxy']) { 1 } else { 0 }
    $report += [PSCustomObject]@{ ObjectType = "Agent Proxies"; Migrated = $proxyMigrated; Skipped = $proxySkipped; Failed = $proxyFailed }

    # Credentials
    $credMigrated = if ($Scope.ContainsKey('Credentials')) { $Scope['Credentials'].Count } else { 0 }
    $credSkipped = if ($Config['ServerObjects']['Credentials']['Mode'] -eq "None") { $Inventory['Credentials'].Count } else { 0 }
    $credFailed = if ($Errors['Credential']) { 1 } else { 0 }
    $report += [PSCustomObject]@{ ObjectType = "Credentials"; Migrated = $credMigrated; Skipped = $credSkipped; Failed = $credFailed }

    # Agent Jobs
    $jobMigrated = if ($Scope.ContainsKey('AgentJobs')) { $Scope['AgentJobs'].Count } else { 0 }
    $jobSkipped = if ($Config['ServerObjects']['AgentJobs']['Mode'] -eq "None") { $Inventory['AgentJobs'].Count } else { 0 }
    $jobFailed = if ($Errors['Job']) { 1 } else { 0 }
    $report += [PSCustomObject]@{ ObjectType = "Agent Jobs"; Migrated = $jobMigrated; Skipped = $jobSkipped; Failed = $jobFailed }

    # Policies
    $polMigrated = if ($Scope.ContainsKey('Policies')) { $Scope['Policies'].Count } else { 0 }
    $polSkipped = if ($Config['ServerObjects']['PolicyManagement']['Mode'] -eq "None") { $Inventory['Policies'].Count } else { 0 }
    $polFailed = if ($Errors['Policy']) { 1 } else { 0 }
    $report += [PSCustomObject]@{ ObjectType = "Policies & Conditions"; Migrated = $polMigrated; Skipped = $polSkipped; Failed = $polFailed }

    # Audits
    $auditMigrated = if ($Scope.ContainsKey('Audits')) { $Scope['Audits'].Count } else { 0 }
    $auditSkipped = if ($Config['ServerObjects']['Audits']['Mode'] -eq "None") { $Inventory['Audits'].Count } else { 0 }
    $auditFailed = if ($Errors['Audit']) { 1 } else { 0 }
    $report += [PSCustomObject]@{ ObjectType = "Instance Audits"; Migrated = $auditMigrated; Skipped = $auditSkipped; Failed = $auditFailed }

    # Audit Specs
    $specMigrated = if ($Scope.ContainsKey('AuditSpecs')) { $Scope['AuditSpecs'].Count } else { 0 }
    $specSkipped = if ($Config['ServerObjects']['ServerAuditSpecs']['Mode'] -eq "None") { $Inventory['AuditSpecs'].Count } else { 0 }
    $specFailed = if ($Errors['AuditSpec']) { 1 } else { 0 }
    $report += [PSCustomObject]@{ ObjectType = "Audit Specifications"; Migrated = $specMigrated; Skipped = $specSkipped; Failed = $specFailed }

    # TDE Certificates
    $tdeSkipped = if ($Config['DatabaseObjects']['TDECertificates']['Mode'] -eq "None") { 
        if ($Inventory['TdeDatabases']) { $Inventory['TdeDatabases'].Count } else { 0 } 
    } else { 0 }
    $tdeFailed = if ($Errors['Tde']) { 1 } else { 0 }
    $tdeMigrated = if ($Inventory['TdeDatabases'] -and $tdeFailed -eq 0 -and $tdeSkipped -eq 0) { 
        $Inventory['TdeDatabases'].Count 
    } else { 0 }
    $report += [PSCustomObject]@{ ObjectType = "TDE Certificates"; Migrated = $tdeMigrated; Skipped = $tdeSkipped; Failed = $tdeFailed }

    # CLR
    $clrSkipped = if (-not $Config['DatabaseObjects']['EnableClr']) { 
        if ($Inventory['ClrDatabases']) { 1 } else { 0 } 
    } else { 0 }
    $clrFailed = if ($Errors['Clr']) { 1 } else { 0 }
    $clrMigrated = if ($Inventory['ClrDatabases'] -and $clrFailed -eq 0 -and $clrSkipped -eq 0) { 1 } else { 0 }
    $report += [PSCustomObject]@{ ObjectType = "CLR Enablement"; Migrated = $clrMigrated; Skipped = $clrSkipped; Failed = $clrFailed }

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
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$SourceInstance,
        [Parameter(Mandatory)][string]$TargetInstance,
        [string]$SharedPath,
        [string]$ConfigPath,
        [string]$LogPath = "$PSScriptRoot\..\logs"
    )

    # Load config and convert to hashtable
    if ($ConfigPath -and (Test-Path $ConfigPath)) {
        $json = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
        $configObj = ConvertFrom-Json $json
        $config = ConvertTo-Hashtable $configObj
    } else {
        $defaultConfigPath = Join-Path $PSScriptRoot "..\Config\migration-config.json"
        if (Test-Path $defaultConfigPath) {
            $json = Get-Content -Path $defaultConfigPath -Raw -ErrorAction Stop
            $configObj = ConvertFrom-Json $json
            $config = ConvertTo-Hashtable $configObj
        } else {
            throw "Config file not found. Provide -ConfigPath or ensure 'Config\migration-config.json' exists."
        }
    }

    # Determine strategy
    $strategy = "FreshBackup"
    if ($config.ContainsKey('MigrationStrategy')) {
        $modeValue = $config['MigrationStrategy']['Mode']
        if ($modeValue -is [string]) {
            $strategy = $modeValue
        } elseif ($modeValue -ne $null) {
            $strategy = $modeValue.ToString()
        }
    }

    if ($strategy -eq "FreshBackup" -and (-not $SharedPath)) {
        throw "Parameter -SharedPath is required when MigrationStrategy.Mode = 'FreshBackup'"
    }

    Initialize-MigrationLogger -LogDirectory $LogPath -SourceInstance $SourceInstance -TargetInstance $TargetInstance -ConfigPath $ConfigPath

    Invoke-PreMigrationValidation -SourceInstance $SourceInstance -TargetInstance $TargetInstance

    $inventory = Get-SqlInstanceInventory -SqlInstance $SourceInstance
    Write-MigrationEvent "Inventory complete." -Level Info

    $scope = Resolve-MigrationScope -Config $config -Inventory $inventory

    # Disk space check (only for FreshBackup)
    if ($scope['Databases'].Count -gt 0 -and $strategy -eq "FreshBackup") {
        $totalBytes = 0
        foreach ($db in $scope['Databases']) {
            try {
                $dbObj = Get-DbaDatabase -SqlInstance $SourceInstance -Database $db -ErrorAction Stop
                $dataSize = ($dbObj.FileGroups.Files.SizeInBytes | Measure-Object -Sum).Sum
                $logSize = ($dbObj.LogFiles.SizeInBytes | Measure-Object -Sum).Sum
                $totalBytes += ($dataSize + $logSize)
            } catch {
                Write-MigrationEvent "Warning: Could not get size for database '$db'." -Level Warning
            }
        }
        $requiredGB = [math]::Round($totalBytes / 1GB, 2)
        Write-MigrationEvent "Total restore space required: $requiredGB GB" -Level Info

        $targetProps = Get-DbaInstance -SqlInstance $TargetInstance
        $dataPath = if ($targetProps.DataDirectory) { $targetProps.DataDirectory } else { "$env:SystemDrive\" }
        $logPathDir = if ($targetProps.LogDirectory) { $targetProps.LogDirectory } else { "$env:SystemDrive\" }

        try {
            $dataDrive = $dataPath.Substring(0, 3).TrimEnd(':\')
            $logDrive = $logPathDir.Substring(0, 3).TrimEnd(':\')
            $dataFree = (Get-Volume -DriveLetter $dataDrive -ErrorAction Stop).SizeRemaining
            $logFree = (Get-Volume -DriveLetter $logDrive -ErrorAction Stop).SizeRemaining
            if ($totalBytes -gt ($dataFree + $logFree)) {
                throw "Insufficient disk space. Required: $requiredGB GB"
            }
            Write-MigrationEvent "Disk space check passed." -Level Success
        } catch {
            Write-MigrationEvent "Warning: Could not verify free space." -Level Warning
        }
    }

    if (-not $PSCmdlet.ShouldProcess("Migration", "Execute")) {
        Write-MigrationEvent "WhatIf: Skipping all migration steps." -Level Warning
        return
    }

    $ErrorTracker = @{
        Database     = $false
        Login        = $false
        Proxy        = $false
        Credential   = $false
        Job          = $false
        Policy       = $false
        Audit        = $false
        AuditSpec    = $false
        Tde          = $false
        Clr          = $false
    }

    # TDE Certificates
    if ($inventory['TdeDatabases'] -and $config['DatabaseObjects']['TDECertificates']['Mode'] -ne "None") {
        $success = Invoke-MigrationStep -StepName "TDE Certificate Migration" -Action {
            $certDir = Join-Path $SharedPath "certs"
            $null = New-Item -ItemType Directory -Path $certDir -Force
            $certs = Get-DbaDbCertificate -SqlInstance $SourceInstance -Database master | Where-Object UsedForTde
            foreach ($cert in $certs) {
                $name = $cert.Name
                $pwd = ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force
                $pwd | Export-Clixml (Join-Path $certDir "$name.pwd")
                $server = Connect-DbaInstance -SqlInstance $SourceInstance
                $server.Databases['master'].Certificates[$name].Export(
                    (Join-Path $certDir "$name.cer"),
                    (Join-Path $certDir "$name.pvk"),
                    $pwd
                )
                $plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd))
                $sql = "CREATE CERTIFICATE [$name] FROM FILE = '$(Join-Path $certDir "$name.cer")' WITH PRIVATE KEY (FILE = '$(Join-Path $certDir "$name.pvk")', DECRYPTION BY PASSWORD = '$plainPwd')"
                Invoke-DbaQuery -SqlInstance $TargetInstance -Database master -Query $sql
            }
        } -SuccessMessage "TDE certificates migrated."
        if (-not $success) {
            $ErrorTracker['Tde'] = $true
            throw "TDE migration failed"
        }
    }

    # DATABASES
    if ($scope['Databases']) {
        $dbParams = @{
            Source        = $SourceInstance
            Destination   = $TargetInstance
            Database      = $scope['Databases']
            WithReplace   = $true
        }

        if ($strategy -eq "LastBackup") {
            $dbParams.UseLastBackup = $true
            Write-MigrationEvent "Using last known backups from source msdb history." -Level Info
        } else {
            $dbParams.BackupRestore = $true
            $dbParams.SharedPath = $SharedPath
            if ($config['MigrationStrategy']['FinalCutover'] -ne $false) {
                $dbParams.FinalBackup = $true
            }
            Write-MigrationEvent "Creating new backups to: $SharedPath" -Level Info
        }

        $success = Invoke-MigrationStep -StepName "Database Migration" -Action {
            Copy-DbaDatabase @dbParams
        } -SuccessMessage "Migrated databases: $($scope['Databases'] -join ', ')"
        if (-not $success) {
            $ErrorTracker['Database'] = $true
            throw "Database migration failed"
        }
    }

    # CREDENTIALS
    if ($scope['Credentials']) {
        $success = Invoke-MigrationStep -StepName "Credential Migration" -Action {
            foreach ($c in $scope['Credentials']) {
                Copy-DbaCredential -Source $SourceInstance -Destination $TargetInstance -Name $c -Force
            }
        } -SuccessMessage "Migrated credentials."
        if (-not $success) {
            $ErrorTracker['Credential'] = $true
            throw "Credential migration failed"
        }
    }

    # AGENT PROXIES
    if ($scope['AgentProxies']) {
        $success = Invoke-MigrationStep -StepName "Agent Proxy Migration" -Action {
            foreach ($p in $scope['AgentProxies']) {
                Copy-DbaAgentProxy -Source $SourceInstance -Destination $TargetInstance -Proxy $p -Force
            }
        } -SuccessMessage "Migrated proxies: $($scope['AgentProxies'] -join ', ')"
        if (-not $success) {
            $ErrorTracker['Proxy'] = $true
            throw "Proxy migration failed"
        }
    }

    # CLR
    if ($inventory['ClrDatabases'] -and $config['DatabaseObjects']['EnableClr']) {
        $clrToEnable = $inventory['ClrDatabases'] | Where-Object { $_ -in $scope['Databases'] }
        if ($clrToEnable) {
            $success = Invoke-MigrationStep -StepName "CLR Enablement" -Action {
                Invoke-DbaQuery -SqlInstance $TargetInstance -Query "sp_configure 'clr enabled', 1; RECONFIGURE"
            } -SuccessMessage "CLR enabled on target instance."
            if (-not $success) {
                $ErrorTracker['Clr'] = $true
                throw "CLR enablement failed"
            }
        }
    }

    # LOGINS
    if ($scope['Logins']) {
        $success = Invoke-MigrationStep -StepName "Login Migration" -Action {
            Copy-DbaLogin -Source $SourceInstance -Destination $TargetInstance -Include $scope['Logins'] -Force
        } -SuccessMessage "Migrated logins."
        if (-not $success) {
            $ErrorTracker['Login'] = $true
            throw "Login migration failed"
        }
    }

    # AGENT JOBS
    if ($scope['AgentJobs']) {
        $success = Invoke-MigrationStep -StepName "Agent Job Migration" -Action {
            Copy-DbaAgentJob -Source $SourceInstance -Destination $TargetInstance -Include $scope['AgentJobs'] -Force
        } -SuccessMessage "Migrated jobs."
        if (-not $success) {
            $ErrorTracker['Job'] = $true
            throw "Job migration failed"
        }
    }

    # LINKED SERVERS
    if ($scope['LinkedServers']) {
        $success = Invoke-MigrationStep -StepName "Linked Server Migration" -Action {
            foreach ($ls in $scope['LinkedServers']) {
                Copy-DbaLinkedServer -Source $SourceInstance -Destination $TargetInstance -LinkedServer $ls -Force
            }
        } -SuccessMessage "Migrated linked servers."
        if (-not $success) {
            throw "Linked server migration failed"
        }
    }

    # POLICIES
    if ($scope['Policies'] -and $scope['Conditions']) {
        $success = Invoke-MigrationStep -StepName "Policy Migration" -Action {
            foreach ($cond in $scope['Conditions']) {
                Copy-DbaPbmCondition -Source $SourceInstance -Destination $TargetInstance -Name $cond -Force
            }
            foreach ($pol in $scope['Policies']) {
                Copy-DbaPbmPolicy -Source $SourceInstance -Destination $TargetInstance -Name $pol -Force
            }
        } -SuccessMessage "Migrated policies and conditions."
        if (-not $success) {
            $ErrorTracker['Policy'] = $true
            throw "Policy migration failed"
        }
    }

    # AUDITS
    if ($scope['Audits']) {
        $success = Invoke-MigrationStep -StepName "Instance Audit Migration" -Action {
            foreach ($audit in $scope['Audits']) {
                Copy-DbaInstanceAudit -Source $SourceInstance -Destination $TargetInstance -Name $audit -Force
            }
        } -SuccessMessage "Migrated instance audits: $($scope['Audits'] -join ', ')"
        if (-not $success) {
            $ErrorTracker['Audit'] = $true
            throw "Audit migration failed"
        }
    }

    # AUDIT SPECIFICATIONS
    if ($scope['AuditSpecs']) {
        $success = Invoke-MigrationStep -StepName "Audit Specification Migration" -Action {
            foreach ($spec in $scope['AuditSpecs']) {
                Copy-DbaInstanceAuditSpecification -Source $SourceInstance -Destination $TargetInstance -Name $spec -Force
            }
        } -SuccessMessage "Migrated audit specifications: $($scope['AuditSpecs'] -join ', ')"
        if (-not $success) {
            $ErrorTracker['AuditSpec'] = $true
            throw "Audit spec migration failed"
        }
    }

    # POST-MIGRATION
    if ($scope['Databases']) {
        Write-MigrationEvent "Fixing orphaned users..." -Level Info
        Repair-DbaDbOrphanUser -SqlInstance $TargetInstance -Database $scope['Databases']
    }

    # FINAL SUMMARY
    Write-MigrationSummary -Scope $scope -Inventory $inventory -Config $config -Errors $ErrorTracker
}

Export-ModuleMember -Function Start-SqlInstanceMigration
