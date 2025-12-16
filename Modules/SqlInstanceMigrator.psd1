@{
    RootModule        = 'SqlInstanceMigrator.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a1b2c3d4-e5f6-7890-g1h2-i3j4k5l6m7n8'
    Author            = 'Karim Attaleb'
    Description       = 'Safe, auditable SQL Server instance migration'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Start-SqlInstanceMigration')
    PrivateData       = @{ PSData = @{ Tags = @('SQLServer', 'Migration', 'dbatools') } }
}
