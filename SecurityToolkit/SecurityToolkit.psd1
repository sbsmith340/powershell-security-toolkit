@{
    RootModule        = 'SecurityToolkit.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '7d3e6a2b-5c41-4f0e-9b8a-2e6c1d4f8a90'
    Author            = 'Shawn Smith'
    Description       = 'Testable building blocks for server lifecycle inventory, deprovisioning SLA measurement, identity hygiene, and script-signing readiness.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-ServerSupportStatus', 'ConvertTo-OSInventoryRecord', 'Measure-DeprovisioningTime',
                          'Get-DeprovisioningSummary', 'Test-UserAttributeHygiene', 'Get-ScriptSigningReport')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('Security', 'Inventory', 'Identity', 'CodeSigning'); ProjectUri = 'https://github.com/sbsmith340/powershell-security-toolkit' } }
}
