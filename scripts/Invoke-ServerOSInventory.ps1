#Requires -Version 5.1
<#
.SYNOPSIS
    Collects OS version, build, last boot and Microsoft lifecycle status for
    every enabled Windows Server in Active Directory, and exports a CSV.
.DESCRIPTION
    Uses CIM over WinRM (WSMan) with a DCOM fallback. Unreachable servers are
    still written to the CSV with the error, so the report shows coverage gaps
    instead of silently dropping them.
.EXAMPLE
    .\Invoke-ServerOSInventory.ps1 -OutFile .\server-os.csv
.EXAMPLE
    .\Invoke-ServerOSInventory.ps1 -ComputerName SRV01,SRV02 -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$SearchBase,
    [pscredential]$Credential,
    [string]$OutFile = ".\server-os-inventory-$(Get-Date -Format yyyyMMdd).csv",
    [int]$ThrottleLimit = 16
)

Import-Module (Join-Path $PSScriptRoot '..\SecurityToolkit\SecurityToolkit.psd1') -Force

if (-not $ComputerName) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adParams = @{ Filter = 'OperatingSystem -like "*Server*" -and Enabled -eq $true'; Properties = 'DNSHostName' }
    if ($SearchBase) { $adParams.SearchBase = $SearchBase }
    $ComputerName = Get-ADComputer @adParams | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } }
}
Write-Verbose "Querying $($ComputerName.Count) servers"

$results = foreach ($name in $ComputerName) {
    $session = $null
    try {
        $opts = @{ ComputerName = $name; ErrorAction = 'Stop'; OperationTimeoutSec = 30 }
        if ($Credential) { $opts.Credential = $Credential }
        try {
            $session = New-CimSession @opts
        }
        catch {
            $opts.SessionOption = New-CimSessionOption -Protocol Dcom
            $session = New-CimSession @opts
        }
        Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop |
            ConvertTo-OSInventoryRecord -ComputerName $name
    }
    catch {
        [pscustomobject]@{
            ComputerName = $name; Caption = ''; Version = ''; BuildNumber = $null; Product = ''
            SupportStatus = 'Unreachable'; ExtendedEnd = ''; LastBoot = ''; UptimeDays = $null
            CollectionError = $_.Exception.Message
        }
    }
    finally {
        if ($session) { Remove-CimSession $session }
    }
}

$results | Sort-Object SupportStatus, ComputerName | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8
$results | Group-Object SupportStatus | Sort-Object Name | Format-Table Name, Count -AutoSize
Write-Host "Wrote $($results.Count) rows to $OutFile"
