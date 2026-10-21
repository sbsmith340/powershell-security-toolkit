#Requires -Version 7.0
<#
.SYNOPSIS
    Measures how quickly terminated users lose access: hours from termination
    request to account disable, against a 24-hour SLA, over the last N months.
.DESCRIPTION
    Inputs:
      -TerminationsCsv  UserPrincipalName,RequestedAt   (export from HR / ticketing)
      Disable events come from one of:
      -DisableEventsCsv UserPrincipalName,DisabledAt    (any source), or
      -FromEntraAudit   pulls "Disable account" audit events via Microsoft Graph
                        (needs Microsoft.Graph.Reports and AuditLog.Read.All).
    Note: Entra audit logs are retained 30 days (P1/P2). For a 12-month metric,
    route AuditLogs to Log Analytics / Sentinel and export from there.
.EXAMPLE
    .\Invoke-DeprovisioningAudit.ps1 -TerminationsCsv ..\samples\terminations.csv -DisableEventsCsv ..\samples\disable-events.csv
#>
[CmdletBinding(DefaultParameterSetName = 'Csv')]
param(
    [Parameter(Mandatory)][string]$TerminationsCsv,
    [Parameter(Mandatory, ParameterSetName = 'Csv')][string]$DisableEventsCsv,
    [Parameter(Mandatory, ParameterSetName = 'Entra')][switch]$FromEntraAudit,
    [int]$Months = 12,
    [double]$SlaHours = 24,
    [string]$OutFile = ".\deprovisioning-audit-$(Get-Date -Format yyyyMMdd).csv"
)

Import-Module (Join-Path $PSScriptRoot '..' 'SecurityToolkit' 'SecurityToolkit.psd1') -Force

$since = (Get-Date).AddMonths(-$Months)
$terminations = Import-Csv $TerminationsCsv | Where-Object { [datetime]$_.RequestedAt -ge $since }

if ($FromEntraAudit) {
    Import-Module Microsoft.Graph.Reports -ErrorAction Stop
    Connect-MgGraph -Scopes 'AuditLog.Read.All' -NoWelcome
    $filter = "activityDisplayName eq 'Disable account' and activityDateTime ge $($since.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    $events = Get-MgAuditLogDirectoryAudit -Filter $filter -All | ForEach-Object {
        [pscustomobject]@{
            UserPrincipalName = $_.TargetResources[0].UserPrincipalName
            DisabledAt        = $_.ActivityDateTime
        }
    }
}
else {
    $events = Import-Csv $DisableEventsCsv
}

$results = Measure-DeprovisioningTime -Terminations $terminations -DisableEvents $events -SlaHours $SlaHours
$summary = Get-DeprovisioningSummary -Results $results

$results | Sort-Object Status, Hours -Descending | Export-Csv $OutFile -NoTypeInformation -Encoding UTF8
"`nDeprovisioning SLA ($SlaHours h), last $Months months"
$summary | Format-List
$results | Where-Object Status -ne 'Met' | Sort-Object Hours -Descending |
    Format-Table UserPrincipalName, RequestedAt, DisabledAt, Hours, Status -AutoSize
Write-Host "Detail written to $OutFile"
