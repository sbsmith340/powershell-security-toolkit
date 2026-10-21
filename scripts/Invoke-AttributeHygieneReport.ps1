#Requires -Version 5.1
<#
.SYNOPSIS
    Reports identity hygiene issues in Active Directory: enabled users missing
    manager/title/department, stale or never-used accounts, non-expiring
    passwords, and disabled users still in groups.
.EXAMPLE
    .\Invoke-AttributeHygieneReport.ps1 -SearchBase 'OU=Staff,DC=contoso,DC=com' -StaleDays 60
#>
[CmdletBinding()]
param(
    [string]$SearchBase,
    [int]$StaleDays = 90,
    [string[]]$RequiredAttributes = @('Manager', 'Title', 'Department'),
    [string]$OutFile = ".\user-hygiene-$(Get-Date -Format yyyyMMdd).csv"
)

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '..\SecurityToolkit\SecurityToolkit.psd1') -Force

$props = @('Manager', 'Title', 'Department', 'LastLogonDate', 'PasswordNeverExpires', 'MemberOf', 'Enabled', 'UserPrincipalName') + $RequiredAttributes | Select-Object -Unique
$params = @{ Filter = '*'; Properties = $props }
if ($SearchBase) { $params.SearchBase = $SearchBase }

$report = Get-ADUser @params |
    Test-UserAttributeHygiene -StaleDays $StaleDays -RequiredAttributes $RequiredAttributes |
    Where-Object IssueCount -gt 0

$report | Sort-Object IssueCount -Descending | Export-Csv $OutFile -NoTypeInformation -Encoding UTF8
$report.Issues -split ';' | Group-Object | Sort-Object Count -Descending | Format-Table Name, Count -AutoSize
Write-Host "$($report.Count) accounts with issues written to $OutFile"
