#Requires -Version 5.1
<#
    SecurityToolkit
    Small, testable building blocks for common security-admin reporting tasks.
    Every function that makes a decision is pure (objects in, objects out) so it
    can be unit-tested with Pester on any OS; the scripts in ..\scripts do the
    collection from AD / Entra / CIM and call these functions.
#>

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Windows Server lifecycle (extended support end dates).
# Verify against https://learn.microsoft.com/lifecycle before relying on them.
# ---------------------------------------------------------------------------
$script:ServerLifecycle = @(
    [pscustomobject]@{ Build = 7601;  Name = 'Windows Server 2008 R2'; ExtendedEnd = [datetime]'2020-01-14' }
    [pscustomobject]@{ Build = 9200;  Name = 'Windows Server 2012';    ExtendedEnd = [datetime]'2023-10-10' }
    [pscustomobject]@{ Build = 9600;  Name = 'Windows Server 2012 R2'; ExtendedEnd = [datetime]'2023-10-10' }
    [pscustomobject]@{ Build = 14393; Name = 'Windows Server 2016';    ExtendedEnd = [datetime]'2027-01-12' }
    [pscustomobject]@{ Build = 17763; Name = 'Windows Server 2019';    ExtendedEnd = [datetime]'2029-01-09' }
    [pscustomobject]@{ Build = 20348; Name = 'Windows Server 2022';    ExtendedEnd = [datetime]'2031-10-14' }
    [pscustomobject]@{ Build = 26100; Name = 'Windows Server 2025';    ExtendedEnd = [datetime]'2034-11-14' }
)

function Get-ServerSupportStatus {
    <#
    .SYNOPSIS
        Classifies a Windows Server build as Supported, Expiring (within N days), Unsupported, or Unknown.
    .EXAMPLE
        Get-ServerSupportStatus -BuildNumber 14393 -AsOf '2026-10-21'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$BuildNumber,
        [datetime]$AsOf = (Get-Date),
        [int]$WarnDays = 365
    )
    $entry = $script:ServerLifecycle | Where-Object Build -eq $BuildNumber | Select-Object -First 1
    if (-not $entry) {
        return [pscustomobject]@{ Product = 'Unknown'; ExtendedEnd = $null; DaysRemaining = $null; Status = 'Unknown' }
    }
    $days = [int][math]::Floor(($entry.ExtendedEnd - $AsOf.Date).TotalDays)
    $status = if ($days -lt 0) { 'Unsupported' } elseif ($days -le $WarnDays) { 'Expiring' } else { 'Supported' }
    [pscustomobject]@{ Product = $entry.Name; ExtendedEnd = $entry.ExtendedEnd; DaysRemaining = $days; Status = $status }
}

function ConvertTo-OSInventoryRecord {
    <#
    .SYNOPSIS
        Normalizes a Win32_OperatingSystem CIM result (or an object with the same
        properties) into one inventory row with lifecycle status.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$OperatingSystem,
        [Parameter(Mandatory)][string]$ComputerName,
        [datetime]$AsOf = (Get-Date)
    )
    process {
        $build = [int]$OperatingSystem.BuildNumber
        $support = Get-ServerSupportStatus -BuildNumber $build -AsOf $AsOf
        $lastBoot = $OperatingSystem.LastBootUpTime
        [pscustomobject]@{
            ComputerName   = $ComputerName
            Caption        = $OperatingSystem.Caption
            Version        = $OperatingSystem.Version
            BuildNumber    = $build
            Product        = $support.Product
            SupportStatus  = $support.Status
            ExtendedEnd    = if ($support.ExtendedEnd) { $support.ExtendedEnd.ToString('yyyy-MM-dd') } else { '' }
            LastBoot       = if ($lastBoot) { ([datetime]$lastBoot).ToString('yyyy-MM-dd HH:mm') } else { '' }
            UptimeDays     = if ($lastBoot) { [int][math]::Floor(($AsOf - [datetime]$lastBoot).TotalDays) } else { $null }
            CollectionError = ''
        }
    }
}

function Measure-DeprovisioningTime {
    <#
    .SYNOPSIS
        Measures hours from a termination request to the account being disabled,
        per user, against an SLA (default 24 hours).
    .PARAMETER Terminations
        Objects with UserPrincipalName and RequestedAt (when HR/manager asked for removal).
    .PARAMETER DisableEvents
        Objects with UserPrincipalName and DisabledAt (e.g. from Entra audit
        "Disable account" / AD event 4725). The first disable at or after the
        request is used.
    .OUTPUTS
        One row per termination. Status is Met, Breached, or NotDisabled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Terminations,
        [object[]]$DisableEvents = @(),
        [double]$SlaHours = 24,
        [datetime]$AsOf = (Get-Date)
    )
    $byUser = @{}
    foreach ($e in $DisableEvents) {
        $k = ([string]$e.UserPrincipalName).ToLowerInvariant()
        if (-not $byUser.ContainsKey($k)) { $byUser[$k] = [System.Collections.Generic.List[datetime]]::new() }
        $byUser[$k].Add([datetime]$e.DisabledAt)
    }
    foreach ($t in $Terminations) {
        $upn = [string]$t.UserPrincipalName
        $requested = [datetime]$t.RequestedAt
        $candidates = @()
        if ($byUser.ContainsKey($upn.ToLowerInvariant())) {
            $candidates = @($byUser[$upn.ToLowerInvariant()] | Where-Object { $_ -ge $requested } | Sort-Object)
        }
        if ($candidates.Count -gt 0) {
            $disabled = $candidates[0]
            $hours = [math]::Round(($disabled - $requested).TotalHours, 1)
            $status = if ($hours -le $SlaHours) { 'Met' } else { 'Breached' }
        }
        else {
            $disabled = $null
            $hours = [math]::Round(($AsOf - $requested).TotalHours, 1)
            $status = 'NotDisabled'
        }
        [pscustomobject]@{
            UserPrincipalName = $upn
            RequestedAt       = $requested
            DisabledAt        = $disabled
            Hours             = $hours
            SlaHours          = $SlaHours
            Status            = $status
        }
    }
}

function Get-DeprovisioningSummary {
    <#
    .SYNOPSIS
        Rolls Measure-DeprovisioningTime output up into the leadership metric:
        average hours from termination request to deprovisioning, and % within SLA.
        NotDisabled accounts count as breaches and are excluded from the average.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object[]]$Results)
    $done = @($Results | Where-Object Status -ne 'NotDisabled')
    $met = @($Results | Where-Object Status -eq 'Met').Count
    [pscustomobject]@{
        Terminations      = $Results.Count
        Disabled          = $done.Count
        NotDisabled       = @($Results | Where-Object Status -eq 'NotDisabled').Count
        AverageHours      = if ($done.Count) { [math]::Round(($done | Measure-Object Hours -Average).Average, 1) } else { $null }
        MaxHours          = if ($done.Count) { ($done | Measure-Object Hours -Maximum).Maximum } else { $null }
        WithinSlaPercent  = if ($Results.Count) { [math]::Round(100 * $met / $Results.Count, 1) } else { $null }
    }
}

function Test-UserAttributeHygiene {
    <#
    .SYNOPSIS
        Flags identity data-quality and access-hygiene issues on user objects.
    .DESCRIPTION
        Checks enabled accounts for missing manager/title/department, stale logons,
        passwords set to never expire, and disabled accounts that still hold group
        memberships. Input objects can come from Get-ADUser, Get-MgUser, or a CSV.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]$User,
        [int]$StaleDays = 90,
        [string[]]$RequiredAttributes = @('Manager', 'Title', 'Department'),
        [datetime]$AsOf = (Get-Date)
    )
    process {
        $issues = [System.Collections.Generic.List[string]]::new()
        $enabled = [bool]$User.Enabled
        $has = { param($name) $User.PSObject.Properties.Name -contains $name -and -not [string]::IsNullOrWhiteSpace([string]$User.$name) }

        if ($enabled) {
            foreach ($attr in $RequiredAttributes) {
                if (-not (& $has $attr)) { $issues.Add("Missing$attr") }
            }
            if (& $has 'LastLogonDate') {
                if (($AsOf - [datetime]$User.LastLogonDate).TotalDays -gt $StaleDays) { $issues.Add('StaleLogon') }
            }
            else { $issues.Add('NeverLoggedOn') }
            if ($User.PSObject.Properties.Name -contains 'PasswordNeverExpires' -and [bool]$User.PasswordNeverExpires) {
                $issues.Add('PasswordNeverExpires')
            }
        }
        elseif ($User.PSObject.Properties.Name -contains 'MemberOf' -and @($User.MemberOf).Count -gt 0) {
            $issues.Add('DisabledWithGroups')
        }

        [pscustomobject]@{
            UserPrincipalName = $User.UserPrincipalName
            Enabled           = $enabled
            IssueCount        = $issues.Count
            Issues            = ($issues -join ';')
        }
    }
}

function Get-ScriptSigningReport {
    <#
    .SYNOPSIS
        Inventories .ps1/.psm1/.psd1 files under a path and reports their
        Authenticode signature status - the readiness check before enforcing
        the AllSigned execution policy.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$TrustedThumbprints = @()
    )
    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        throw 'Get-AuthenticodeSignature is only available on Windows.'
    }
    Get-ChildItem -Path $Path -Recurse -File -Include *.ps1, *.psm1, *.psd1 | ForEach-Object {
        $sig = Get-AuthenticodeSignature -FilePath $_.FullName
        $thumb = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { '' }
        [pscustomobject]@{
            File          = $_.FullName
            Status        = [string]$sig.Status
            Signer        = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
            Thumbprint    = $thumb
            TrustedSigner = ($TrustedThumbprints.Count -eq 0) -or ($TrustedThumbprints -contains $thumb)
            Timestamped   = [bool]$sig.TimeStamperCertificate
            ReadyForAllSigned = ([string]$sig.Status -eq 'Valid') -and (($TrustedThumbprints.Count -eq 0) -or ($TrustedThumbprints -contains $thumb))
        }
    }
}

Export-ModuleMember -Function Get-ServerSupportStatus, ConvertTo-OSInventoryRecord, Measure-DeprovisioningTime,
    Get-DeprovisioningSummary, Test-UserAttributeHygiene, Get-ScriptSigningReport
