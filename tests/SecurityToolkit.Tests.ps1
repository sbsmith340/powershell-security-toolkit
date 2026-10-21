BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..' 'SecurityToolkit' 'SecurityToolkit.psd1') -Force
    $script:AsOf = [datetime]'2026-10-21'
}

Describe 'Get-ServerSupportStatus' {
    It 'marks Server 2012 R2 unsupported' {
        (Get-ServerSupportStatus -BuildNumber 9600 -AsOf $AsOf).Status | Should -Be 'Unsupported'
    }
    It 'marks Server 2016 as expiring within a year of its end date' {
        $r = Get-ServerSupportStatus -BuildNumber 14393 -AsOf $AsOf
        $r.Status | Should -Be 'Expiring'
        $r.DaysRemaining | Should -BeGreaterThan 0
    }
    It 'marks Server 2022 supported' {
        (Get-ServerSupportStatus -BuildNumber 20348 -AsOf $AsOf).Status | Should -Be 'Supported'
    }
    It 'returns Unknown for an unrecognized build' {
        (Get-ServerSupportStatus -BuildNumber 12345 -AsOf $AsOf).Status | Should -Be 'Unknown'
    }
}

Describe 'ConvertTo-OSInventoryRecord' {
    It 'normalizes a CIM-like object and computes uptime' {
        $os = [pscustomobject]@{ Caption = 'Microsoft Windows Server 2019 Standard'; Version = '10.0.17763'; BuildNumber = '17763'; LastBootUpTime = [datetime]'2026-10-01' }
        $r = $os | ConvertTo-OSInventoryRecord -ComputerName 'SRV01' -AsOf $AsOf
        $r.Product | Should -Be 'Windows Server 2019'
        $r.SupportStatus | Should -Be 'Supported'
        $r.UptimeDays | Should -Be 20
    }
}

Describe 'Measure-DeprovisioningTime' {
    BeforeAll {
        $script:terms = @(
            [pscustomobject]@{ UserPrincipalName = 'a@contoso.com'; RequestedAt = '2026-09-01T09:00:00' }
            [pscustomobject]@{ UserPrincipalName = 'b@contoso.com'; RequestedAt = '2026-09-02T09:00:00' }
            [pscustomobject]@{ UserPrincipalName = 'c@contoso.com'; RequestedAt = '2026-09-03T09:00:00' }
        )
        $script:events = @(
            [pscustomobject]@{ UserPrincipalName = 'A@contoso.com'; DisabledAt = '2026-08-01T00:00:00' }  # before request: ignored
            [pscustomobject]@{ UserPrincipalName = 'a@contoso.com'; DisabledAt = '2026-09-01T15:00:00' }  # 6h
            [pscustomobject]@{ UserPrincipalName = 'b@contoso.com'; DisabledAt = '2026-09-04T09:00:00' }  # 48h
        )
        $script:results = Measure-DeprovisioningTime -Terminations $terms -DisableEvents $events -AsOf '2026-09-10T09:00:00'
    }
    It 'uses the first disable at or after the request, case-insensitively' {
        ($results | Where-Object UserPrincipalName -eq 'a@contoso.com').Hours | Should -Be 6
    }
    It 'flags a breach over 24 hours' {
        ($results | Where-Object UserPrincipalName -eq 'b@contoso.com').Status | Should -Be 'Breached'
    }
    It 'flags accounts never disabled' {
        $c = $results | Where-Object UserPrincipalName -eq 'c@contoso.com'
        $c.Status | Should -Be 'NotDisabled'
        $c.Hours | Should -Be 168
    }
    It 'summarizes average hours and SLA percent' {
        $s = Get-DeprovisioningSummary -Results $results
        $s.AverageHours | Should -Be 27
        $s.WithinSlaPercent | Should -Be 33.3
        $s.NotDisabled | Should -Be 1
    }
}

Describe 'Test-UserAttributeHygiene' {
    It 'reports a clean user with no issues' {
        $u = [pscustomobject]@{ UserPrincipalName = 'ok@contoso.com'; Enabled = $true; Manager = 'CN=Boss'; Title = 'Analyst'; Department = 'IT'; LastLogonDate = $AsOf.AddDays(-3); PasswordNeverExpires = $false }
        ($u | Test-UserAttributeHygiene -AsOf $AsOf).IssueCount | Should -Be 0
    }
    It 'flags missing attributes, stale logon and non-expiring password' {
        $u = [pscustomobject]@{ UserPrincipalName = 'bad@contoso.com'; Enabled = $true; Manager = ''; Title = 'Analyst'; Department = $null; LastLogonDate = $AsOf.AddDays(-200); PasswordNeverExpires = $true }
        $r = $u | Test-UserAttributeHygiene -AsOf $AsOf
        $r.Issues | Should -Be 'MissingManager;MissingDepartment;StaleLogon;PasswordNeverExpires'
    }
    It 'flags enabled accounts that never logged on' {
        $u = [pscustomobject]@{ UserPrincipalName = 'new@contoso.com'; Enabled = $true; Manager = 'x'; Title = 'x'; Department = 'x' }
        ($u | Test-UserAttributeHygiene -AsOf $AsOf).Issues | Should -Be 'NeverLoggedOn'
    }
    It 'flags disabled accounts that still have group memberships' {
        $u = [pscustomobject]@{ UserPrincipalName = 'gone@contoso.com'; Enabled = $false; MemberOf = @('CN=Finance') }
        ($u | Test-UserAttributeHygiene -AsOf $AsOf).Issues | Should -Be 'DisabledWithGroups'
    }
}
