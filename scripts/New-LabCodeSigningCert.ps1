#Requires -Version 5.1
<#
.SYNOPSIS
    LAB ONLY. Creates a self-signed code-signing certificate, trusts it on this
    machine, and optionally signs every script under a path - so you can
    practice the AllSigned rollout end to end without an enterprise CA.
.DESCRIPTION
    In production, request a code-signing certificate from your internal CA
    (or a public CA) and distribute trust via Group Policy / Intune. Never
    distribute a self-signed certificate's trust beyond a lab.
.EXAMPLE
    .\New-LabCodeSigningCert.ps1 -SignPath ..\scripts
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Subject = 'CN=Lab PowerShell Code Signing',
    [string]$SignPath,
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)

if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') { throw 'Code signing requires Windows.' }

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Subject -eq $Subject | Select-Object -First 1
if (-not $cert -and $PSCmdlet.ShouldProcess($Subject, 'Create self-signed code-signing certificate')) {
    $cert = New-SelfSignedCertificate -Subject $Subject -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My `
        -KeyExportPolicy NonExportable -KeyLength 3072 -NotAfter (Get-Date).AddYears(1)
    # Trust it for this user only: Root (chain) + TrustedPublisher (no prompt under AllSigned)
    foreach ($storeName in 'Root', 'TrustedPublisher') {
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, 'CurrentUser')
        $store.Open('ReadWrite'); $store.Add($cert); $store.Close()
    }
}
Write-Host "Signing certificate: $($cert.Subject)  thumbprint $($cert.Thumbprint)"

if ($SignPath) {
    Get-ChildItem $SignPath -Recurse -File -Include *.ps1, *.psm1, *.psd1 | ForEach-Object {
        if ($PSCmdlet.ShouldProcess($_.FullName, 'Sign')) {
            $r = Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $cert -TimestampServer $TimestampServer -HashAlgorithm SHA256
            '{0,-10} {1}' -f $r.Status, $_.Name
        }
    }
}
