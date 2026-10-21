# PowerShell Security Toolkit

> PowerShell for four recurring security-admin jobs: a server OS lifecycle inventory, a deprovisioning-speed audit against a 24-hour SLA, identity hygiene reporting, and a readiness check plus rollout plan for enforcing the **AllSigned** execution policy.

![ci](https://github.com/sbsmith340/powershell-security-toolkit/actions/workflows/ci.yml/badge.svg)
![pwsh](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-5391FE)
![data](https://img.shields.io/badge/sample%20data-fictional-blue)

## Problem
These questions come up in every audit and every leadership review:
- *Which servers are running an OS that's out of support, or about to be?*
- *When someone leaves, how long until they actually lose access?*
- *How clean is our identity data?* Missing managers break access reviews, and stale accounts are attack surface.
- *Can we require signed scripts without breaking production?*

The answers usually come from one-off scripts that nobody can test or reuse.

## What I built
A module, **`SecurityToolkit`**, where every function that makes a decision is **pure**: objects in, objects out. Each is unit-tested with Pester on any OS. Thin scripts handle the collection from AD, Entra ID, or CIM and pass the data to the module.

| Function | What it decides |
|---|---|
| `Get-ServerSupportStatus` | Supported / Expiring (≤365 days) / Unsupported, from the build number |
| `ConvertTo-OSInventoryRecord` | Normalizes `Win32_OperatingSystem` and adds lifecycle status and uptime |
| `Measure-DeprovisioningTime` | Hours from termination request to the first disable; Met / Breached / NotDisabled |
| `Get-DeprovisioningSummary` | Average hours and % within SLA, the leadership metric |
| `Test-UserAttributeHygiene` | Missing manager/title/department, stale or never-used logons, non-expiring passwords, disabled accounts still in groups |
| `Get-ScriptSigningReport` | Signature status per script and whether it's ready for AllSigned |

| Script | Does |
|---|---|
| `scripts/Invoke-ServerOSInventory.ps1` | Queries every enabled server in AD over CIM (WinRM, with DCOM fallback) and writes a CSV, **including unreachable servers and their errors**, so coverage gaps are visible |
| `scripts/Invoke-DeprovisioningAudit.ps1` | Combines HR terminations with disable events (from CSV or Entra audit logs via Graph) and reports the SLA |
| `scripts/Invoke-AttributeHygieneReport.ps1` | AD hygiene report with a count per issue type |
| `scripts/New-LabCodeSigningCert.ps1` | **Lab only**: self-signed signer to practice the AllSigned rollout |
| [`docs/AllSigned-rollout.md`](docs/AllSigned-rollout.md) | Phased plan: inventory → sign → pilot → rings → sustain, with the CIA risk view and a rollback |

## Example: deprovisioning SLA
Run against the fictional sample data in `samples/`:
```powershell
.\scripts\Invoke-DeprovisioningAudit.ps1 -TerminationsCsv .\samples\terminations.csv -DisableEventsCsv .\samples\disable-events.csv
```
```
UserPrincipalName      Hours Status
j.alvarez@contoso.com   0.80 Met
p.okafor@contoso.com   16.50 Met
r.nguyen@contoso.com   62.60 Breached     <- Friday-evening request, disabled Monday
d.harris@contoso.com   30.40 Breached
s.patel@contoso.com   272.20 NotDisabled  <- still active: escalate
...
Terminations 8 · AverageHours 16 · MaxHours 62.6 · WithinSlaPercent 62.5
```
The average alone (16 hours) looks fine against a 24-hour target. The per-user view shows the actual risks: late-week requests that wait out the weekend, and one account that was **never disabled**. Accounts that were never disabled count as SLA breaches, so they can't flatter the average.

## How to run
```powershell
git clone https://github.com/sbsmith340/powershell-security-toolkit.git
cd powershell-security-toolkit
Import-Module .\SecurityToolkit\SecurityToolkit.psd1
Invoke-Pester .\tests                       # 13 tests
.\scripts\Invoke-ServerOSInventory.ps1      # needs RSAT ActiveDirectory + WinRM to servers
```
**Permissions:** read access to AD, and WinRM/DCOM access to servers for the inventory. `AuditLog.Read.All` for the Entra option. Nothing in the toolkit writes to AD or Entra.

## Testing approach
- Decision logic is tested with Pester, using fixed `-AsOf` dates so results are deterministic
- CI runs Pester and **PSScriptAnalyzer** on every push
- Collection scripts were parse-checked. They need a domain to run end to end, so their behavior with live AD/CIM is the next lab test.

## Framework mapping
| Control | Supported by |
|---|---|
| NIST SP 800-53 **AC-2(3)** Disable accounts / **PS-4** Personnel termination | Deprovisioning audit |
| NIST SP 800-53 **CM-8** System component inventory / **SA-22** Unsupported components | Server OS inventory |
| NIST SP 800-53 **AC-2(j)** Account review / **IA-4** Identifier management | Attribute hygiene report |
| NIST SP 800-53 **CM-14** Signed components / **SI-7** Software integrity | AllSigned rollout + signing report |
| CIS Controls v8 **5.3** Disable dormant accounts | Hygiene report (StaleLogon / NeverLoggedOn) |

## Limitations & what's next
- Lifecycle dates are a built-in table. Refresh them from the Microsoft Lifecycle API, or keep them in a JSON file.
- Add an Entra ID (Graph) version of the hygiene report for cloud-only users
- Add Linux server inventory over SSH remoting
- Sign the module itself in a release pipeline once a public code-signing certificate is available

---
All names, domains, and sample records are fictional. Built by [Shawn Smith](https://sbsmith340.github.io).
