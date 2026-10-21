# Enforcing the AllSigned execution policy: rollout plan

## Why
`AllSigned` means PowerShell only runs scripts and modules signed by a trusted publisher. It stops casual execution of downloaded or tampered scripts, and it gives you a clear inventory of which code is approved to run.

**What it is not:** a security boundary on its own. Anyone can still type commands interactively or run `powershell -Command`/`-EncodedCommand`, and a local admin can change the policy. Pair it with:
- **Constrained Language Mode** through App Control for Business (WDAC) or AppLocker
- **Script block logging** (event 4104) and **module logging**
- The detection for encoded commands in the [KQL detection library](https://github.com/sbsmith340/kql-detection-library)

## Risk view (CIA)
| | Confidentiality | Integrity | Availability | Likelihood | Impact | Risk |
|---|---|---|---|---|---|---|
| Unsigned scripts allowed (RemoteSigned/Unrestricted) | Moderate | High | Moderate | Moderate | High | **High** |
| AllSigned + logging + CLM | Moderate | Low | Moderate* | Low | Moderate | **Low–Moderate** |

\*The availability risk shifts to the rollout itself: an unsigned script that something depends on will stop running. The phases below exist to manage that.

## Phase 0: Prerequisites (week 0)
- [ ] Code-signing certificate from the internal CA (Enhanced Key Usage: Code Signing), issued to a named signing identity, **not** a person's daily account
- [ ] Private key on a hardware token/HSM, or in a vault with access logged; only 2–3 named signers
- [ ] Timestamping URL chosen (`Set-AuthenticodeSignature -TimestampServer`) so signatures stay valid after the certificate expires
- [ ] Signer certificate distributed to **Trusted Publishers** (and its CA chain to Trusted Root) through GPO or Intune
- [ ] Change request approved, with a rollback (GPO back to `RemoteSigned`)

## Phase 1: Inventory (week 1)
Find every script that runs anywhere: scheduled tasks, GPO startup/logon scripts, Intune scripts and remediations, RMM tools, SCCM, and admin toolkits on file shares.
```powershell
Import-Module .\SecurityToolkit\SecurityToolkit.psd1
Get-ScriptSigningReport -Path \\fileserver\scripts -TrustedThumbprints <thumbprint> |
    Export-Csv .\signing-readiness.csv -NoTypeInformation
```
`ReadyForAllSigned = False` is the work list.

## Phase 2: Sign and fix (weeks 2–3)
- [ ] Sign scripts from a controlled pipeline, not ad hoc. Re-sign on every change, because any edit invalidates the signature.
- [ ] Retire scripts nobody owns
- [ ] Third-party modules from the PowerShell Gallery are often already signed. Check with `Get-AuthenticodeSignature`.
- [ ] **Intune note:** Intune platform scripts have their own "Enforce script signature check" setting, separate from the machine policy

## Phase 3: Pilot (week 4)
- [ ] GPO: *Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on Script Execution → "Allow only signed scripts"*, linked to a pilot OU (IT devices plus one server per role)
- [ ] Turn on script block logging in the same GPO
- [ ] Watch for failures: event 4104 and errors from scheduled tasks. Help desk tickets mentioning "is not digitally signed" go straight to the rollout owner.

## Phase 4: Broad rollout (weeks 5–6)
Expand in rings: workstations, then member servers, then tier-0 servers last. Hold each ring 3–5 business days.

## Phase 5: Sustain
- Signing becomes a required step in the script change process
- Track certificate expiry, with an alert 60 days before
- Run `Get-ScriptSigningReport` quarterly
- Metric: % of scripts in use that are signed by a trusted publisher (target 100%), and the count of unsigned-script execution failures (target 0 after rollout)

## Verify on an endpoint
```powershell
Get-ExecutionPolicy -List            # MachinePolicy should show AllSigned
Get-AuthenticodeSignature .\script.ps1 | Format-List Status, SignerCertificate, TimeStamperCertificate
```

## Practice it in a lab
`scripts/New-LabCodeSigningCert.ps1 -SignPath .\scripts` creates a **lab-only** self-signed signer, trusts it for the current user, and signs the toolkit. Then set `Set-ExecutionPolicy AllSigned -Scope CurrentUser` and confirm the signed scripts run and an unsigned copy is blocked.
