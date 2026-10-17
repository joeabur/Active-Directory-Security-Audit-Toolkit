# Troubleshooting

Start with the report: **Collection errors** and the **Coverage** table tell you which part failed and why. Every collection problem is classified into one of these categories.

| Category | Meaning | Section |
|---|---|---|
| `ModuleUnavailable` | The `ActiveDirectory` module is not present | [below](#the-activedirectory-module-is-missing) |
| `AccessDenied` | The account lacks permission | [below](#insufficient-permissions) |
| `Unreachable` | A domain controller or WinRM endpoint could not be contacted | [below](#a-domain-controller-is-unreachable) |
| `LdapError` | LDAP referral, filter, size or other directory error | [below](#ldap-errors) |
| `UnsupportedAttribute` | The directory rejected a requested attribute | [below](#unsupported-attributes) |
| `Skipped` | You skipped it (`-SkipDcHostChecks`, `-SkipSysvol`, `-SkipAcls`, or configuration) | not an error |
| `NotCollected` | A section is absent from an imported snapshot | [below](#snapshot-problems) |

**In every case the affected rules report `ERROR` or `NOT_ASSESSED`. They never report `PASS`.**

## The ActiveDirectory module is missing

Symptoms: every section is `NotAssessed` with category `ModuleUnavailable`; `Test-ADSAPrerequisite` shows `ActiveDirectoryModule` false and `LiveReady` false.

Fix on Windows 10/11 (elevated, one-time):

```powershell
Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
Get-Module -ListAvailable ActiveDirectory
```

On Windows Server: `Install-WindowsFeature RSAT-AD-PowerShell`. On Linux or macOS the module does not exist: collect on a Windows host, or analyse a snapshot exported from one (`-SnapshotPath`). PowerShell 7 on Windows loads the module through Windows PowerShell compatibility automatically.

## Insufficient permissions

Symptoms: a section has category `AccessDenied`; some ACL targets appear as collection warnings; fine-grained password policies are denied.

What is normal:

- **Fine-grained password policies** are readable only by Domain Admins by default. The section is supplementary; the rules do not depend on it, but the report lists the gap.
- **DC host checks** (`DcHosts`) need WinRM access and, for audit policy, local administrative rights on each DC. Without them use `-SkipDcHostChecks`.
- **SYSVOL** read access is normally granted to authenticated users; hardened environments may restrict it. GPO rules then report `ERROR` per GPO.
- **ACLs**: reading a DACL is normally allowed to authenticated users. Denied targets are listed in the collection errors and noted in the ACL rules' limitations.

Do not respond by running the audit as Domain Admin by default. Delegate the specific read rights listed under [permissions by module](security-and-limitations.md#permissions-by-module), or accept the documented gaps.

Check who you are running as and test a single query:

```powershell
whoami
Get-ADDomain -Server dc01.lab.example | Select-Object DNSRoot
```

## A domain controller is unreachable

Symptoms: `Domain controller was not reachable`/`DcHosts ... Unreachable`; every per-DC rule (`LDAP-001/002`, `DC-001`, `AUD-001/002`) shows `ERROR` for that DC. Other DCs are still assessed and rules are marked **Partial**.

Checks:

```powershell
Test-NetConnection dc01.lab.example -Port 389
Test-NetConnection dc01.lab.example -Port 9389
Test-NetConnection dc01.lab.example -Port 5985
Test-WSMan dc01.lab.example
Resolve-DnsName dc01.lab.example
```

- Ports: 389/636 (LDAP), 9389 (AD Web Services, used by the AD module), 445 (SYSVOL), 5985/5986 (WinRM for DC host checks).
- Use `-Server` to name a reachable DC when automatic discovery picks an unreachable one.
- WinRM: `Enable-PSRemoting` is a configuration change made **by your administrators on the DCs**; this toolkit never makes it.
- Across trusts or from a non-domain host, supply `-Credential` and make sure DNS resolves the domain's controllers.

## LDAP errors

| Message fragment | Likely cause | Action |
|---|---|---|
| `A referral was returned from the server` | Query reached a DC that is not authoritative; wrong `-Server` | Point `-Server` at a DC of the target domain |
| `Unable to contact the server` / `server is not operational` | Connectivity, DNS, ADWS not running | See unreachable DC checks; confirm the "Active Directory Web Services" service |
| `Size limit exceeded` | Very large result set against restrictive limits | Ask the directory team to raise `MaxPageSize`/limits for the account, or analyse in scope-limited runs |
| `The supplied credential is invalid` / `Logon failure` | Wrong credential | Re-enter with `Get-Credential`; account must be able to bind |

Raise logging detail without exposing data by setting `logging.level` to `Debug` and `logging.path` to a file in an untracked folder:

```json
{ "logging": { "level": "Debug", "path": "./output/logs/audit.log" } }
```

Logs contain section names, counts and categories, not credentials or object lists.

## Unsupported attributes

Symptom: category `UnsupportedAttribute` (message like "One or more properties are invalid"). It means an attribute requested by the collector is not in this directory's schema, which is typical for very old schema versions or for attributes your account may not read.

- The failing section is listed in the collection errors; other sections still collect.
- Dependent rules report `ERROR`.
- Open an issue with the section name and the schema version (`Get-ADObject (Get-ADRootDSE).schemaNamingContext -Properties objectVersion`). Do not edit the collector to guess.

## Snapshot problems

| Message | Meaning |
|---|---|
| `Snapshot file '...' is not valid JSON` | File truncated or edited by hand; regenerate |
| `schemaVersion ... missing or unsupported` | Not a snapshot from this toolkit version |
| `dataSource ... must be 'Live' or 'Simulated'` | Envelope field missing |
| `Snapshot is invalid: domain.name is missing` | Required envelope field missing |
| Rules report `NOT_ASSESSED` with "property was not retrieved" | The snapshot lacks an attribute the rule needs; recollect |
| Very large snapshot fails to parse on Windows PowerShell 5.1 | 5.1's JSON parser has a size limit; use PowerShell 7 for the offline analysis |

## Configuration problems

`Configuration is invalid:` lists every error at once. Common ones are covered in [configuration](configuration.md#malformed-configuration). Validate with `Test-ADSAConfig -Path <file>` before running.

## Output problems

| Message | Fix |
|---|---|
| `OutputPath is inside the tracked repository folder` | Use `./output/...` or any folder outside `src`, `docs`, `tests`, `config`, `scripts`, `examples`, `sample-data`, `.github` |
| `OutputPath is a UNC path` | Use a local encrypted folder, or add `-AllowUncOutput` deliberately |
| `OutputPath ... is an existing file` | Choose a directory |
| `BaseName ... must be a plain file name` | Remove path separators |
| `Live collection ... Re-run with -AuthorizedAssessment` | Add the switch only if you are authorized |

## Tests and lint

| Symptom | Fix |
|---|---|
| `Pester 5 is required` | `./scripts/Install-DevDependencies.ps1` |
| `Import-Module PSScriptAnalyzer` fails | Same script, or install from the gallery |
| Integration suite shows many skipped tests | Expected: the Windows-domain tests need explicit environment variables ([security and limitations](security-and-limitations.md#validation-that-needs-a-real-windows-test-domain)) |
| `Test-Documentation` reports a stale number | Re-run the demo, update the walkthrough numbers, or regenerate `docs/rule-reference.md` with `./scripts/New-RuleReference.ps1` |
