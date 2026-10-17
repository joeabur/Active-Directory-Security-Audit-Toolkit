# Security and limitations

## Safety model

| Guarantee | How it is enforced |
|---|---|
| Read-only | The code uses `Get-AD*` queries, one fixed remote script block per DC (reads registry, a service state, `auditpol /get`, the Security log configuration) and file reads from SYSVOL. A Pester test parses every source file and fails if any state-changing cmdlet (`Set-/New-/Remove-/Add-...AD*`, `Set-GPO`, service, registry, firewall, scheduled task changes, `Invoke-Expression`, downloads) or any native tool other than `auditpol /get` appears. Mocked-AD tests also assert that write cmdlets are never invoked. |
| No credential attacks or exploitation | The toolkit contains no password guessing, hash handling, ticket requests or exploit logic. It reads configuration and reports it. Findings such as "Kerberos pre-authentication disabled" are configuration evidence only. |
| No credentials stored | Credentials are a run-time `[pscredential]` parameter. Tests fail if a parameter named like a secret has any other type, if `ConvertTo-SecureString`/`-AsPlainText`/`.Password` appear in source, or if configuration/examples/sample data contain credential-like keys. Logs redact secret-looking keys. |
| Secrets in the directory are not stored | GPP `cpassword` is detected and only the file path is recorded. User descriptions and hashes are not collected. |
| Explicit authorization | Live collection stops unless `-AuthorizedAssessment` is passed. |
| Protected output | Output paths are validated (no empty paths, no tracked repository folders, no UNC unless allowed, no existing file); files are created owner-only (`chmod 600`-equivalent on Unix, a protected ACL on Windows); `output/` and `*.snapshot.json` are git-ignored; HTML is escaped and script-free; CSV is formula-injection safe. |
| Missing access is never a pass | Failed or skipped sections yield `ERROR`/`NOT_ASSESSED`; a module crash or a silent rule yields `ERROR`; PASS requires at least one object actually evaluated. |

The remote script block is the only code that runs on domain controllers. It is a literal block in `src/Private/Collectors.ps1` (`Get-ADSADcHostData`); review it before enabling DC host checks. It runs only if you do not pass `-SkipDcHostChecks`.

## Permissions by module

"Authenticated user" means any ordinary, non-privileged domain account. **No module requires Domain Admin.**

| Module / data | Needs | Notes |
|---|---|---|
| Domain info, `AccountLifecycle`, `PrivilegedAccess`, `Delegation`, `Infrastructure` (users, computers, groups, DCs, trusts) | Authenticated user; LDAP and AD Web Services (9389) access to a DC | Standard attributes are readable by Authenticated Users by default. Hardened environments that deny-read some attributes produce `AccessDenied` or `NOT_ASSESSED` |
| Default password policy (`POL-001..006`) | Authenticated user | Default Domain Policy is readable |
| Fine-grained password policy inventory | Read on `CN=Password Settings Container` (Domain Admins by default) | Optional; denial is reported as a collection error and does not affect rules |
| `Acl` (domain root, AdminSDHolder, privileged groups, DC OU, DC objects, GPO containers) | Authenticated user able to read the security descriptor (Read permissions) | Typically allowed. Unreadable targets are listed and noted in limitations. SACLs are never read |
| `GroupPolicy` (`GPO-001..003`) | Read access to `\\<domain>\SYSVOL` over SMB (445) | Authenticated Users have it by default |
| `AuthenticationPolicy` per-DC rules (`LDAP-001/002`, `DC-001`) | WinRM (5985/5986) access to each DC with read access to `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters` and service state | Membership of local *Remote Management Users* may be insufficient for the registry/service reads; plan on a delegated read-only operator group or local administrator on DCs |
| `AUD-001` (`auditpol /get`) | Local administrative rights on each DC (audit policy requires an audit privilege) | Skip with `-SkipDcHostChecks` if you will not grant this |
| `AUD-002` (Security log size) | *Event Log Readers* or administrator on each DC | Reads log configuration, not events |
| `krbtgt` age (`KRB-001`) | Authenticated user | Reads `pwdLastSet` |

Least-privilege recommendation: run the first assessment with a standard user and `-SkipDcHostChecks`. Add DC host checks only after your DC owners approve the specific rights above. Treat the audit account as sensitive: it can read your whole directory.

The permission needs above reflect documented Windows defaults and the design of each query; they have **not** been verified against a real domain by the author (see below).

## Data handling

- Reports and snapshots contain account names, group membership, SPNs, DNs and security configuration. Treat them as sensitive, store on encrypted disks, restrict access, and delete after the engagement.
- Prefer `-Redact` when sharing. Redaction pseudonymises names in findings, evidence, inventories, collection errors and error messages, replaces the domain SID with `S-1-5-21-REDACTED`, keeps well-known names readable, and uses a random per-run salt unless `-RedactionSalt` is given. It does **not** hide counts, structure, timing, or the existence of a finding, and is not anonymisation.
- `-SaveSnapshotPath` writes the raw collection. Only use it when you must re-run offline.
- Never commit anything from `output/`.

## Limitations

1. **Selective, not exhaustive.** The toolkit does not claim to find every AD attack path. ACL coverage is limited to selected objects; delegation and group analysis cover the documented conditions; group membership of ACE principals is not expanded.
2. **Point in time, one DC.** Data is from the queried DC at collection time. `lastLogonTimestamp` lags by up to about 14 days. Recent changes may not have replicated.
3. **Configuration, not exploitability.** Findings describe configuration. They do not prove that an account is guessable or that an attack would succeed.
4. **Stale is not vulnerable.** Hygiene findings (ACC-001, 002, 008, PRV-007, PRV-008) indicate clean-up candidates only.
5. **GPO rules** read `GptTmpl.inf` settings as defined in GPOs linked to the domain root or Domain Controllers OU. They do not compute resultant policy (precedence, WMI filters, security filtering, block inheritance). Conflicts lower confidence; absent settings are `NOT_ASSESSED`.
6. **Password and lockout rules** evaluate the default domain policy only; fine-grained policies can override it.
7. **Audit policy** parsing understands English `auditpol` output only; other languages yield `NOT_ASSESSED`.
8. **LDAP signing / channel binding** read the registry values on each DC. A GPO-delivered value is reflected only if applied to the registry. Unset values are lower-confidence findings, and the Windows Server 2025 default is deliberately not asserted.
9. **Trust direction semantics** follow MS-ADTS; verify with `Get-ADTrust` before acting.
10. **Thresholds** (stale days, maximum members, baselines) are organisational choices, not standards.
11. **Windows PowerShell 5.1 JSON parser size limit** for very large offline snapshots; use PowerShell 7.
12. **Mock and simulated data prove tooling behaviour only.** They never establish the security of a real domain.

## Validation that needs a real Windows test domain

This repository was developed and tested on Linux with PowerShell 7 and mocked ActiveDirectory cmdlets. The following have **not** been validated and require a Windows test domain you are authorized to assess:

| Area | What to verify | How |
|---|---|---|
| Live collection with real `ActiveDirectory` cmdlets | Property names and types returned by `Get-ADUser/Computer/Group/DomainController/Object` match the collector assumptions (for example `LastLogonTimestamp` FILETIME handling, `PrincipalsAllowedToDelegateToAccount`) | `tests/Integration/WindowsDomain.Tests.ps1` |
| ACL reading | `nTSecurityDescriptor.GetOwner/GetAccessRules` with `SecurityIdentifier` on real objects; inheritance types; replication GUIDs | same suite, then compare with `dsacls`/ADUC for a few objects |
| Windows PowerShell 5.1 runtime | Full unit suite and a live run under 5.1 (static `PSUseCompatibleSyntax` passes, but 5.1 itself was not run) | run `./scripts/Invoke-Tests.ps1 -Suite All` in `powershell.exe` |
| DC host checks | Remote script block under WinRM: registry values, spooler state, `auditpol` CSV parsing, Security log config; required rights | set `ADSA_INTEGRATION_DCHOSTS=1` |
| SYSVOL reads | UNC access, `GptTmpl.inf` encoding, cpassword scan against real GPOs | same suite with SYSVOL enabled |
| Permission-failure behaviour with a real low-privilege account | `AccessDenied` classification and `ERROR` results | run once with an account lacking rights |
| File protection on Windows | Owner-only ACL applied to output files | inspect with `icacls` on a produced report |
| Performance on large domains | Memory and time for 100k+ objects | measure; consider scoping with `-Module` |

To run the Windows-domain suite (read-only), on a Windows host with RSAT:

```powershell
$env:ADSA_INTEGRATION_SERVER = 'dc01.lab.example'
$env:ADSA_INTEGRATION_CONFIRM = 'I-AM-AUTHORIZED-FOR-THIS-TEST-DOMAIN'
./scripts/Invoke-Tests.ps1 -Suite Integration
```

Without those variables the suite skips itself.

## Reporting vulnerabilities in the toolkit

Open a private security advisory on the repository. Include the command, PowerShell version and sanitized output.
