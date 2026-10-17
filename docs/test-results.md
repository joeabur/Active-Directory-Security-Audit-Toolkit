# Test results

These are the **actual results recorded when this documentation was written**, plus an explicit list of what has *not* been validated. Re-run the commands to reproduce.

## Environment used

| Item | Value |
|---|---|
| OS | Ubuntu 24.04 (Linux), no Active Directory domain, no network path to one |
| PowerShell | 7.4.6 (Core) |
| Pester | 5.7.1 |
| PSScriptAnalyzer | 1.23.0 (built from the upstream tag with `dotnet build`) |
| Data | Synthetic only: `sample-data/contoso-sim.snapshot.json`, in-test builders, mocked `Get-AD*` commands |

## Results

| Check | Command | Result |
|---|---|---|
| Lint (src, scripts, examples, tests) | `./scripts/Invoke-Lint.ps1` | **0 findings** with `PSScriptAnalyzerSettings.psd1` (includes `PSUseCompatibleSyntax` for 5.1 and 7.0); tests use `tests/PSScriptAnalyzerSettings.psd1`, which only relaxes three style rules for throwaway test helpers |
| Unit tests | `./scripts/Invoke-Tests.ps1 -Suite Unit` | **205 passed, 0 failed, 0 skipped** |
| Integration (offline, portable) | `./scripts/Invoke-Tests.ps1 -Suite Integration` | **5 passed, 0 failed**, **7 skipped** (the Windows-domain suite, by design) |
| Documentation validation | `./scripts/Test-Documentation.ps1` | **0 problems** |
| Repeatable demo | `./scripts/Invoke-Demo.ps1` | Self-checks passed: valid report, `Simulated` label, all five statuses, planted findings present |

Unit test coverage by area: configuration (valid, partial overlay, malformed JSON, unknown keys, ranges, exclusions, exceptions), nested group membership and cycles (including diamonds and self-membership), each audit module (thresholds at the boundary, missing properties, collection failures, exclusions, exceptions), ACL interpretation (rights, inheritance, deny ACEs, replication rights, trusted principals), delegation, per-DC settings (including unreachable DCs), GPO parsing and real SYSVOL folder reads, mocked live collection (permission failures, LDAP errors, unsupported attributes, missing module, unreachable domain, ACL targets that fail), report escaping (HTML, CSV formula injection), schema validation, redaction, output-path validation, authorization gate, static read-only analysis of all source, credential handling, rule catalog integrity, and documentation validation.

## What these results do and do not show

- They show that the toolkit's logic behaves as documented **on synthetic data and mocked directory cmdlets**.
- They do **not** establish the security of any real domain, and the simulated data says nothing about real environments.
- Mocked cmdlets prove the collector code paths and error handling, not that real `ActiveDirectory` cmdlet output has exactly the shape the mocks assume.

## Not validated (requires a real Windows test domain or Windows PowerShell 5.1)

| Area | Status |
|---|---|
| Execution under Windows PowerShell 5.1 | **Not run.** Static compatibility analysis (`PSUseCompatibleSyntax` for 5.1) passes; the CI matrix runs 5.1 on `windows-latest` and is the first real check |
| Live collection with the real `ActiveDirectory` module | **Not run.** `tests/Integration/WindowsDomain.Tests.ps1` exists and skips itself unless explicitly enabled |
| ACL reads from real `nTSecurityDescriptor` objects | **Not run** (mocked only) |
| Remote DC host checks over WinRM (registry, services, `auditpol`, Security log) | **Not run** |
| SYSVOL reads over UNC from a real domain | **Not run** (real files in a temp folder are tested) |
| Permission-failure behaviour with a real low-privilege account | **Not run** (simulated through mocks) |
| Windows ACL protection of output files | **Not run** (Unix mode `600` is tested on Linux) |
| Performance and memory on large directories | **Not measured** |
| CI workflows on GitHub | **Not run at the time of writing**; secret scanning and dependency review need a GitHub-hosted run |

The exact steps to run the Windows-domain suite are in [security and limitations](security-and-limitations.md#validation-that-needs-a-real-windows-test-domain).

## Reproduce

```powershell
./scripts/Install-DevDependencies.ps1
./scripts/Invoke-Lint.ps1
./scripts/Invoke-Tests.ps1 -Suite All
./scripts/Test-Documentation.ps1
./scripts/Invoke-Demo.ps1
```
