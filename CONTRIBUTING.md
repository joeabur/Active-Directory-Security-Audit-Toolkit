# Contributing

Thank you for helping. The toolkit's first rule is **read-only**: contributions must not add anything that changes directory, ACL, Group Policy, domain controller, registry, service or account state.

## Workflow

1. Install tools: `./scripts/Install-DevDependencies.ps1`
2. Make a focused change on a branch.
3. Run, and keep green:
   ```powershell
   ./scripts/Invoke-Lint.ps1
   ./scripts/Invoke-Tests.ps1 -Suite All
   ./scripts/Test-Documentation.ps1
   ```
4. Open a pull request using the template.

## Adding or changing a rule

1. Add the rule to `src/Rules/RuleCatalog.psd1` with all fields (title, severity, confidence, finding type, description, remediation, limitations, required data, permissions). Be honest in *limitations*; separate hygiene evidence from confirmed misconfiguration.
2. Implement it in the matching module under `src/Modules/`. Use `Invoke-ADSAObjectRule` / `Complete-ADSARule` so that missing data yields `NOT_ASSESSED`, failed collection yields `ERROR`, and `PASS` requires at least one evaluated object.
3. Add unit tests: a failing case, a passing case, a missing-property case, and a collection-failure case.
4. Regenerate `docs/rule-reference.md` with `./scripts/New-RuleReference.ps1`; update walkthrough numbers if the sample output changes (`./scripts/Test-Documentation.ps1` tells you).

## Rules of the road

- No credentials or real directory data anywhere in the repository (fixtures are synthetic: `contoso-sim.test`).
- Keep source files ASCII and compatible with Windows PowerShell 5.1 (no `?.`, `??`, ternary, `&&`).
- Do not weaken the safety tests in `tests/Unit/Safety.Tests.ps1` to make a change pass.
- Never present mock-based results as evidence about a real domain.
