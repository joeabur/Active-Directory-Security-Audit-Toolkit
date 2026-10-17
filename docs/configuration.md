# Configuration

Configuration is JSON with a version. It holds **thresholds, baselines, exclusions and documented exceptions only. It never holds credentials.** Credentials are supplied at run time as a `[pscredential]` and are not persisted.

## How configuration is loaded

1. `config/default.config.json` is loaded.
2. Your file (`-ConfigPath`) is overlaid: objects merge key by key; arrays and scalars replace the default.
3. The merged result is validated strictly. **Unknown keys are errors**, so a typo cannot silently disable a check. Any error stops the run before any collection.

Validate without running an audit:

```powershell
Import-Module ./src/ADSecurityAudit.psd1 -Force
Test-ADSAConfig -Path ./examples/custom-config.json
```

Expected for a valid file: `IsValid` is `True` with empty `Errors`. `Warnings` lists expired exceptions.

```powershell
(Get-ADSAConfig).thresholds
```

A schema for editors is in `config/schemas/config.schema.json`; `Test-ADSAConfig` is authoritative.

## Reference

| Key | Default | Range / values | Used by |
|---|---|---|---|
| `configVersion` | `"1.0"` | `1.x` (major must be 1) | all |
| `thresholds.staleUserDays` | 90 | 15..3650 | ACC-001, PRV-002 |
| `thresholds.staleComputerDays` | 90 | 15..3650 | ACC-002 |
| `thresholds.neverLoggedOnGraceDays` | 30 | 0..3650 | ACC-008 |
| `thresholds.servicePasswordMaxAgeDays` | 365 | 30..3650 | SVC-001 |
| `thresholds.krbtgtMaxAgeDays` | 180 | 30..3650 | KRB-001 |
| `privilegedGroupMaxMembers` | `default` 10; Domain Admins 5; Enterprise Admins 3; Administrators 8 | non-negative integers; `default` required | PRV-001 |
| `passwordPolicy.minLength` | 14 | 1..128 | POL-001 |
| `passwordPolicy.minHistory` | 24 | 0..24 | POL-003 |
| `passwordPolicy.complexityRequired` | `true` | true/false | POL-002 |
| `passwordPolicy.lockoutThresholdMax` | 10 | 1..999 | POL-004 |
| `passwordPolicy.lockoutDurationMinMinutes` | 15 | 0..100000 | POL-005 |
| `privilegedGroups` | the ten built-in protected groups | each needs `name` and exactly one of `sid` or `rid` | privileged index |
| `trustedPrincipals.sids` / `.names` | empty | SIDs / `DOMAIN\name` | ACL-001..004 |
| `domainControllers.unsupportedOsPattern` | `Windows (Server )?(2000\|2003\|2008\|2012)` | .NET regex | INF-001 |
| `domainControllers.minDomainFunctionalLevel` / `minForestFunctionalLevel` | `Windows2012R2Domain` / `Windows2012R2Forest` | functional level names | INF-002 |
| `securityLog.minSizeMB` | 1024 | 1..1048576 | AUD-002 |
| `auditPolicy.required` | ten subcategories by GUID | `name`, `guid`, `success`, `failure` | AUD-001 |
| `collection.aclMaxObjects` | 500 | 1..100000 | ACL collection |
| `collection.collectDcHostSettings` / `collectSysvol` / `collectAcls` | true | true/false | live collection |
| `exclusions` | none | see below | all object rules |
| `exceptions` | none | see below | FAIL results |
| `logging.level` / `logging.path` | `Information` / none | Debug, Information, Warning, Error / file path | structured log |

Notes:

- Thresholds are **organisational policy**, not universal standards. Choose values you can defend.
- Stale thresholds start at 15 days because `lastLogonTimestamp` is replicated with up to about 14 days of lag.
- The default privileged group list matches the AdminSDHolder-protected built-in groups. If you remove a group, accounts with `adminCount = 1` that are only in that group appear as orphaned (ADSA-PRV-008).
- `logging.path` is validated like an output path and cannot point inside tracked repository folders. Logs never contain credentials; keys that look like secrets are redacted.

## Exclusions

An exclusion removes matching objects from a rule's scope. Use it for objects that are out of scope by design (for example a decommissioned OU you are not assessing).

```json
{
  "exclusions": [
    {
      "pattern": "svc_gmsa_*",
      "appliesTo": ["user"],
      "ruleIds": ["ADSA-ACC-003"],
      "reason": "Managed by a group Managed Service Account process; tracked in CHG-1234"
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `pattern` | yes | Wildcard (`-like`) matched against `SamAccountName`/name **and** distinguished name |
| `appliesTo` | no | `user`, `computer`, `group`, `any` (default any) |
| `ruleIds` | no | Limit to these rules (default all rules) |
| `reason` | **yes** | Why. Missing reasons are rejected so blind spots are always documented |

Excluded objects are counted and the count appears in that rule's limitations.

## Exceptions

An exception accepts a specific *failing* finding for a limited time. The finding **stays in the report**, flagged as excepted with its owner, approver and expiry, and is left out of active severity counts.

```json
{
  "exceptions": [
    {
      "id": "EXC-001",
      "ruleId": "ADSA-PRV-004",
      "objectPattern": "svc_backup",
      "reason": "Backup agent requires domain admin and an SPN until vendor release 9.2",
      "owner": "backup-team@contoso-sim.test",
      "approvedBy": "ciso@contoso-sim.test",
      "expires": "2027-06-30"
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique within the file |
| `ruleId` | yes | One rule ID, for example `ADSA-ACC-003` |
| `objectPattern` | yes | Wildcard matched against the affected object, its distinguished name, or the principal in ACL findings |
| `reason`, `owner` | yes | Justification and accountable owner |
| `approvedBy` | no | Approver |
| `expires` | yes | `yyyy-MM-dd`. After this date (relative to the **collection time**) the exception no longer applies and a warning is added |

Exceptions that match nothing produce a warning ("may be obsolete"). Documented privileged service accounts (ADSA-PRV-003/004) and legitimate synchronisation accounts (ADSA-ACL-002) are the typical uses.

Exclusion or exception? Use an **exclusion** when the object should not be assessed at all. Use an **exception** when the finding is real, understood and temporarily accepted.

## Malformed configuration

| Problem | Result |
|---|---|
| Not valid JSON | Error naming the file and the parser message |
| Unknown key | Error naming the key (`Unknown configuration key 'thresholds.staleUserDay'.`) |
| Wrong type or out of range | Error naming the key, the value and the allowed range |
| Unsupported `configVersion` major | Error |
| Invalid regex, SID, GUID, rule ID or date | Error |
| Exclusion without `reason`; exception without owner, reason or expiry | Error |
| Expired exception | Warning; the exception is not applied |

See also [troubleshooting](troubleshooting.md).
