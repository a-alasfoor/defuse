# Phase 4 remediation guide

Defuse remediation is intended only for a disposable, isolated Windows analysis VM. Reverting the VM to a known-clean snapshot remains the most reliable way to restore trust. The remediation workflow exists to demonstrate and document artifact removal for this project.

## Safety gates

Applied remediation occurs only when all of these conditions are met:

1. `-Mode Remediate` is selected.
2. At least one structured remediation artifact is configured.
3. `-Apply` is explicitly supplied.
4. `labAcknowledgement` and `remediationAcknowledgement` are both `true`.
5. The machine passes the VM check.
6. PowerShell is running as Administrator.
7. Each artifact passes its exact validation checks.
8. PowerShell's `ShouldProcess` confirmation approves the action.

Scan mode is always read-only. Remediate mode without `-Apply` is also read-only and writes a plan to `remediation.json`.

## Configuration schema

The `remediation` section is deliberately separate from detection indicators. A broad detection candidate must never silently become a deletion target.

### Process artifacts

```json
{
  "name": "confirmed-sample.exe",
  "path": "%APPDATA%\\ConfirmedCase\\confirmed-sample.exe",
  "sha256": "64_HEXADECIMAL_CHARACTERS_REPLACE_WITH_OBSERVED_HASH"
}
```

Defuse terminates a process only when its exact name and executable path match, the file still exists, and its SHA-256 matches.

### Registry values

```json
{
  "path": "Registry::HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "name": "ConfirmedCaseValue",
  "expectedData": "%APPDATA%\\ConfirmedCase\\confirmed-sample.exe"
}
```

Defuse removes only the named value when its unexpanded data exactly matches `expectedData`. It does not delete the containing key, which may contain legitimate startup entries.

### Scheduled tasks

```json
{
  "name": "ConfirmedCaseTask",
  "taskPath": "\\",
  "expectedExecutablePath": "%APPDATA%\\ConfirmedCase\\confirmed-sample.exe"
}
```

The exact task name, task folder, and executable action must match.

### Services

```json
{
  "name": "ConfirmedCaseService",
  "expectedExecutablePath": "%PROGRAMDATA%\\ConfirmedCase\\confirmed-sample.exe"
}
```

The internal service name and configured executable must match. Defuse stops the service and asks Windows to delete it.

### Files

```json
{
  "path": "%APPDATA%\\ConfirmedCase\\confirmed-sample.exe",
  "sha256": "64_HEXADECIMAL_CHARACTERS_REPLACE_WITH_OBSERVED_HASH"
}
```

Files are permanently deleted only after exact SHA-256 verification. Directories are never recursively deleted by Phase 4.

The examples are structural placeholders, not real indicators. Replace every field using reviewed Phase 2 evidence.

## Safe operating sequence

First take a VM snapshot. Then create the local configuration and leave `remediationAcknowledgement` false while reviewing it.

Generate a read-only plan:

```powershell
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Defuse.ps1 `
  -ConfigPath .\config\defuse.local.json `
  -Mode Remediate
```

Review `remediation.json`. Resolve every `Blocked` or `Error` result from evidence; do not weaken a match merely to make it pass.

After confirming the snapshot and every target, set `remediationAcknowledgement` to `true`, open PowerShell as Administrator, and apply:

```powershell
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Defuse.ps1 `
  -ConfigPath .\config\defuse.local.json `
  -Mode Remediate `
  -Apply
```

PowerShell requests confirmation for each destructive target unless the analyst explicitly controls confirmation behavior. `-WhatIf` can be combined with `-Apply` to exercise those confirmation paths without changing artifacts.

## Action order and records

Defuse performs approved actions in this order:

1. Terminate verified processes.
2. Stop and delete verified services.
3. Unregister verified scheduled tasks.
4. Remove exact verified Registry values.
5. Permanently delete hash-verified files.

`remediation.json` records each result as `Planned`, `Stopped`, `Removed`, `NotFound`, `Blocked`, `Declined`, or `Error`. `events.jsonl` records the same actions chronologically.

Afterward, run Scan again and retain its separate evidence directory. Phase 5 will formalize reboot and post-remediation verification.

