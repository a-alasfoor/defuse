# Phase 3 detection guide

Defuse Phase 3 performs read-only checks against analyst-reviewed indicators. A finding means that the configured object was observed; it does not independently prove maliciousness.

## Indicator formats

All comparisons are case-insensitive exact matches unless noted otherwise. Wildcards are not supported.

| Configuration field | Required value format | Detection behavior |
|---|---|---|
| `processNames` | Executable name such as `sample.exe` | Exact process name; records PID, parent PID, path, and command line |
| `filePaths` | Full path, optionally using `%ENVIRONMENT_VARIABLES%` | Tests the literal expanded path and hashes files with SHA-256 |
| `registryPaths` | PowerShell Registry path such as `Registry::HKEY_CURRENT_USER\Software\Example` | Tests the exact key and records its values |
| `scheduledTaskNames` | Task name without wildcards | Exact task name across all task folders |
| `serviceNames` | Internal service name, not display name | Exact service name and configuration |
| `remoteIpAddresses` | Valid IPv4 or IPv6 address | Checks current TCP connections and records ports and owning process |

Registry paths identify keys in Phase 3, not individual value names. If a common key such as a Windows `Run` key is configured, Defuse reports all values for analyst review. Do not treat the entire key as malicious.

The remote-IP check is a point-in-time view of active TCP endpoints. A `NotFound` result does not prove that the sample never contacted that address. Correlate it with packet capture and other Phase 2 evidence. UDP and historical connections are not covered by this check.

## Configuration example

The following values are deliberately fictional and must not be copied into a real case:

```json
{
  "processNames": ["confirmed-sample.exe"],
  "filePaths": ["%APPDATA%\\ConfirmedCase\\confirmed-sample.exe"],
  "registryPaths": ["Registry::HKEY_CURRENT_USER\\Software\\ConfirmedCase"],
  "scheduledTaskNames": ["ConfirmedCaseTask"],
  "serviceNames": ["ConfirmedCaseService"],
  "remoteIpAddresses": ["192.0.2.10"]
}
```

`192.0.2.10` belongs to an address block reserved for documentation; it is not asserted to be attacker infrastructure.

## Run and output

Run from the repository root inside the isolated Windows VM:

```powershell
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Defuse.ps1 `
  -ConfigPath .\config\defuse.local.json `
  -Mode Scan
```

Each run adds `findings.json` to its timestamped evidence directory. Every entry has:

- `type` and configured `indicator`;
- `status`: `Found`, `NotFound`, or `Error`;
- a short summary;
- category-specific details where available.

Review `Error` separately from `NotFound`. An error means the check could not reach a conclusion. When all indicator arrays are empty, the scan completes successfully with zero findings.

## Interpreting results

- `Found`: the exact configured object is currently observable.
- `NotFound`: the object was not observable during this particular check.
- `Error`: the check was unsupported, inaccessible, or invalid.

Detection is deliberately separated from remediation. Phase 3 never calls process termination, Registry modification, task/service removal, or file deletion commands.

