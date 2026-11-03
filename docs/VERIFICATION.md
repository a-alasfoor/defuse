# Phase 5 eradication verification

Verification is a read-only operation that links the current machine state to evidence from an applied Phase 4 run. It does not claim that a compromised VM is generally trustworthy; reverting or rebuilding remains the reliable way to restore a real system.

## What Verify checks

- The earlier `remediation.json` belongs to the same case.
- The earlier report has `applyRequested: true`, not merely a preview plan.
- The earlier report contains no `Blocked`, `Declined`, `Error`, or `Planned` outcomes.
- A reboot occurred after remediation when `requireRebootAfterRemediation` is true.
- Approved malware processes are no longer running from their exact paths.
- Approved malware files are absent.
- Exact persistence Registry values are absent.
- Exact scheduled tasks and services are absent.
- No active TCP connection targets a configured malware-associated remote IP.

Remote-IP verification is point-in-time evidence only. It does not replace packet-capture review and does not cover historical or UDP traffic.

## Configuration

Phase 5 uses the same `remediation` allowlist that Phase 4 applied. The example configuration also contains:

```json
"verification": {
  "requireRebootAfterRemediation": true
}
```

Leave this true when the exercise requires proof that persistence did not restore the malware after startup.

## Procedure

1. Preserve the timestamped evidence directory produced by `Remediate -Apply`.
2. Reboot the isolated Windows VM while keeping its network disconnected or internally isolated.
3. Wait for Windows startup to settle, but do not launch the malware.
4. Open PowerShell and run:

```powershell
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Defuse.ps1 `
  -ConfigPath .\config\defuse.local.json `
  -Mode Verify `
  -PreviousEvidenceDirectory .\evidence\CASE-01-YYYYMMDDTHHMMSSZ
```

Use the actual directory produced by the applied remediation run. A plan-only directory is rejected.

## Verdicts

| Verdict | Meaning | Process exit code |
|---|---|---:|
| `Pass` | Every required check passed | 0 |
| `Fail` | At least one artifact remains, reboot proof failed, or the remediation evidence records a failed action | 2 |
| `Inconclusive` | No check failed, but at least one check could not be completed | 3 |

`verification.json` contains the overall verdict, timestamps, previous evidence path, counts, and every individual check. `events.jsonl` provides the chronological audit record, while `findings.json` preserves the normal indicator scan from the same run.

## Proof package

For the final report, retain:

- The applied Phase 4 `remediation.json` and `events.jsonl`.
- The Phase 5 `verification.json`, `findings.json`, `system-context.json`, and `events.jsonl`.
- Screenshots showing the applied run, rebooted desktop, and verification verdict.
- Packet or connection evidence supporting the malware-associated remote IP.

A `Pass` verdict supports the statement that the configured artifacts were absent at verification time. It does not prove the absence of unknown malware behavior or unconfigured persistence.

