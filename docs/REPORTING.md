# Phase 6 reporting workflow

The final report must be generated from real Phase 4 and Phase 5 evidence. Do not replace unknown facts with invented process names, screenshots, IP addresses, or successful outcomes.

## Required inputs

Before generating the report, confirm that you have:

- A completed local configuration with reviewed indicators and remediation artifacts.
- Real values under `reporting` for malware name, organization, security email, and analyst contact.
- An applied Phase 4 evidence directory.
- A Phase 5 evidence directory containing `verification.json` and `findings.json`.
- Screenshots and packet or connection evidence stored with the case.

The generator follows `verification.previousEvidence` to find the applied `remediation.json`. It validates that all case IDs match and that remediation was applied.

## Generate the report

From PowerShell:

```powershell
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\New-DefuseReport.ps1 `
  -ConfigPath .\config\defuse.local.json `
  -VerificationEvidenceDirectory .\evidence\CASE-01-VERIFICATION-RUN `
  -OutputPath .\evidence\CASE-01-final-report.md
```

The script refuses placeholder reporting fields and refuses to overwrite an existing report unless `-Force` is supplied. It preserves `Pass`, `Fail`, or `Inconclusive` exactly as recorded; only `Pass` produces successful-mitigation wording.

## Submission checklist

- [ ] Source code: `scripts\Defuse.ps1` and `scripts\New-DefuseReport.ps1`.
- [ ] Project documentation: `README.md` and the `docs` runbooks.
- [ ] Completed analysis worksheet.
- [ ] Generated final report and mitigation email.
- [ ] Phase 4 and Phase 5 machine-readable evidence.
- [ ] Screenshots showing relevant process/persistence behavior, applied remediation, reboot, and verification.
- [ ] Evidence supporting the malware-associated IP.
- [ ] VirtualBox or equivalent available for the audit.
- [ ] Malware sample kept outside the repository and handled according to authorization.

Review the generated report manually before submission. Check that evidence filenames are available to the auditor, redact unrelated personal information, and ensure every technical claim is supported.

