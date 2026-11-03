# Defuse

Defuse is an educational, defensive Windows malware-analysis and remediation project. Its eventual purpose is to identify a known malware sample inside an isolated lab, stop it, remove its confirmed persistence mechanisms and files, extract its remote IP address, and preserve evidence of the result.

The repository is complete through **Phase 6: reporting and presentation**. It provides evidence-backed scanning, controlled remediation, post-reboot verification, and generation of the final report and mitigation email.

## Safety boundary

Never download or execute a malware sample on a personal computer, work computer, production network, or any system containing valuable data or credentials.

Use a dedicated Windows virtual machine with:

- A clean snapshot taken before analysis.
- No shared clipboard, drag-and-drop, shared folders, USB passthrough, or host credential access.
- No bridged networking. Begin with networking disabled; use a controlled simulated network only when network behavior must be observed.
- No access to production or home networks.
- A plan to revert the VM to its clean snapshot after the exercise.

The current script requires an explicit lab acknowledgement and checks for common virtualization markers. These checks reduce mistakes but cannot prove that an environment is safe.

## Repository layout

```text
defuse/
├── config/
│   └── defuse.example.json  # Safe configuration template
├── docs/
│   ├── ANALYSIS_RUNBOOK.md   # Static and dynamic analysis procedure
│   ├── ANALYSIS_WORKSHEET.md # Evidence and indicator worksheet
│   ├── DETECTION.md          # Indicator formats and result interpretation
│   ├── LAB_SETUP.md          # VM isolation and snapshot procedure
│   ├── PRESENTATION.md        # Stakeholder role-play notes
│   ├── REMEDIATION.md        # Approval, preview, and removal workflow
│   ├── REPORTING.md          # Final report and submission workflow
│   └── VERIFICATION.md       # Post-remediation proof and verdicts
├── evidence/                # Runtime output; ignored by Git
├── scripts/
│   ├── Defuse.ps1            # Scan, remediation, and verification entry point
│   └── New-DefuseReport.ps1  # Evidence-driven report generator
├── .gitignore
└── README.md
```

## Phase 1 setup

Perform these steps from PowerShell inside the isolated Windows VM:

1. Copy `config\defuse.example.json` to `config\defuse.local.json`.
2. Set `caseId` and `analyst` to meaningful values.
3. Review the lab-safety checklist above.
4. Set `labAcknowledgement` to `true` only after confirming the VM is isolated and snapshotted.
5. Leave all `indicators` arrays empty until analysis establishes trustworthy values.
6. Run the scan:

```powershell
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Defuse.ps1 `
  -ConfigPath .\config\defuse.local.json `
  -Mode Scan
```

`-ExecutionPolicy Bypass` applies only to this PowerShell process; it does not permanently weaken the system execution policy.

Each run creates a timestamped directory under `evidence` containing:

- `events.jsonl`: machine-readable audit events.
- `system-context.json`: basic Windows, PowerShell, and VM information.
- `findings.json`: read-only results for every configured indicator.
- `remediation.json` or `verification.json` when the corresponding mode is used.

Evidence output and `defuse.local.json` are excluded from Git because they can contain analyst- or machine-specific information.

## Configuration safety controls

- `labAcknowledgement` defaults to `false`, so the example cannot run accidentally.
- `allowNonVirtualMachine` defaults to `false`. It should remain false for this project.
- `indicators` are empty placeholders. Later phases will populate them only from observed evidence.
- `Scan` and remediation preview are read-only; applied remediation requires all Phase 4 safety gates.

## Current limitations

The actual malware sample, process name, persistence locations, file paths, and attacker IP have not yet been supplied or observed. Defuse therefore makes no assumptions about them and cannot produce genuine mitigation proof until the isolated lab supplies reviewed indicators and runtime evidence.

## Phase 2 analysis procedure

Before handling a sample, follow [the lab setup](docs/LAB_SETUP.md). Then use [the analysis runbook](docs/ANALYSIS_RUNBOOK.md) and record every observation in a case-specific copy of [the analysis worksheet](docs/ANALYSIS_WORKSHEET.md).

The required sample link was absent from the supplied project text. Obtain the exact authorized sample from the course or project owner; do not choose a substitute. The sample itself must never be added to this repository.

## Phase 3 detection

After reviewing Phase 2 evidence, add only confirmed values to the local configuration. See [the detection guide](docs/DETECTION.md) for exact formats and result interpretation. Empty indicator lists are valid and produce a zero-finding report.

## Phase 4 remediation

Remediation uses a separate structured allowlist and never acts on detection indicators alone. Follow [the remediation guide](docs/REMEDIATION.md) to preview `remediation.json`, review exact matches, and apply approved changes. File and process approval requires SHA-256 verification; Registry remediation targets only an exact named value and expected data.

## Phase 5 verification

After applied remediation and a VM reboot, follow [the verification guide](docs/VERIFICATION.md). Verify mode requires the applied remediation evidence directory, checks every configured artifact for absence, confirms reboot timing when required, and writes `verification.json` with an explicit verdict.

## Phase 6 reporting and presentation

Follow [the reporting workflow](docs/REPORTING.md) after Phase 5. `New-DefuseReport.ps1` validates case continuity, reads the linked remediation and verification evidence, and produces a Markdown report containing:

- Executive summary and analysis walkthrough.
- Defuse program explanation.
- Remediation and verification proof tables.
- Malware-associated remote IP information.
- Impact and prevention recommendations.
- Threat-intelligence mitigation email.
- Ethical-hacking report.
- Evidence limitations.

Only a Phase 5 `Pass` is described as successful mitigation. Use [the presentation notes](docs/PRESENTATION.md) for the Malware Analyst stakeholder role-play.

## Malware mitigation report email

The final email is generated with the required subject:

```text
To: [security contact]
Subject: Malware Analysis Report: Mitigation of [Malware Name]

Dear Security Team,

[Evidence-dependent outcome statement]

Summary: [Observed behavior and impact]
Proof of Mitigation: [Phase 4 actions and Phase 5 verdict]
Attacker Information: [Malware-associated remote IP, or not established]

Best regards,
[Analyst]
```

The wording intentionally distinguishes network infrastructure from identification of a human attacker.

## Ethical hacking report

Malware analysis must have explicit authorization and remain within scope. Samples belong only in disposable, isolated environments with clean snapshots, disabled host integration, and no production-network access. Analysts must protect unrelated systems and personal information, preserve evidence accurately, avoid uncontrolled communication with external infrastructure, and report uncertainty honestly.

Executing malware outside isolation can cause data loss, credential theft, lateral movement, business interruption, and harm to third parties. Samples must not be distributed or uploaded publicly without permission. If containment fails, disconnect the lab, preserve appropriate evidence, notify the responsible party, and revert or destroy the affected VM.

## Remediation recommendations

- Rebuild or revert compromised machines from trusted sources.
- Patch operating systems, applications, browsers, and security tools.
- Enforce least privilege and application control.
- Monitor startup Registry values, Startup folders, tasks, services, and unusual process trees.
- Restrict unnecessary outbound traffic and retain endpoint, DNS, firewall, and proxy telemetry.
- Maintain tested backups, user-awareness controls, and an incident-response procedure.

## Submission status

The implementation and documentation are complete. A genuine final report still requires the authorized malware sample, completed worksheet, confirmed indicators, applied VM remediation evidence, and Phase 5 verification evidence. The repository deliberately contains no invented results or malware sample.
