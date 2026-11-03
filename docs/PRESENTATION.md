# Malware analyst stakeholder presentation

Use these notes for the role-play session. Replace bracketed prompts with real case evidence and keep the presentation focused on what was observed.

## 1. Purpose and scope

“I analyzed `[Malware Name]` as an authorized educational exercise in an isolated Windows VM. The objective was to identify its execution, persistence, file, and network behavior; build a safe removal tool; and verify the configured artifacts were absent after remediation.”

Show the case ID, sample SHA-256, authorization, VM isolation diagram, and analysis dates.

## 2. Analysis method

Explain the sequence:

1. Static analysis without launching the sample.
2. Clean baseline and snapshot.
3. Bounded dynamic observation with process, file, Registry, task, service, and network monitoring.
4. Before/after comparison and indicator review.

Show one process-tree artifact, one persistence artifact, and one network artifact. Explain the difference between direct observation and inference.

## 3. Observed behavior and impact

Present only evidence-backed behavior:

- Initial and child processes: `[Evidence]`.
- Files created or modified: `[Evidence]`.
- Persistence mechanism: `[Evidence]`.
- Malware-associated remote IP/domain: `[Evidence]`.
- Potential impact if run outside isolation: `[Evidence-supported assessment]`.

Avoid claiming that an IP identifies the human attacker.

## 4. Defuse functionality

Explain the four operating paths:

- `Scan`: read-only exact-indicator detection.
- `Remediate`: read-only remediation plan.
- `Remediate -Apply`: controlled process, persistence, and file removal.
- `Verify`: evidence-linked post-reboot checks and verdict.

Highlight path/hash validation, exact Registry-value matching, separate allowlists, confirmation, JSON evidence, and fail-closed behavior.

## 5. Mitigation proof

Show:

- Phase 4 `remediation.json` results.
- The reboot timestamp.
- Phase 5 artifact-absence checks.
- The final `Pass`, `Fail`, or `Inconclusive` verdict.
- Proof that the malware-associated connection is inactive at verification time.

State the limitation: the verdict covers configured artifacts, not unknown behavior.

## 6. Recommendations

Recommend rebuilding compromised production systems from trusted media, patching, least privilege, application control, endpoint monitoring, persistence monitoring, outbound filtering, centralized telemetry, backups, user awareness, and rehearsed incident response.

## 7. Ethics and questions

Close with the need for explicit authorization, disposable isolated systems, no uncontrolled command-and-control communication, careful sample handling, privacy protection, accurate attribution, and transparent uncertainty.

Be prepared to answer:

- Why is reverting or rebuilding more trustworthy than deletion?
- How did you avoid deleting legitimate objects?
- What evidence ties the remote IP to the malware process?
- What happens when a hash or expected Registry value does not match?
- What does an Inconclusive verdict mean?
- Which behaviors could the current configuration fail to detect?

