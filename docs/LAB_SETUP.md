# Isolated malware-analysis lab

This runbook describes the safety conditions required before analyzing the Defuse sample. It does not authorize downloading or executing malware on the host computer.

## Recommended layout

Use two disposable virtual machines when network behavior must be observed:

```text
Windows analysis VM  <---- internal virtual network ---->  Network simulator VM
        |                                                     |
     no host shares                                      no internet route
        |                                                     |
        +---------------- no production access ---------------+
```

The Windows VM runs the sample. A separate simulator such as a dedicated REMnux/INetSim VM can answer controlled DNS or service requests without forwarding traffic to the internet. If no simulator is available, keep the Windows VM network adapter disconnected.

Do not use bridged networking. Host-only networking still exposes the host to the guest and should not be treated as full isolation. An internal network shared only by the disposable lab VMs is preferred.

## Windows VM checklist

Create a dedicated Windows VM with no personal information or reused credentials. Before importing the sample, verify every item:

- [ ] The VM contains no personal, organizational, or production data.
- [ ] The hypervisor and host operating system are patched.
- [ ] Networking is disconnected or attached only to an isolated internal lab network.
- [ ] Shared folders are disabled.
- [ ] Shared clipboard and drag-and-drop are disabled.
- [ ] USB, camera, microphone, and printer passthrough are disabled.
- [ ] Guest access to host credentials and cloud-sync folders is unavailable.
- [ ] Remote desktop and management access from other networks are disabled.
- [ ] Windows AutoPlay is disabled.
- [ ] A clean snapshot named `defuse-clean` exists.
- [ ] A second snapshot named `defuse-tools-ready` exists after installing analysis tools.
- [ ] The analyst has a documented method to destroy or revert the VM.

Treat these controls as layers, not proof that the sample cannot escape.

## Suggested analysis tools

Obtain tools from their official publishers before introducing the malware sample, then snapshot the prepared VM. Useful categories include:

- Static inspection: Windows file properties, `Get-FileHash`, PEStudio, Detect It Easy, and FLOSS or a strings utility.
- Process and persistence monitoring: Process Explorer, Process Monitor, Autoruns, Regshot, Task Scheduler, and Services.
- Network monitoring: TCPView, Wireshark, and `Get-NetTCPConnection`.
- Optional debugging: x64dbg in a separate disposable snapshot.

Record tool names and versions in the analysis worksheet. Do not upload an unknown sample to a public scanning service unless the project owner explicitly permits disclosure; public services may redistribute samples and indicators.

## Sample transfer

The requirements supplied to this repository do not contain the actual sample URL or sample file. Do not substitute a random malware sample.

When the authorized sample becomes available:

1. Confirm the source and authorization with the course or project owner.
2. Revert to `defuse-tools-ready`.
3. Disconnect networking before transfer.
4. Transfer the password-protected archive using the course-approved method. Do not use shared host folders.
5. Keep the sample encrypted or archived until static evidence collection is ready.
6. Calculate SHA-256 before execution and record it in `ANALYSIS_WORKSHEET.md`.
7. Rename neither the original sample nor its extension without documenting the change.

Never email the sample, commit it to Git, or place it in this repository.

## Snapshot lifecycle

Use this sequence for every dynamic run:

1. Revert to `defuse-tools-ready`.
2. Confirm isolation again.
3. Capture the baseline state.
4. Create a temporary snapshot such as `defuse-before-run-01`.
5. Run one bounded experiment and collect evidence.
6. Shut down the VM rather than continuing normal use.
7. Export only non-executable evidence through the approved method.
8. Revert to `defuse-tools-ready` or destroy the VM.

Do not rely on deleting the malware from a compromised VM as a way to make that VM trustworthy again. Reverting or rebuilding is the reliable lab reset.

## Emergency stop

If the VM connects to an unintended network, the sample appears outside the guest, or isolation is uncertain:

1. Disconnect the virtual network adapter at the hypervisor.
2. Pause or power off the guest.
3. Do not copy additional files from it.
4. Preserve relevant logs and notify the responsible instructor or security contact.
5. Revert or destroy the affected lab VM after the incident is documented.

