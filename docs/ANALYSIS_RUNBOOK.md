# Malware analysis and evidence runbook

Use this procedure only in the isolated lab described in `LAB_SETUP.md`. The purpose is to produce defensible indicators for Defuse—not to explore unrelated systems or communicate with a real command-and-control server.

## Evidence principles

- Record observations in UTC where possible.
- Preserve the original sample hash and never commit the sample to this repository.
- Distinguish an observation from an inference. For example, a TCP connection is evidence; calling its destination the attacker is an inference until context supports it.
- Corroborate important indicators with at least two sources when practical.
- Capture screenshots plus machine-readable exports. A screenshot alone is difficult to validate.
- Record negative results, such as “no scheduled task difference observed.”

Create a separate case folder outside Git for screenshots and exports. Use filenames in this form:

```text
YYYYMMDDTHHMMSSZ_category_description.ext
```

## Stage A — Static analysis (do not launch the sample)

1. Record the source, received filename, size, and acquisition time.
2. Calculate hashes:

   ```powershell
   Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\Lab\sample.bin'
   Get-FileHash -Algorithm SHA1 -LiteralPath 'C:\Lab\sample.bin'
   ```

3. Determine the file type from its content and PE headers, not only its extension.
4. Record architecture, compilation metadata, imported functions, sections, and signatures. Treat compilation timestamps as untrusted metadata.
5. Extract readable strings and note potential:
   - process or mutex names;
   - file and directory paths;
   - Registry keys;
   - task or service names;
   - domains, URLs, and IP literals;
   - command-line fragments.
6. Do not classify a string as a confirmed indicator until runtime behavior or another reliable source supports it.

Complete the static-analysis portion of `ANALYSIS_WORKSHEET.md` before proceeding.

## Stage B — Baseline capture

Before execution, record the clean state with the chosen monitoring tools:

- Running processes, process IDs, executable paths, and command lines.
- Startup Registry locations and startup folders.
- Scheduled tasks and services.
- Active TCP/UDP endpoints and DNS configuration.
- Files present in directories commonly used for user-level persistence, especially `%APPDATA%`, `%LOCALAPPDATA%`, `%PROGRAMDATA%`, `%TEMP%`, and the user Startup folder.

Start Process Monitor with filters focused on process creation, file writes, Registry writes, and network activity. Save the native capture as well as a filtered export. Take the first Regshot snapshot if Regshot is part of the toolset.

## Stage C — Controlled dynamic observation

Proceed only after the checklist is complete and a temporary pre-run snapshot exists.

1. Start evidence capture before launching the sample.
2. Record the exact launch time and method.
3. Observe for a short, predefined interval. Do not interact with real external services.
4. Record the original process and its children, including PID, parent PID, executable path, command line, and hash.
5. Record created, modified, or deleted files.
6. Record Registry modifications, especially `Run` and `RunOnce` keys.
7. Record new or changed scheduled tasks, services, WMI persistence, and Startup-folder items.
8. Record DNS queries and connection attempts with timestamp, local process/PID, protocol, destination IP, and destination port.
9. Stop collection at the predefined time, or immediately if unexpected behavior threatens isolation.
10. Save the Process Monitor capture, second Regshot snapshot/difference, process tree, Autoruns output, network capture, and screenshots.

Do not manually browse to, probe, or attack an observed destination. The destination may be compromised third-party infrastructure rather than a system owned by the malware author.

## Stage D — Persistence confirmation

Persistence is confirmed only when an artifact causes or is designed to cause the malware to restart. For each candidate, record:

- Mechanism type: Registry, Startup folder, scheduled task, service, WMI, or other.
- Exact object path or name.
- Value, executable target, arguments, trigger, and user context.
- Creating process and timestamp, if observable.
- Before/after evidence source.

If safe within the disposable lab, a reboot observation can confirm restart behavior. Take a snapshot first and keep monitoring active. Do not reconnect the VM to an uncontrolled network.

## Stage E — Remote IP attribution

An IP address qualifies as a malware-associated destination when evidence ties it to the sample or its child process. Record:

- Destination IP and port.
- Protocol and timestamp.
- Owning PID and process path.
- DNS name or query immediately associated with it, if present.
- Packet-capture frame number or TCPView/Process Monitor evidence.
- Whether the address belongs to the isolated simulator.

Do not report the simulator's address as an attacker IP. Also do not automatically claim that a remote address identifies the human attacker. The accurate wording is usually **malware-associated remote IP** or **suspected command-and-control IP**, followed by the evidence and confidence level.

## Stage F — Indicator review

Before adding an indicator to `config\defuse.local.json`, verify that it is:

1. Directly observed or strongly corroborated.
2. Specific enough not to target legitimate Windows components.
3. Recorded exactly, including full paths where possible.
4. Supported by an evidence filename and worksheet entry.
5. Assigned a confidence level and rationale.

Phase 3 will turn only these reviewed indicators into scan logic.

## Minimum evidence package

- Completed analysis worksheet.
- Original sample SHA-256 and metadata.
- Process tree and relevant command lines.
- Before/after persistence evidence.
- File-system change evidence.
- Network evidence tying a process to a destination.
- List of confirmed indicators with supporting filenames.
- Notes about uncertainty and negative findings.

