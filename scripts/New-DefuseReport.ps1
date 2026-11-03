#requires -Version 5.1
<#
.SYNOPSIS
    Builds the Phase 6 Markdown submission report from Defuse evidence.

.DESCRIPTION
    Reads a local case configuration and a Phase 5 evidence directory. The report
    reflects the recorded verification verdict and never upgrades Fail or
    Inconclusive evidence into a successful-mitigation claim.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$VerificationEvidenceDirectory,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Report {
    param([Parameter(Mandatory)] [string]$Message)
    throw "DEFUSE REPORT STOP: $Message"
}

function Read-JsonFile {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Label)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Stop-Report "$Label not found: $Path"
    }
    try {
        return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        Stop-Report "$Label is invalid JSON: $($_.Exception.Message)"
    }
}

function ConvertTo-MarkdownCell {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value).Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ')
}

function Join-OrNone {
    param([object[]]$Values)
    $items = @($Values | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($items.Count -eq 0) { return 'None established from the supplied evidence.' }
    return ($items -join ', ')
}

$resolvedConfig = [System.IO.Path]::GetFullPath($ConfigPath)
$evidenceDirectory = [System.IO.Path]::GetFullPath($VerificationEvidenceDirectory)
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)

$config = Read-JsonFile -Path $resolvedConfig -Label 'Configuration'
foreach ($property in @('caseId', 'analyst', 'indicators', 'remediation', 'reporting')) {
    if ($null -eq $config.PSObject.Properties[$property]) {
        Stop-Report "Configuration is missing '$property'."
    }
}
foreach ($property in @('malwareName', 'organization', 'securityEmail', 'analystContact')) {
    if ($null -eq $config.reporting.PSObject.Properties[$property] -or
        [string]::IsNullOrWhiteSpace([string]$config.reporting.$property) -or
        [string]$config.reporting.$property -match 'CHANGE-ME|example\.invalid') {
        Stop-Report "Set reporting.$property to a real case value before generating the report."
    }
}

$verificationPath = Join-Path $evidenceDirectory 'verification.json'
$findingsPath = Join-Path $evidenceDirectory 'findings.json'
$verification = Read-JsonFile -Path $verificationPath -Label 'Phase 5 verification report'
$findings = Read-JsonFile -Path $findingsPath -Label 'Phase 5 findings report'

foreach ($property in @('caseId', 'verdict', 'previousEvidence', 'checks', 'counts', 'generatedAtUtc')) {
    if ($null -eq $verification.PSObject.Properties[$property]) {
        Stop-Report "Verification report is missing '$property'."
    }
}
if ($verification.caseId -cne $config.caseId -or $findings.caseId -cne $config.caseId) {
    Stop-Report 'Configuration, findings, and verification case IDs must match.'
}
if ([string]$verification.verdict -notin @('Pass', 'Fail', 'Inconclusive')) {
    Stop-Report "Unsupported verification verdict '$($verification.verdict)'."
}

$previousEvidence = [System.IO.Path]::GetFullPath([string]$verification.previousEvidence)
$remediation = Read-JsonFile -Path (Join-Path $previousEvidence 'remediation.json') -Label 'Applied remediation report'
if ($remediation.caseId -cne $config.caseId -or $remediation.applyRequested -ne $true) {
    Stop-Report 'Linked remediation evidence is not an applied run for this case.'
}

if ((Test-Path -LiteralPath $resolvedOutput) -and -not $Force) {
    Stop-Report "Output already exists: $resolvedOutput. Use -Force to replace it."
}

$verdict = [string]$verification.verdict
$mitigationStatement = switch ($verdict) {
    'Pass' { 'The configured malware artifacts were successfully mitigated and were absent during post-reboot verification.' }
    'Fail' { 'Mitigation was not successfully verified because one or more required checks failed.' }
    default { 'Mitigation remains inconclusive because one or more verification checks could not reach a conclusion.' }
}
$emailOutcome = switch ($verdict) {
    'Pass' { 'I am reporting successful mitigation of the configured malware artifacts.' }
    'Fail' { 'I am reporting that mitigation verification failed and requires further response.' }
    default { 'I am reporting an inconclusive mitigation result that requires additional evidence.' }
}

$remoteIps = @($config.indicators.remoteIpAddresses)
$remoteIpText = Join-OrNone -Values $remoteIps
$processText = Join-OrNone -Values @($config.indicators.processNames)
$persistenceCount = @($config.remediation.registryValues).Count + @($config.remediation.scheduledTasks).Count + @($config.remediation.services).Count
$fileCount = @($config.remediation.files).Count

$lines = New-Object System.Collections.Generic.List[string]
[void]$lines.Add("# Malware Analysis Report: Mitigation of $($config.reporting.malwareName)")
[void]$lines.Add('')
[void]$lines.Add("**Case ID:** $($config.caseId)  ")
[void]$lines.Add("**Analyst:** $($config.analyst)  ")
[void]$lines.Add("**Generated from verification evidence:** $($verification.generatedAtUtc)  ")
[void]$lines.Add("**Verification verdict:** $verdict")
[void]$lines.Add('')
[void]$lines.Add('## Executive summary')
[void]$lines.Add('')
[void]$lines.Add($mitigationStatement)
[void]$lines.Add("The reviewed case configuration identifies process indicators as: $processText. It contains $persistenceCount approved persistence artifact(s) and $fileCount hash-approved file artifact(s). Statements in this report are limited to configured and observed evidence; unknown behavior is outside the verdict's scope.")
[void]$lines.Add('')
[void]$lines.Add('## Analysis approach')
[void]$lines.Add('')
[void]$lines.Add('The sample was handled in an isolated, snapshotted Windows VM. Static analysis established file metadata and candidate indicators without launching the sample. Controlled dynamic analysis then recorded process, file, Registry, scheduled-task, service, and network behavior. Candidates were reviewed before being added to the detection and remediation allowlists.')
[void]$lines.Add('')
[void]$lines.Add('## Defuse program functionality')
[void]$lines.Add('')
[void]$lines.Add('Defuse separates scanning, remediation planning, applied remediation, and verification. Applied actions require a VM acknowledgement, an elevated session, a separate remediation acknowledgement, exact artifact matching, and confirmation. Processes and files require path and SHA-256 validation; Registry remediation removes only the exact confirmed value. Verification links to the applied evidence and checks artifact absence after reboot.')
[void]$lines.Add('')
[void]$lines.Add('## Remediation evidence')
[void]$lines.Add('')
[void]$lines.Add('| Type | Target | Result | Summary |')
[void]$lines.Add('|---|---|---|---|')
foreach ($result in @($remediation.results)) {
[void]$lines.Add("| $(ConvertTo-MarkdownCell $result.type) | $(ConvertTo-MarkdownCell $result.target) | $(ConvertTo-MarkdownCell $result.status) | $(ConvertTo-MarkdownCell $result.summary) |")
}
[void]$lines.Add('')
[void]$lines.Add('## Post-remediation verification')
[void]$lines.Add('')
[void]$lines.Add('| Check | Target | Result | Summary |')
[void]$lines.Add('|---|---|---|---|')
foreach ($check in @($verification.checks)) {
[void]$lines.Add("| $(ConvertTo-MarkdownCell $check.type) | $(ConvertTo-MarkdownCell $check.target) | $(ConvertTo-MarkdownCell $check.status) | $(ConvertTo-MarkdownCell $check.summary) |")
}
[void]$lines.Add('')
[void]$lines.Add('## Attacker and network information')
[void]$lines.Add('')
[void]$lines.Add("**Malware-associated remote IP address(es):** $remoteIpText")
[void]$lines.Add('')
[void]$lines.Add('A remote IP is infrastructure associated with observed malware communication; it does not by itself identify the human attacker. Simulator addresses must not be reported as hostile infrastructure.')
[void]$lines.Add('')
[void]$lines.Add('## Potential impact')
[void]$lines.Add('')
[void]$lines.Add('If executed outside the controlled lab, malware with process execution, persistence, file modification, and remote communication capabilities could regain execution after logon or reboot, expose host or user information, receive instructions, download additional payloads, and affect other reachable systems. The exact impact must be limited to behavior supported by the case evidence.')
[void]$lines.Add('')
[void]$lines.Add('## Prevention and remediation recommendations')
[void]$lines.Add('')
[void]$lines.Add('- Rebuild or revert compromised systems from a known-clean source rather than assuming deletion restores trust.')
[void]$lines.Add('- Keep Windows, applications, browsers, and security tools patched.')
[void]$lines.Add('- Enforce least privilege and avoid routine administrator use.')
[void]$lines.Add('- Monitor startup Registry values, scheduled tasks, services, Startup folders, and unusual child processes.')
[void]$lines.Add('- Use application control, endpoint protection, email filtering, and attachment sandboxing.')
[void]$lines.Add('- Restrict unnecessary outbound traffic and retain DNS, proxy, firewall, and endpoint telemetry.')
[void]$lines.Add('- Block reviewed malicious hashes, domains, and IPs only after checking for false positives and infrastructure reuse.')
[void]$lines.Add('- Preserve evidence and follow the organization incident-response process.')
[void]$lines.Add('')
[void]$lines.Add('## Malware mitigation report email')
[void]$lines.Add('')
[void]$lines.Add("**To:** $($config.reporting.securityEmail)  ")
[void]$lines.Add("**Subject:** Malware Analysis Report: Mitigation of $($config.reporting.malwareName)")
[void]$lines.Add('')
[void]$lines.Add('Dear Security Team,')
[void]$lines.Add('')
[void]$lines.Add("$emailOutcome The analysis was performed as an authorized educational exercise in an isolated Windows VM.")
[void]$lines.Add('')
[void]$lines.Add("**Summary:** The reviewed evidence identified configured process and persistence artifacts associated with $($config.reporting.malwareName). Defuse scanned the indicators and processed only separately approved remediation targets.")
[void]$lines.Add('')
[void]$lines.Add("**Proof of Mitigation:** Phase 5 returned **$verdict**. The linked evidence records $($verification.counts.passed) passed, $($verification.counts.failed) failed, and $($verification.counts.errors) error check(s). See the attached remediation and verification evidence for individual results.")
[void]$lines.Add('')
[void]$lines.Add("**Attacker Information:** Malware-associated remote IP address(es): $remoteIpText. This is network-infrastructure evidence and not direct identification of a person.")
[void]$lines.Add('')
[void]$lines.Add('Please contact me for clarification or additional evidence.')
[void]$lines.Add('')
[void]$lines.Add('Best regards,  ')
[void]$lines.Add("$($config.analyst)  ")
[void]$lines.Add([string]$config.reporting.analystContact)
[void]$lines.Add('')
[void]$lines.Add('## Ethical hacking report')
[void]$lines.Add('')
[void]$lines.Add('Malware analysis must be authorized, necessary, and contained. The analyst is responsible for protecting people and systems that are not part of the exercise, preserving evidence accurately, respecting licensing and privacy, and reporting uncertainty rather than overstating attribution or mitigation.')
[void]$lines.Add('')
[void]$lines.Add('A controlled environment is essential because malware may damage files, steal credentials, evade monitoring, spread to reachable hosts, or contact third-party infrastructure. Isolation controls include disposable VMs, clean snapshots, disabled host integration, no production access, and disconnected or simulated networking. These controls reduce risk but do not guarantee containment.')
[void]$lines.Add('')
[void]$lines.Add('Legal and ethical boundaries require explicit permission to possess and execute the sample, compliance with course and organizational rules, no testing against systems outside scope, no unauthorized interception, and no distribution of malware. Public sample uploads may disclose confidential material and should occur only with authorization.')
[void]$lines.Add('')
[void]$lines.Add('Executing malware outside isolation risks data loss, credential theft, business interruption, lateral movement, harm to unrelated third parties, and legal consequences. If containment fails, the correct response is to disconnect the lab, preserve appropriate evidence, notify the responsible party, and revert or destroy the affected VM.')
[void]$lines.Add('')
[void]$lines.Add('## Evidence scope and limitations')
[void]$lines.Add('')
[void]$lines.Add("This report was generated from $verificationPath and its linked applied-remediation report. The verdict covers only configured artifacts and checks. It does not prove that unknown persistence, dormant behavior, or unrelated compromise is absent.")

$outputDirectory = Split-Path -Parent $resolvedOutput
if (-not [string]::IsNullOrWhiteSpace($outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}
if ($PSCmdlet.ShouldProcess($resolvedOutput, 'Write evidence-driven Defuse report')) {
    $lines | Set-Content -LiteralPath $resolvedOutput -Encoding UTF8
    Write-Host "Report written to: $resolvedOutput"
    Write-Host "Verification verdict preserved as: $verdict"
}
