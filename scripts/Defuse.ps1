#requires -Version 5.1
<#
.SYNOPSIS
    Indicator scanner and controlled remediation tool for Defuse.

.DESCRIPTION
    Validates that the program is running on an acknowledged Windows analysis
    lab, records system context, checks configured indicators, and can remove
    separately approved artifacts when all remediation safeguards are satisfied.

.PARAMETER ConfigPath
    Path to a JSON case configuration. The example configuration refuses to run
    until labAcknowledgement is deliberately set to true.

.PARAMETER Mode
    Scan is read-only. Remediate builds a plan unless Apply is also set. Verify
    checks post-remediation absence against a prior applied-remediation report.

.PARAMETER Apply
    Permits approved remediation actions in Remediate mode. PowerShell confirmation
    still applies. This switch is rejected in Scan mode.

.PARAMETER PreviousEvidenceDirectory
    Evidence directory from the applied Phase 4 run. Required in Verify mode.

.EXAMPLE
    .\scripts\Defuse.ps1 -ConfigPath .\config\defuse.local.json -Mode Scan

.EXAMPLE
    .\scripts\Defuse.ps1 -ConfigPath .\config\defuse.local.json -Mode Remediate

.EXAMPLE
    .\scripts\Defuse.ps1 -ConfigPath .\config\defuse.local.json -Mode Remediate -Apply

.EXAMPLE
    .\scripts\Defuse.ps1 -ConfigPath .\config\defuse.local.json -Mode Verify -PreviousEvidenceDirectory .\evidence\CASE-01-20260825T120000Z
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\defuse.local.json'),

    [Parameter()]
    [ValidateSet('Scan', 'Remediate', 'Verify')]
    [string]$Mode = 'Scan',

    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [string]$PreviousEvidenceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Defuse {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [int]$ExitCode = 1
    )

    Write-Error "DEFUSE SAFETY STOP: $Message"
    exit $ExitCode
}

function Resolve-ConfiguredPath {
    param(
        [Parameter(Mandatory)]
        [string]$Value,

        [Parameter(Mandatory)]
        [string]$BaseDirectory
    )

    if ([System.IO.Path]::IsPathRooted($Value)) {
        return [System.IO.Path]::GetFullPath($Value)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BaseDirectory $Value))
}

function Write-DefuseEvent {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [hashtable]$Data = @{}
    )

    $event = [ordered]@{
        timestampUtc = [DateTime]::UtcNow.ToString('o')
        level        = $Level
        caseId       = $script:CaseId
        mode         = $Mode
        message      = $Message
        data         = $Data
    }

    $event | ConvertTo-Json -Compress -Depth 6 | Add-Content -LiteralPath $script:LogPath -Encoding UTF8
    Write-Host "[$Level] $Message"
}

function Test-VirtualMachine {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $identity = "$($computerSystem.Manufacturer) $($computerSystem.Model)"
    $virtualizationMarkers = @(
        'VirtualBox',
        'VMware',
        'Virtual Machine',
        'KVM',
        'QEMU',
        'Xen',
        'Parallels'
    )

    $isVirtual = $false
    foreach ($marker in $virtualizationMarkers) {
        if ($identity -match [regex]::Escape($marker)) {
            $isVirtual = $true
            break
        }
    }

    return [pscustomobject]@{
        IsVirtual   = $isVirtual
        Manufacturer = $computerSystem.Manufacturer
        Model        = $computerSystem.Model
    }
}

function New-DefuseFinding {
    param(
        [Parameter(Mandatory)] [string]$Type,
        [Parameter(Mandatory)] [string]$Indicator,
        [Parameter(Mandatory)] [ValidateSet('Found', 'NotFound', 'Error')] [string]$Status,
        [Parameter(Mandatory)] [string]$Summary,
        [object]$Details = $null
    )

    return [pscustomobject][ordered]@{
        type      = $Type
        indicator = $Indicator
        status    = $Status
        summary   = $Summary
        details   = $Details
    }
}

function Find-ConfiguredProcesses {
    param([string[]]$Names)

    $processes = @(Get-CimInstance -ClassName Win32_Process)
    foreach ($configuredName in $Names) {
        $name = [System.IO.Path]::GetFileName([string]$configuredName)
        $matches = @($processes | Where-Object { $_.Name -ieq $name })
        if ($matches.Count -eq 0) {
            New-DefuseFinding -Type 'Process' -Indicator $configuredName -Status NotFound -Summary 'No exact process-name match.'
            continue
        }

        $details = @($matches | ForEach-Object {
            [ordered]@{
                name        = $_.Name
                processId   = $_.ProcessId
                parentId    = $_.ParentProcessId
                path        = $_.ExecutablePath
                commandLine = $_.CommandLine
            }
        })
        New-DefuseFinding -Type 'Process' -Indicator $configuredName -Status Found -Summary "$($matches.Count) exact process-name match(es)." -Details $details
    }
}

function Find-ConfiguredFiles {
    param([string[]]$Paths)

    foreach ($configuredPath in $Paths) {
        $path = [Environment]::ExpandEnvironmentVariables([string]$configuredPath)
        try {
            if (-not (Test-Path -LiteralPath $path)) {
                New-DefuseFinding -Type 'File' -Indicator $configuredPath -Status NotFound -Summary 'Path does not exist.'
                continue
            }

            $item = Get-Item -LiteralPath $path -Force
            $details = [ordered]@{
                resolvedPath  = $item.FullName
                itemType      = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
                length        = if ($item.PSIsContainer) { $null } else { $item.Length }
                lastWriteUtc  = $item.LastWriteTimeUtc.ToString('o')
                sha256        = if ($item.PSIsContainer) { $null } else { (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash }
            }
            New-DefuseFinding -Type 'File' -Indicator $configuredPath -Status Found -Summary 'Configured path exists.' -Details $details
        }
        catch {
            New-DefuseFinding -Type 'File' -Indicator $configuredPath -Status Error -Summary $_.Exception.Message
        }
    }
}

function Find-ConfiguredRegistryKeys {
    param([string[]]$Paths)

    foreach ($path in $Paths) {
        try {
            if (-not (Test-Path -LiteralPath $path)) {
                New-DefuseFinding -Type 'Registry' -Indicator $path -Status NotFound -Summary 'Registry key does not exist.'
                continue
            }

            $key = Get-Item -LiteralPath $path
            $values = [ordered]@{}
            foreach ($valueName in $key.GetValueNames()) {
                $displayName = if ([string]::IsNullOrEmpty($valueName)) { '(Default)' } else { $valueName }
                $values[$displayName] = $key.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
            New-DefuseFinding -Type 'Registry' -Indicator $path -Status Found -Summary 'Configured Registry key exists.' -Details @{ values = $values }
        }
        catch {
            New-DefuseFinding -Type 'Registry' -Indicator $path -Status Error -Summary $_.Exception.Message
        }
    }
}

function Find-ConfiguredScheduledTasks {
    param([string[]]$Names)

    if ($Names.Count -eq 0) { return }
    if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        foreach ($name in $Names) {
            New-DefuseFinding -Type 'ScheduledTask' -Indicator $name -Status Error -Summary 'Get-ScheduledTask is unavailable.'
        }
        return
    }

    $tasks = @(Get-ScheduledTask)
    foreach ($name in $Names) {
        $matches = @($tasks | Where-Object { $_.TaskName -ieq $name })
        if ($matches.Count -eq 0) {
            New-DefuseFinding -Type 'ScheduledTask' -Indicator $name -Status NotFound -Summary 'No exact task-name match.'
            continue
        }

        $details = @($matches | ForEach-Object {
            [ordered]@{ taskName = $_.TaskName; taskPath = $_.TaskPath; state = [string]$_.State }
        })
        New-DefuseFinding -Type 'ScheduledTask' -Indicator $name -Status Found -Summary "$($matches.Count) exact task-name match(es)." -Details $details
    }
}

function Find-ConfiguredServices {
    param([string[]]$Names)

    if ($Names.Count -eq 0) { return }
    $services = @(Get-CimInstance -ClassName Win32_Service)
    foreach ($name in $Names) {
        $matches = @($services | Where-Object { $_.Name -ieq $name })
        if ($matches.Count -eq 0) {
            New-DefuseFinding -Type 'Service' -Indicator $name -Status NotFound -Summary 'No exact service-name match.'
            continue
        }

        $details = @($matches | ForEach-Object {
            [ordered]@{ name = $_.Name; displayName = $_.DisplayName; state = $_.State; startMode = $_.StartMode; pathName = $_.PathName }
        })
        New-DefuseFinding -Type 'Service' -Indicator $name -Status Found -Summary "$($matches.Count) exact service-name match(es)." -Details $details
    }
}

function Find-ConfiguredRemoteIps {
    param([string[]]$Addresses)

    if ($Addresses.Count -eq 0) { return }
    if (-not (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        foreach ($address in $Addresses) {
            New-DefuseFinding -Type 'RemoteIp' -Indicator $address -Status Error -Summary 'Get-NetTCPConnection is unavailable.'
        }
        return
    }

    $connections = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    foreach ($address in $Addresses) {
        $parsedAddress = $null
        if (-not [System.Net.IPAddress]::TryParse($address, [ref]$parsedAddress)) {
            New-DefuseFinding -Type 'RemoteIp' -Indicator $address -Status Error -Summary 'Indicator is not a valid IPv4 or IPv6 address.'
            continue
        }

        $matches = @($connections | Where-Object { $_.RemoteAddress -eq $parsedAddress.ToString() })
        if ($matches.Count -eq 0) {
            New-DefuseFinding -Type 'RemoteIp' -Indicator $address -Status NotFound -Summary 'No active TCP connection matches this remote IP.'
            continue
        }

        $details = @($matches | ForEach-Object {
            $owner = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [ordered]@{
                remoteAddress = $_.RemoteAddress
                remotePort    = $_.RemotePort
                localAddress  = $_.LocalAddress
                localPort     = $_.LocalPort
                state         = [string]$_.State
                processId     = $_.OwningProcess
                processName   = if ($null -eq $owner) { $null } else { $owner.ProcessName }
            }
        })
        New-DefuseFinding -Type 'RemoteIp' -Indicator $address -Status Found -Summary "$($matches.Count) active TCP connection match(es)." -Details $details
    }
}

function New-RemediationResult {
    param(
        [Parameter(Mandatory)] [string]$Type,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [ValidateSet('Planned', 'Removed', 'Stopped', 'NotFound', 'Blocked', 'Declined', 'Error')] [string]$Status,
        [Parameter(Mandatory)] [string]$Summary
    )

    return [pscustomobject][ordered]@{ type = $Type; target = $Target; status = $Status; summary = $Summary }
}

function Test-Sha256Text {
    param([string]$Value)
    return $Value -match '^[a-fA-F0-9]{64}$'
}

function Get-NormalizedFilePath {
    param([string]$Path)
    return [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path)).TrimEnd('\')
}

function Test-ApprovedFile {
    param([string]$Path, [string]$ExpectedSha256)

    $resolvedPath = Get-NormalizedFilePath -Path $Path
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        return [pscustomobject]@{ Approved = $false; Missing = $true; Path = $resolvedPath; Reason = 'File does not exist.' }
    }

    $actualHash = (Get-FileHash -LiteralPath $resolvedPath -Algorithm SHA256).Hash
    if ($actualHash -ine $ExpectedSha256) {
        return [pscustomobject]@{ Approved = $false; Missing = $false; Path = $resolvedPath; Reason = "SHA-256 mismatch. Actual: $actualHash" }
    }

    return [pscustomobject]@{ Approved = $true; Missing = $false; Path = $resolvedPath; Reason = 'Path and SHA-256 match.' }
}

function Invoke-ProcessRemediation {
    param([object[]]$Artifacts, [bool]$Execute)

    $processes = @(Get-CimInstance -ClassName Win32_Process)
    foreach ($artifact in $Artifacts) {
        $target = "$($artifact.name) at $($artifact.path)"
        $fileCheck = Test-ApprovedFile -Path ([string]$artifact.path) -ExpectedSha256 ([string]$artifact.sha256)
        if (-not $fileCheck.Approved) {
            $status = if ($fileCheck.Missing) { 'NotFound' } else { 'Blocked' }
            New-RemediationResult -Type Process -Target $target -Status $status -Summary $fileCheck.Reason
            continue
        }

        $matches = @($processes | Where-Object {
            $_.Name -ieq [string]$artifact.name -and
            -not [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath) -and
            (Get-NormalizedFilePath -Path $_.ExecutablePath) -ieq $fileCheck.Path
        })
        if ($matches.Count -eq 0) {
            New-RemediationResult -Type Process -Target $target -Status NotFound -Summary 'No process matches both the approved name and executable path.'
            continue
        }
        if (-not $Execute) {
            New-RemediationResult -Type Process -Target $target -Status Planned -Summary "Would terminate $($matches.Count) verified process(es)."
            continue
        }

        foreach ($process in $matches) {
            $processTarget = "$($process.Name) PID $($process.ProcessId) at $($process.ExecutablePath)"
            try {
                if ($script:CommandRuntime.ShouldProcess($processTarget, 'Terminate verified malware process')) {
                    Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
                    New-RemediationResult -Type Process -Target $processTarget -Status Stopped -Summary 'Verified process terminated.'
                }
                else {
                    New-RemediationResult -Type Process -Target $processTarget -Status Declined -Summary 'Confirmation declined or WhatIf was used.'
                }
            }
            catch {
                New-RemediationResult -Type Process -Target $processTarget -Status Error -Summary $_.Exception.Message
            }
        }
    }
}

function Invoke-RegistryValueRemediation {
    param([object[]]$Artifacts, [bool]$Execute)

    foreach ($artifact in $Artifacts) {
        $target = "$($artifact.path) value '$($artifact.name)'"
        try {
            if (-not (Test-Path -LiteralPath ([string]$artifact.path))) {
                New-RemediationResult -Type RegistryValue -Target $target -Status NotFound -Summary 'Registry key does not exist.'
                continue
            }
            $key = Get-Item -LiteralPath ([string]$artifact.path)
            if ($artifact.name -notin $key.GetValueNames()) {
                New-RemediationResult -Type RegistryValue -Target $target -Status NotFound -Summary 'Registry value does not exist.'
                continue
            }
            $actualData = [string]$key.GetValue([string]$artifact.name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($actualData -cne [string]$artifact.expectedData) {
                New-RemediationResult -Type RegistryValue -Target $target -Status Blocked -Summary "Registry data mismatch. Actual data: $actualData"
                continue
            }
            if (-not $Execute) {
                New-RemediationResult -Type RegistryValue -Target $target -Status Planned -Summary 'Would remove the exact verified Registry value.'
                continue
            }
            if ($script:CommandRuntime.ShouldProcess($target, 'Remove verified persistence value')) {
                Remove-ItemProperty -LiteralPath ([string]$artifact.path) -Name ([string]$artifact.name) -Force
                New-RemediationResult -Type RegistryValue -Target $target -Status Removed -Summary 'Verified Registry value removed.'
            }
            else {
                New-RemediationResult -Type RegistryValue -Target $target -Status Declined -Summary 'Confirmation declined or WhatIf was used.'
            }
        }
        catch {
            New-RemediationResult -Type RegistryValue -Target $target -Status Error -Summary $_.Exception.Message
        }
    }
}

function Invoke-TaskRemediation {
    param([object[]]$Artifacts, [bool]$Execute)

    foreach ($artifact in $Artifacts) {
        $target = "$($artifact.taskPath)$($artifact.name)"
        try {
            $task = Get-ScheduledTask -TaskName ([string]$artifact.name) -TaskPath ([string]$artifact.taskPath) -ErrorAction SilentlyContinue
            if ($null -eq $task) {
                New-RemediationResult -Type ScheduledTask -Target $target -Status NotFound -Summary 'Scheduled task does not exist.'
                continue
            }
            $expectedPath = Get-NormalizedFilePath -Path ([string]$artifact.expectedExecutablePath)
            $matchingActions = @($task.Actions | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_.Execute) -and
                (Get-NormalizedFilePath -Path ([string]$_.Execute)) -ieq $expectedPath
            })
            if ($matchingActions.Count -eq 0) {
                New-RemediationResult -Type ScheduledTask -Target $target -Status Blocked -Summary 'Task action does not match the approved executable path.'
                continue
            }
            if (-not $Execute) {
                New-RemediationResult -Type ScheduledTask -Target $target -Status Planned -Summary 'Would unregister the exact verified scheduled task.'
                continue
            }
            if ($script:CommandRuntime.ShouldProcess($target, 'Unregister verified persistence task')) {
                Unregister-ScheduledTask -TaskName ([string]$artifact.name) -TaskPath ([string]$artifact.taskPath) -Confirm:$false
                New-RemediationResult -Type ScheduledTask -Target $target -Status Removed -Summary 'Verified scheduled task removed.'
            }
            else {
                New-RemediationResult -Type ScheduledTask -Target $target -Status Declined -Summary 'Confirmation declined or WhatIf was used.'
            }
        }
        catch {
            New-RemediationResult -Type ScheduledTask -Target $target -Status Error -Summary $_.Exception.Message
        }
    }
}

function Invoke-ServiceRemediation {
    param([object[]]$Artifacts, [bool]$Execute)

    foreach ($artifact in $Artifacts) {
        $target = [string]$artifact.name
        try {
            $service = Get-CimInstance -ClassName Win32_Service | Where-Object { $_.Name -ieq $target }
            if ($null -eq $service) {
                New-RemediationResult -Type Service -Target $target -Status NotFound -Summary 'Service does not exist.'
                continue
            }
            $expectedPath = Get-NormalizedFilePath -Path ([string]$artifact.expectedExecutablePath)
            $serviceExecutable = if ($service.PathName -match '^\s*"([^"]+)"') { $Matches[1] } else { ([string]$service.PathName -split '\s+')[0] }
            if ((Get-NormalizedFilePath -Path $serviceExecutable) -ine $expectedPath) {
                New-RemediationResult -Type Service -Target $target -Status Blocked -Summary "Service executable mismatch. Actual configuration: $($service.PathName)"
                continue
            }
            if (-not $Execute) {
                New-RemediationResult -Type Service -Target $target -Status Planned -Summary 'Would stop and delete the exact verified service.'
                continue
            }
            if ($script:CommandRuntime.ShouldProcess($target, 'Stop and delete verified persistence service')) {
                if ($service.State -ne 'Stopped') { Stop-Service -Name $service.Name -Force -ErrorAction Stop }
                $scOutput = & "$env:SystemRoot\System32\sc.exe" delete $service.Name 2>&1
                if ($LASTEXITCODE -ne 0) { throw "sc.exe delete failed: $($scOutput -join ' ')" }
                New-RemediationResult -Type Service -Target $target -Status Removed -Summary 'Verified service stopped and marked for deletion.'
            }
            else {
                New-RemediationResult -Type Service -Target $target -Status Declined -Summary 'Confirmation declined or WhatIf was used.'
            }
        }
        catch {
            New-RemediationResult -Type Service -Target $target -Status Error -Summary $_.Exception.Message
        }
    }
}

function Invoke-FileRemediation {
    param([object[]]$Artifacts, [bool]$Execute)

    foreach ($artifact in $Artifacts) {
        $target = [Environment]::ExpandEnvironmentVariables([string]$artifact.path)
        try {
            $fileCheck = Test-ApprovedFile -Path $target -ExpectedSha256 ([string]$artifact.sha256)
            if (-not $fileCheck.Approved) {
                $status = if ($fileCheck.Missing) { 'NotFound' } else { 'Blocked' }
                New-RemediationResult -Type File -Target $target -Status $status -Summary $fileCheck.Reason
                continue
            }
            if (-not $Execute) {
                New-RemediationResult -Type File -Target $target -Status Planned -Summary 'Would permanently delete the exact hash-verified file.'
                continue
            }
            if ($script:CommandRuntime.ShouldProcess($fileCheck.Path, 'Permanently delete verified malware file')) {
                Remove-Item -LiteralPath $fileCheck.Path -Force
                New-RemediationResult -Type File -Target $fileCheck.Path -Status Removed -Summary 'Hash-verified file permanently deleted.'
            }
            else {
                New-RemediationResult -Type File -Target $fileCheck.Path -Status Declined -Summary 'Confirmation declined or WhatIf was used.'
            }
        }
        catch {
            New-RemediationResult -Type File -Target $target -Status Error -Summary $_.Exception.Message
        }
    }
}

function New-VerificationCheck {
    param(
        [Parameter(Mandatory)] [string]$Type,
        [Parameter(Mandatory)] [string]$Target,
        [Parameter(Mandatory)] [ValidateSet('Pass', 'Fail', 'Error')] [string]$Status,
        [Parameter(Mandatory)] [string]$Summary
    )

    return [pscustomobject][ordered]@{ type = $Type; target = $Target; status = $Status; summary = $Summary }
}

function Test-ProcessAbsence {
    param([object[]]$Artifacts)

    $processes = @(Get-CimInstance -ClassName Win32_Process)
    foreach ($artifact in $Artifacts) {
        $expectedPath = Get-NormalizedFilePath -Path ([string]$artifact.path)
        $matches = @($processes | Where-Object {
            $_.Name -ieq [string]$artifact.name -and
            -not [string]::IsNullOrWhiteSpace([string]$_.ExecutablePath) -and
            (Get-NormalizedFilePath -Path $_.ExecutablePath) -ieq $expectedPath
        })
        $target = "$($artifact.name) at $expectedPath"
        if ($matches.Count -eq 0) {
            New-VerificationCheck -Type ProcessAbsent -Target $target -Status Pass -Summary 'No matching malware process is running.'
        }
        else {
            New-VerificationCheck -Type ProcessAbsent -Target $target -Status Fail -Summary "$($matches.Count) matching process(es) are still running."
        }
    }
}

function Test-FileAbsence {
    param([object[]]$Artifacts)

    foreach ($artifact in $Artifacts) {
        $path = Get-NormalizedFilePath -Path ([string]$artifact.path)
        if (Test-Path -LiteralPath $path) {
            New-VerificationCheck -Type FileAbsent -Target $path -Status Fail -Summary 'Configured malware path still exists.'
        }
        else {
            New-VerificationCheck -Type FileAbsent -Target $path -Status Pass -Summary 'Configured malware path is absent.'
        }
    }
}

function Test-RegistryValueAbsence {
    param([object[]]$Artifacts)

    foreach ($artifact in $Artifacts) {
        $target = "$($artifact.path) value '$($artifact.name)'"
        try {
            if (-not (Test-Path -LiteralPath ([string]$artifact.path))) {
                New-VerificationCheck -Type RegistryValueAbsent -Target $target -Status Pass -Summary 'Containing Registry key is absent.'
                continue
            }
            $key = Get-Item -LiteralPath ([string]$artifact.path)
            if ([string]$artifact.name -in @($key.GetValueNames())) {
                $actualData = [string]$key.GetValue([string]$artifact.name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                New-VerificationCheck -Type RegistryValueAbsent -Target $target -Status Fail -Summary "Persistence value still exists with data: $actualData"
            }
            else {
                New-VerificationCheck -Type RegistryValueAbsent -Target $target -Status Pass -Summary 'Persistence value is absent.'
            }
        }
        catch {
            New-VerificationCheck -Type RegistryValueAbsent -Target $target -Status Error -Summary $_.Exception.Message
        }
    }
}

function Test-ScheduledTaskAbsence {
    param([object[]]$Artifacts)

    foreach ($artifact in $Artifacts) {
        $target = "$($artifact.taskPath)$($artifact.name)"
        try {
            $task = Get-ScheduledTask -TaskName ([string]$artifact.name) -TaskPath ([string]$artifact.taskPath) -ErrorAction SilentlyContinue
            if ($null -eq $task) {
                New-VerificationCheck -Type ScheduledTaskAbsent -Target $target -Status Pass -Summary 'Persistence task is absent.'
            }
            else {
                New-VerificationCheck -Type ScheduledTaskAbsent -Target $target -Status Fail -Summary 'Persistence task still exists.'
            }
        }
        catch {
            New-VerificationCheck -Type ScheduledTaskAbsent -Target $target -Status Error -Summary $_.Exception.Message
        }
    }
}

function Test-ServiceAbsence {
    param([object[]]$Artifacts)

    $services = @(Get-CimInstance -ClassName Win32_Service)
    foreach ($artifact in $Artifacts) {
        $matches = @($services | Where-Object { $_.Name -ieq [string]$artifact.name })
        if ($matches.Count -eq 0) {
            New-VerificationCheck -Type ServiceAbsent -Target ([string]$artifact.name) -Status Pass -Summary 'Persistence service is absent.'
        }
        else {
            New-VerificationCheck -Type ServiceAbsent -Target ([string]$artifact.name) -Status Fail -Summary 'Persistence service still exists or remains pending deletion.'
        }
    }
}

function Test-RemoteIpInactive {
    param([string[]]$Addresses)

    if ($Addresses.Count -eq 0) { return }
    if (-not (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
        foreach ($address in $Addresses) {
            New-VerificationCheck -Type RemoteIpInactive -Target $address -Status Error -Summary 'Get-NetTCPConnection is unavailable.'
        }
        return
    }
    $connections = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    foreach ($address in $Addresses) {
        $parsedAddress = $null
        if (-not [System.Net.IPAddress]::TryParse($address, [ref]$parsedAddress)) {
            New-VerificationCheck -Type RemoteIpInactive -Target $address -Status Error -Summary 'Configured value is not a valid IP address.'
            continue
        }
        $matches = @($connections | Where-Object { $_.RemoteAddress -eq $parsedAddress.ToString() })
        if ($matches.Count -eq 0) {
            New-VerificationCheck -Type RemoteIpInactive -Target $address -Status Pass -Summary 'No active TCP connection to the malware-associated IP.'
        }
        else {
            New-VerificationCheck -Type RemoteIpInactive -Target $address -Status Fail -Summary "$($matches.Count) active TCP connection(s) still target this IP."
        }
    }
}

$isWindowsPlatform = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
if (-not $isWindowsPlatform) {
    Stop-Defuse 'This program is designed for a Windows analysis VM only.'
}

$resolvedConfigPath = [System.IO.Path]::GetFullPath($ConfigPath)
if (-not (Test-Path -LiteralPath $resolvedConfigPath -PathType Leaf)) {
    Stop-Defuse "Configuration file not found: $resolvedConfigPath. Copy config\defuse.example.json to config\defuse.local.json first."
}

try {
    $config = Get-Content -LiteralPath $resolvedConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
}
catch {
    Stop-Defuse "Configuration is not valid JSON: $($_.Exception.Message)"
}

foreach ($requiredProperty in @('labAcknowledgement', 'caseId', 'analyst', 'allowNonVirtualMachine', 'evidenceDirectory', 'indicators')) {
    if ($null -eq $config.PSObject.Properties[$requiredProperty]) {
        Stop-Defuse "Configuration is missing required property '$requiredProperty'."
    }
}

if ($Apply -and $Mode -ne 'Remediate') {
    Stop-Defuse '-Apply is valid only with -Mode Remediate.'
}

if ($Mode -ne 'Verify' -and -not [string]::IsNullOrWhiteSpace($PreviousEvidenceDirectory)) {
    Stop-Defuse '-PreviousEvidenceDirectory is valid only with -Mode Verify.'
}

$previousRemediation = $null
$previousEvidencePath = $null
if ($Mode -in @('Remediate', 'Verify')) {
    foreach ($requiredProperty in @('remediationAcknowledgement', 'remediation')) {
        if ($null -eq $config.PSObject.Properties[$requiredProperty]) {
            Stop-Defuse "Configuration is missing required remediation property '$requiredProperty'."
        }
    }
    foreach ($category in @('processArtifacts', 'registryValues', 'scheduledTasks', 'services', 'files')) {
        if ($null -eq $config.remediation.PSObject.Properties[$category]) {
            Stop-Defuse "Remediation configuration is missing category '$category'."
        }
    }

    $schemas = @{
        processArtifacts = @('name', 'path', 'sha256')
        registryValues   = @('path', 'name', 'expectedData')
        scheduledTasks   = @('name', 'taskPath', 'expectedExecutablePath')
        services         = @('name', 'expectedExecutablePath')
        files            = @('path', 'sha256')
    }
    foreach ($category in $schemas.Keys) {
        foreach ($artifact in @($config.remediation.$category)) {
            foreach ($property in $schemas[$category]) {
                if ($null -eq $artifact.PSObject.Properties[$property] -or [string]::IsNullOrWhiteSpace([string]$artifact.$property)) {
                    Stop-Defuse "Remediation category '$category' contains an artifact with missing or empty '$property'."
                }
            }
            if ($category -in @('processArtifacts', 'files') -and -not (Test-Sha256Text -Value ([string]$artifact.sha256))) {
                Stop-Defuse "Remediation category '$category' contains an invalid SHA-256 value."
            }
        }
    }

    $remediationCount = @($config.remediation.processArtifacts).Count +
        @($config.remediation.registryValues).Count +
        @($config.remediation.scheduledTasks).Count +
        @($config.remediation.services).Count +
        @($config.remediation.files).Count
    if ($remediationCount -eq 0) {
        Stop-Defuse "$Mode mode requires at least one explicitly configured remediation artifact."
    }

    if ($Apply -and $config.remediationAcknowledgement -ne $true) {
        Stop-Defuse 'Set remediationAcknowledgement to true only after reviewing every remediation artifact and taking a VM snapshot.'
    }

    if ($Apply) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Stop-Defuse 'Applied remediation requires an elevated PowerShell session.'
        }
    }

    if ($Mode -eq 'Verify') {
        if ($null -eq $config.PSObject.Properties['verification'] -or $null -eq $config.verification -or
            $null -eq $config.verification.PSObject.Properties['requireRebootAfterRemediation']) {
            Stop-Defuse "Verify mode requires configuration property 'verification.requireRebootAfterRemediation'."
        }
        if ([string]::IsNullOrWhiteSpace($PreviousEvidenceDirectory)) {
            Stop-Defuse 'Verify mode requires -PreviousEvidenceDirectory from the applied Phase 4 run.'
        }
        $previousEvidencePath = [System.IO.Path]::GetFullPath($PreviousEvidenceDirectory)
        if (-not (Test-Path -LiteralPath $previousEvidencePath -PathType Container)) {
            Stop-Defuse "Previous evidence directory does not exist: $previousEvidencePath"
        }
        $previousRemediationPath = Join-Path $previousEvidencePath 'remediation.json'
        if (-not (Test-Path -LiteralPath $previousRemediationPath -PathType Leaf)) {
            Stop-Defuse "Previous evidence is missing remediation.json: $previousRemediationPath"
        }
        try {
            $previousRemediation = Get-Content -LiteralPath $previousRemediationPath -Raw -Encoding UTF8 | ConvertFrom-Json
        }
        catch {
            Stop-Defuse "Previous remediation report is invalid JSON: $($_.Exception.Message)"
        }
        foreach ($property in @('generatedAtUtc', 'caseId', 'applyRequested', 'results')) {
            if ($null -eq $previousRemediation.PSObject.Properties[$property]) {
                Stop-Defuse "Previous remediation report is missing property '$property'."
            }
        }
        if ($previousRemediation.caseId -cne $config.caseId) {
            Stop-Defuse 'Previous remediation report caseId does not match the current configuration.'
        }
        if ($previousRemediation.applyRequested -ne $true) {
            Stop-Defuse 'Previous remediation report is a plan, not an applied remediation run.'
        }
    }
}

foreach ($requiredIndicator in @('processNames', 'filePaths', 'registryPaths', 'scheduledTaskNames', 'serviceNames', 'remoteIpAddresses')) {
    if ($null -eq $config.indicators.PSObject.Properties[$requiredIndicator]) {
        Stop-Defuse "Configuration indicators are missing required property '$requiredIndicator'."
    }

    foreach ($indicator in @($config.indicators.$requiredIndicator)) {
        if ([string]::IsNullOrWhiteSpace([string]$indicator)) {
            Stop-Defuse "Configuration indicator list '$requiredIndicator' contains an empty value."
        }
    }
}

if ($config.labAcknowledgement -ne $true) {
    Stop-Defuse 'Set labAcknowledgement to true only inside an isolated, snapshotted malware-analysis VM.'
}

if ([string]::IsNullOrWhiteSpace([string]$config.caseId) -or $config.caseId -eq 'CASE-CHANGE-ME') {
    Stop-Defuse 'Set a meaningful caseId in the local configuration.'
}

if ([string]::IsNullOrWhiteSpace([string]$config.analyst) -or $config.analyst -eq 'CHANGE-ME') {
    Stop-Defuse 'Set the analyst name in the local configuration.'
}

$vm = Test-VirtualMachine
if (-not $vm.IsVirtual -and $config.allowNonVirtualMachine -ne $true) {
    Stop-Defuse "The host does not appear to be virtual ($($vm.Manufacturer) $($vm.Model)). Use an isolated VM."
}

$configDirectory = Split-Path -Parent $resolvedConfigPath
$evidenceRoot = Resolve-ConfiguredPath -Value ([string]$config.evidenceDirectory) -BaseDirectory $configDirectory
$safeCaseId = ([string]$config.caseId) -replace '[^a-zA-Z0-9._-]', '_'
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$runDirectory = Join-Path $evidenceRoot "$safeCaseId-$runId"
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null

$script:CaseId = [string]$config.caseId
$script:LogPath = Join-Path $runDirectory 'events.jsonl'
$script:CommandRuntime = $PSCmdlet

Write-DefuseEvent -Level INFO -Message 'Defuse operation started.' -Data @{
    analyst = [string]$config.analyst
    version = '0.5.0-phase5'
    apply   = [bool]$Apply
}

$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
$lastBootUpUtc = $operatingSystem.LastBootUpTime.ToUniversalTime()
$systemContext = [ordered]@{
    collectedAtUtc = [DateTime]::UtcNow.ToString('o')
    caseId          = [string]$config.caseId
    analyst         = [string]$config.analyst
    computerName    = $env:COMPUTERNAME
    windowsVersion  = [Environment]::OSVersion.VersionString
    lastBootUpUtc   = $lastBootUpUtc.ToString('o')
    powershell      = $PSVersionTable.PSVersion.ToString()
    manufacturer    = $vm.Manufacturer
    model           = $vm.Model
    virtualMachine  = $vm.IsVirtual
    mode            = $Mode
}

$contextPath = Join-Path $runDirectory 'system-context.json'
$systemContext | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $contextPath -Encoding UTF8

Write-DefuseEvent -Level INFO -Message 'System context captured.' -Data @{
    output = $contextPath
}

$findings = @()
try {
    $findings += @(Find-ConfiguredProcesses -Names @($config.indicators.processNames))
    $findings += @(Find-ConfiguredFiles -Paths @($config.indicators.filePaths))
    $findings += @(Find-ConfiguredRegistryKeys -Paths @($config.indicators.registryPaths))
    $findings += @(Find-ConfiguredScheduledTasks -Names @($config.indicators.scheduledTaskNames))
    $findings += @(Find-ConfiguredServices -Names @($config.indicators.serviceNames))
    $findings += @(Find-ConfiguredRemoteIps -Addresses @($config.indicators.remoteIpAddresses))
}
catch {
    Write-DefuseEvent -Level ERROR -Message 'A detection category failed unexpectedly.' -Data @{ error = $_.Exception.Message }
    throw
}

$counts = [ordered]@{
    total    = @($findings).Count
    found    = @($findings | Where-Object { $_.status -eq 'Found' }).Count
    notFound = @($findings | Where-Object { $_.status -eq 'NotFound' }).Count
    errors   = @($findings | Where-Object { $_.status -eq 'Error' }).Count
}
$report = [ordered]@{
    generatedAtUtc = [DateTime]::UtcNow.ToString('o')
    caseId          = [string]$config.caseId
    mode            = $Mode
    counts          = $counts
    findings        = @($findings)
}
$findingsPath = Join-Path $runDirectory 'findings.json'
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $findingsPath -Encoding UTF8

foreach ($finding in $findings) {
    $level = if ($finding.status -eq 'Found') { 'WARNING' } elseif ($finding.status -eq 'Error') { 'ERROR' } else { 'INFO' }
    Write-DefuseEvent -Level $level -Message "$($finding.type) indicator $($finding.status): $($finding.indicator)" -Data @{
        summary = $finding.summary
    }
}

Write-DefuseEvent -Level INFO -Message 'Indicator scan completed.' -Data @{
    evidenceDirectory = $runDirectory
    findingsFile      = $findingsPath
    counts            = $counts
}

if ($Mode -eq 'Remediate') {
    $remediationResults = @()
    $remediationResults += @(Invoke-ProcessRemediation -Artifacts @($config.remediation.processArtifacts) -Execute ([bool]$Apply))
    $remediationResults += @(Invoke-ServiceRemediation -Artifacts @($config.remediation.services) -Execute ([bool]$Apply))
    $remediationResults += @(Invoke-TaskRemediation -Artifacts @($config.remediation.scheduledTasks) -Execute ([bool]$Apply))
    $remediationResults += @(Invoke-RegistryValueRemediation -Artifacts @($config.remediation.registryValues) -Execute ([bool]$Apply))
    $remediationResults += @(Invoke-FileRemediation -Artifacts @($config.remediation.files) -Execute ([bool]$Apply))

    $remediationReport = [ordered]@{
        generatedAtUtc = [DateTime]::UtcNow.ToString('o')
        caseId          = [string]$config.caseId
        applyRequested  = [bool]$Apply
        results         = @($remediationResults)
    }
    $remediationPath = Join-Path $runDirectory 'remediation.json'
    $remediationReport | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $remediationPath -Encoding UTF8

    foreach ($result in $remediationResults) {
        $level = if ($result.status -in @('Blocked', 'Error')) { 'ERROR' } elseif ($result.status -in @('Removed', 'Stopped')) { 'WARNING' } else { 'INFO' }
        Write-DefuseEvent -Level $level -Message "$($result.type) remediation $($result.status): $($result.target)" -Data @{ summary = $result.summary }
    }
    Write-DefuseEvent -Level INFO -Message 'Phase 4 remediation workflow completed.' -Data @{
        applyRequested  = [bool]$Apply
        remediationFile = $remediationPath
    }
}

$verificationVerdict = $null
if ($Mode -eq 'Verify') {
    $verificationChecks = @()

    $priorProblemResults = @($previousRemediation.results | Where-Object { $_.status -in @('Blocked', 'Declined', 'Error', 'Planned') })
    if (@($previousRemediation.results).Count -lt $remediationCount) {
        $verificationChecks += New-VerificationCheck -Type EvidenceChain -Target $previousEvidencePath -Status Fail -Summary 'Previous remediation report contains fewer results than configured artifacts.'
    }
    elseif ($priorProblemResults.Count -gt 0) {
        foreach ($problem in $priorProblemResults) {
            $verificationChecks += New-VerificationCheck -Type EvidenceChain -Target ([string]$problem.target) -Status Fail -Summary "Previous remediation result was $($problem.status): $($problem.summary)"
        }
    }
    else {
        $verificationChecks += New-VerificationCheck -Type EvidenceChain -Target $previousEvidencePath -Status Pass -Summary 'Previous report records an applied run without blocked, declined, error, or planned results.'
    }

    if ($config.verification.requireRebootAfterRemediation -eq $true) {
        $remediationTime = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse([string]$previousRemediation.generatedAtUtc, [ref]$remediationTime)) {
            $verificationChecks += New-VerificationCheck -Type RebootAfterRemediation -Target $env:COMPUTERNAME -Status Error -Summary 'Previous remediation timestamp is invalid.'
        }
        elseif ($lastBootUpUtc -gt $remediationTime.UtcDateTime) {
            $verificationChecks += New-VerificationCheck -Type RebootAfterRemediation -Target $env:COMPUTERNAME -Status Pass -Summary "Last boot $($lastBootUpUtc.ToString('o')) occurred after remediation."
        }
        else {
            $verificationChecks += New-VerificationCheck -Type RebootAfterRemediation -Target $env:COMPUTERNAME -Status Fail -Summary "No reboot after remediation. Last boot: $($lastBootUpUtc.ToString('o'))."
        }
    }

    try {
        $verificationChecks += @(Test-ProcessAbsence -Artifacts @($config.remediation.processArtifacts))
        $verificationChecks += @(Test-ServiceAbsence -Artifacts @($config.remediation.services))
        $verificationChecks += @(Test-ScheduledTaskAbsence -Artifacts @($config.remediation.scheduledTasks))
        $verificationChecks += @(Test-RegistryValueAbsence -Artifacts @($config.remediation.registryValues))
        $verificationChecks += @(Test-FileAbsence -Artifacts @($config.remediation.files))
        $verificationChecks += @(Test-RemoteIpInactive -Addresses @($config.indicators.remoteIpAddresses))
    }
    catch {
        $verificationChecks += New-VerificationCheck -Type VerificationRuntime -Target $env:COMPUTERNAME -Status Error -Summary $_.Exception.Message
    }

    $verificationCounts = [ordered]@{
        total  = @($verificationChecks).Count
        passed = @($verificationChecks | Where-Object { $_.status -eq 'Pass' }).Count
        failed = @($verificationChecks | Where-Object { $_.status -eq 'Fail' }).Count
        errors = @($verificationChecks | Where-Object { $_.status -eq 'Error' }).Count
    }
    $verificationVerdict = if ($verificationCounts.failed -gt 0) {
        'Fail'
    }
    elseif ($verificationCounts.errors -gt 0) {
        'Inconclusive'
    }
    else {
        'Pass'
    }

    $verificationReport = [ordered]@{
        generatedAtUtc           = [DateTime]::UtcNow.ToString('o')
        caseId                  = [string]$config.caseId
        verdict                 = $verificationVerdict
        previousEvidence       = $previousEvidencePath
        previousRemediationUtc = [string]$previousRemediation.generatedAtUtc
        currentBootUtc         = $lastBootUpUtc.ToString('o')
        counts                  = $verificationCounts
        checks                  = @($verificationChecks)
    }
    $verificationPath = Join-Path $runDirectory 'verification.json'
    $verificationReport | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $verificationPath -Encoding UTF8

    foreach ($check in $verificationChecks) {
        $level = if ($check.status -eq 'Pass') { 'INFO' } elseif ($check.status -eq 'Fail') { 'WARNING' } else { 'ERROR' }
        Write-DefuseEvent -Level $level -Message "$($check.type) verification $($check.status): $($check.target)" -Data @{ summary = $check.summary }
    }
    Write-DefuseEvent -Level INFO -Message "Phase 5 verification verdict: $verificationVerdict" -Data @{
        verificationFile = $verificationPath
        counts           = $verificationCounts
    }
}

Write-Host "`nEvidence saved to: $runDirectory"
Write-Host "Findings: $($counts.found) found, $($counts.notFound) not found, $($counts.errors) errors."
if ($Mode -eq 'Scan') {
    Write-Host 'Scan mode is read-only. No remediation was performed.'
}
elseif (-not $Apply) {
    if ($Mode -eq 'Remediate') {
        Write-Host 'Remediation plan only: no changes were made. Review remediation.json, then use -Apply when approved.'
    }
    else {
        Write-Host "Verification verdict: $verificationVerdict. Review verification.json for proof and exceptions."
        if ($verificationVerdict -eq 'Fail') { exit 2 }
        if ($verificationVerdict -eq 'Inconclusive') { exit 3 }
    }
}
elseif ($Mode -eq 'Remediate') {
    Write-Host 'Applied remediation finished. Review remediation.json and run a new Scan for verification.'
}
