<#
    Script Name: VSMC vSphere 8 Guest VMware Tools Hardening Utility (P0)
    Version:     vsmc-v1
    Scope:       Audits / remediates the guest-OS VMware Tools (tools.conf)
                 P0 controls from VSMC_vSphere8_SCG_Controls_P0-P1.

    *** RUN THIS INSIDE EACH WINDOWS GUEST OS, not against vCenter. ***
    These settings are configured with VMwareToolboxCmd.exe and cannot be set
    over PowerCLI. To push it to many guests at once, wrap it with
    Invoke-VMScript (see the README) or your existing config-management tooling.

    By default this script AUDITS only. Add -Remediate to apply the VSMC values.
    Each block is annotated with its SCG ID. See docs/VSMC_P0-P1_Control_Mapping.md.
    Copyright (C) 2026 Broadcom, Inc. All rights reserved.
#>

Param (
    # Apply the VSMC values. Without this switch the script only reports current state.
    [Parameter(Mandatory=$false)][switch]$Remediate = $false,
    # Set this if the target is a TEMPLATE/golden image; skips prevent-recustomization
    # (guest-8.tools-prevent-recustomization must NOT be set on templates).
    [Parameter(Mandatory=$false)][switch]$IsTemplate = $false,
    [Parameter(Mandatory=$false)][string]$OutputFileName
)

function Log-Message {
    param([string]$Message = "", [ValidateSet("INFO","WARNING","ERROR","PASS","FAIL","UPDATE")][string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    switch ($Level) {
        "INFO"    { Write-Host $entry -ForegroundColor White }
        "WARNING" { Write-Host $entry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $entry -ForegroundColor Red }
        "PASS"    { Write-Host $entry -ForegroundColor Gray }
        "FAIL"    { Write-Host $entry -ForegroundColor Yellow }
        "UPDATE"  { Write-Host $entry -ForegroundColor Green }
    }
    if ($OutputFileName) { $entry | Out-File -FilePath $OutputFileName -Append }
}

# Locate VMwareToolboxCmd.exe (default install path per the VSMC sheet)
$toolbox = "C:\Program Files\VMware\VMware Tools\VMwareToolboxCmd.exe"
if (-not (Test-Path $toolbox)) {
    $alt = Get-ChildItem -Path "C:\Program Files*\VMware\VMware Tools\VMwareToolboxCmd.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($alt) { $toolbox = $alt.FullName }
}
if (-not (Test-Path $toolbox)) {
    Log-Message "VMwareToolboxCmd.exe not found - is this a Windows guest with VMware Tools installed?" -Level "ERROR"
    exit 1
}

Log-Message "VSMC Guest VMware Tools Hardening Utility (P0) vsmc-v1 - mode: $(if($Remediate){'REMEDIATE'}else{'AUDIT'})" -Level "INFO"

# Helper: get a tools.conf value
function Get-ToolsConf([string]$section, [string]$key) {
    try { (& $toolbox config get $section $key) 2>$null } catch { $null }
}
# Helper: set a tools.conf value
function Set-ToolsConf([string]$section, [string]$key, [string]$val) {
    & $toolbox config set $section $key $val | Out-Null
}

# section | key | desired | SCG ID
$controls = @(
    @{ Section='autoupgrade';       Key='allow-add-feature';    Desired='false';  Id='guest-8.tools-add-feature' }
    @{ Section='autoupgrade';       Key='allow-remove-feature'; Desired='false';  Id='guest-8.tools-remove-feature' }
    @{ Section='appinfo';           Key='disabled';             Desired='true';   Id='guest-8.tools-deactivate-appinfo' }
    @{ Section='containerinfo';     Key='poll-interval';        Desired='0';      Id='guest-8.tools-deactivate-containerinfo' }
    @{ Section='gueststoreupgrade'; Key='policy';               Desired='off';    Id='guest-8.tools-deactivate-gueststoreupgrade' }
    @{ Section='servicediscovery';  Key='disabled';             Desired='true';   Id='guest-8.tools-deactivate-servicediscovery' }
)

foreach ($c in $controls) {
    $cur = Get-ToolsConf $c.Section $c.Key
    if ("$cur".Trim() -ieq $c.Desired) {
        Log-Message "$($c.Id): $($c.Section) $($c.Key) already '$($c.Desired)'" -Level "PASS"
    } elseif ($Remediate) {
        try {
            Set-ToolsConf $c.Section $c.Key $c.Desired
            Log-Message "$($c.Id): $($c.Section) $($c.Key) set ('$cur' -> '$($c.Desired)')" -Level "UPDATE"
        } catch { Log-Message "$($c.Id): failed to set $($c.Section) $($c.Key): $_" -Level "ERROR" }
    } else {
        Log-Message "$($c.Id): $($c.Section) $($c.Key) is '$cur', expected '$($c.Desired)'" -Level "FAIL"
    }
}

#####################
# guest-8.tools-enable-syslog (P0): send all Tools logs to syslog
$loggingHandlers = 'vmsvc.handler','toolboxcmd.handler','vgauthsvc.handler','vmtoolsd.handler'
foreach ($h in $loggingHandlers) {
    $cur = Get-ToolsConf 'logging' $h
    if ("$cur".Trim() -ieq 'syslog') {
        Log-Message "guest-8.tools-enable-syslog: logging $h already 'syslog'" -Level "PASS"
    } elseif ($Remediate) {
        try {
            Set-ToolsConf 'logging' $h 'syslog'
            Log-Message "guest-8.tools-enable-syslog: logging $h set ('$cur' -> 'syslog')" -Level "UPDATE"
        } catch { Log-Message "guest-8.tools-enable-syslog: failed to set logging $h: $_" -Level "ERROR" }
    } else {
        Log-Message "guest-8.tools-enable-syslog: logging $h is '$cur', expected 'syslog'" -Level "FAIL"
    }
}

#####################
# guest-8.tools-prevent-recustomization (P0): deployPkg enable-customization = false
# MUST NOT be applied to template/golden images (would block customization on clone).
$cur = Get-ToolsConf 'deployPkg' 'enable-customization'
if ($IsTemplate) {
    Log-Message "guest-8.tools-prevent-recustomization: SKIPPED (-IsTemplate). Do not set on templates." -Level "WARNING"
} elseif ("$cur".Trim() -ieq 'false') {
    Log-Message "guest-8.tools-prevent-recustomization: deployPkg enable-customization already 'false'" -Level "PASS"
} elseif ($Remediate) {
    try {
        Set-ToolsConf 'deployPkg' 'enable-customization' 'false'
        Log-Message "guest-8.tools-prevent-recustomization: deployPkg enable-customization set ('$cur' -> 'false')" -Level "UPDATE"
    } catch { Log-Message "guest-8.tools-prevent-recustomization: failed: $_" -Level "ERROR" }
} else {
    Log-Message "guest-8.tools-prevent-recustomization: deployPkg enable-customization is '$cur', expected 'false'" -Level "FAIL"
}

#####################
# guest-8.tools-upgrade (P0): autoupgrade allow-upgrade = true (audit; this is the default)
$cur = Get-ToolsConf 'autoupgrade' 'allow-upgrade'
if ([string]::IsNullOrWhiteSpace("$cur") -or ("$cur".Trim() -ieq 'true')) {
    Log-Message "guest-8.tools-upgrade: autoupgrade allow-upgrade is 'true'/default ($cur)" -Level "PASS"
} else {
    Log-Message "guest-8.tools-upgrade: autoupgrade allow-upgrade is '$cur', expected 'true'" -Level "FAIL"
}

#####################
# guest-8.tools-updates (P0): VMware Tools must be kept updated - operational check.
Log-Message "guest-8.tools-updates: MANUAL - ensure VMware Tools (and vmxnet3/pvscsi drivers) are kept current" -Level "WARNING"

Log-Message "Guest VMware Tools hardening completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level "INFO"
if ($Remediate) { Log-Message "Restart VMware Tools service or reboot the guest for some settings to take effect." -Level "INFO" }
