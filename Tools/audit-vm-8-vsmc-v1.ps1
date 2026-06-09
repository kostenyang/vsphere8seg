<#
    Script Name: VSMC vSphere 8 Virtual Machine Security Settings Audit Utility (P0-P1)
    Version:     vsmc-v1
    Based on:    Broadcom VCF Security Configuration & Hardening Guide vSphere 8.0
                 audit-vm-8.ps1 (8.0.3)
    Scope:       Audits ONLY the Virtual Machine P0 controls selected in
                 VSMC_vSphere8_SCG_Controls_P0-P1. Each block is annotated with
                 its SCG ID. See docs/VSMC_P0-P1_Control_Mapping.md.
    Copyright (C) 2026 Broadcom, Inc. All rights reserved.
#>

<#
    This software is provided as is and any express or implied warranties are
    disclaimed. This software is not supported by anyone. Make backups before use.
#>

Param (
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$Name,
    [Parameter(Mandatory=$false)][ValidateNotNullOrEmpty()][string]$OutputFileName,
    [Parameter(Mandatory=$false)][switch]$AcceptEULA,
    [Parameter(Mandatory=$false)][switch]$NoSafetyChecks,
    [Parameter(Mandatory=$false)][switch]$NoSafetyChecksExceptAppliances = $false
)

Import-Module "$PSScriptRoot\scg-common.psm1" -Force

function Log-Message {
    param (
        [Parameter(Mandatory=$false)][AllowEmptyString()][AllowNull()][string]$Message = "",
        [Parameter(Mandatory=$false)][ValidateSet("INFO", "WARNING", "ERROR", "EULA", "PASS", "FAIL", "UPDATE")][string]$Level = "INFO"
    )
    Write-Log -Message $Message -Level $Level -OutputFileName $OutputFileName
}
Function Accept-EULA() { Show-EULA -OutputFileName $OutputFileName }
Function Check-vCenter() { if (-not (Test-vCenterConnection -OutputFileName $OutputFileName)) { Exit } }
Function Check-Hosts() { if (-not (Test-HostsExist -OutputFileName $OutputFileName)) { Exit } }

#######################################################################################################

$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Log-Message "VSMC vSphere 8 Virtual Machine Security Settings Audit Utility (P0-P1) vsmc-v1" -Level "INFO"
Log-Message "Audit of $name started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

if ($false -eq $AcceptEULA) { Accept-EULA }
Log-Message "EULA accepted." -Level "INFO"
if ($false -eq $NoSafetyChecks) { Check-vCenter; Check-Hosts } else { Log-Message "Safety checks skipped." -Level "INFO" }

#####################
# Read the VM into objects and views once
$obj = Get-VM $name -ErrorAction Stop
$view = Get-View -VIObject $obj

# Broadcom/VMware support policy does not permit changes to VMware virtual appliances
if (($NoSafetyChecks -eq $false) -or ($NoSafetyChecksExceptAppliances -eq $true)) {
    $flag = $false
    if ($obj | Select-Object -ExpandProperty Notes | Select-String -Pattern "VMware" -AllMatches) { $flag = $true }
    if ($obj | Select-Object -ExpandProperty Notes | Select-String -Pattern "vSphere Cluster Service" -AllMatches) { $flag = $true }
    if ($obj | Select-Object -ExpandProperty Name  | Select-String -Pattern "vCLS-" -AllMatches) { $flag = $true }
    if ($flag) {
        Log-Message "$name`: The specified object may be a VMware virtual appliance or vCLS container; skipping." -Level "ERROR"
        Log-Message "$name`: Use -NoSafetyChecks or -NoSafetyChecksExceptAppliances to override." -Level "ERROR"
        Exit
    }
}

#####################
# guest-8.virtual-hardware (P0): VM hardware version 19 or newer (VSMC target vmx-21)
$value = $view.Config.Version
switch ($value) {
    'vmx-19' { Log-Message "$name`: VM Hardware 19 - meets minimum, VSMC target is vmx-21 ($value)" -Level "PASS" }
    'vmx-20' { Log-Message "$name`: VM Hardware 20 - meets minimum, VSMC target is vmx-21 ($value)" -Level "PASS" }
    'vmx-21' { Log-Message "$name`: VM Hardware 21 - meets VSMC target ($value)" -Level "PASS" }
    Default  { Log-Message "$name`: VM Hardware version should be 19 or later, target vmx-21 ($value)" -Level "FAIL" }
}

#####################
# vm-8.limit-console-connections (P0): RemoteDisplay.maxConnections = 1
$vmval = (Get-AdvancedSetting -Entity $obj 'RemoteDisplay.maxConnections').Value
if ($vmval -eq 1) {
    Log-Message "$name`: RemoteDisplay.maxConnections configured correctly ($vmval)" -Level "PASS"
} else {
    Log-Message "$name`: RemoteDisplay.maxConnections not configured correctly ($vmval, expected 1)" -Level "FAIL"
}

#####################
# vm-8.vmrc-lock (P0): tools.guest.desktop.autolock = TRUE
$vmval = (Get-AdvancedSetting -Entity $obj 'tools.guest.desktop.autolock').Value
switch ($vmval) {
    'TRUE'  { Log-Message "$name`: tools.guest.desktop.autolock configured correctly ($vmval)" -Level "PASS" }
    'true'  { Log-Message "$name`: tools.guest.desktop.autolock configured correctly ($vmval)" -Level "PASS" }
    Default { Log-Message "$name`: tools.guest.desktop.autolock not set to TRUE ($vmval)" -Level "FAIL" }
}

#####################
# vm-8.pci-passthrough (P0): PCI passthrough must be limited/documented (audit-only)
$value = $obj | Get-PassthroughDevice
if ($null -eq $value) {
    Log-Message "$name`: No PCI passthrough devices configured" -Level "PASS"
} else {
    Log-Message "$name`: PCI passthrough configured - verify business need and document ($($value.Name -join ', '))" -Level "FAIL"
}

#####################
# vm-8.remove-unnecessary-devices (P0): no unnecessary virtual hardware
$UnnecessaryHardware = "VirtualUSBController|VirtualUSBXHCIController|VirtualParallelPort|VirtualFloppy|VirtualSerialPort|VirtualHdAudioCard|VirtualAHCIController|VirtualEnsoniq1371|VirtualCdrom"
$found = $false
$view.Config.Hardware.Device | Where-Object { $_.GetType().Name -match $UnnecessaryHardware } | ForEach-Object {
    $found = $true
    Log-Message "$name`: $($_.GetType().Name) device present - evaluate and remove if unnecessary" -Level "FAIL"
}
if (-not $found) {
    Log-Message "$name`: No unnecessary virtual hardware devices present" -Level "PASS"
}

Log-Message "$name`: Audit of $name completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level "INFO"
