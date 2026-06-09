<#
    Script Name: VSMC vSphere 8 Virtual Machine Security Settings Remediation Utility (P0-P1)
    Version:     vsmc-v1
    Based on:    Broadcom VCF Security Configuration & Hardening Guide vSphere 8.0
                 remediate-vm-8.ps1 (8.0.3)
    Scope:       Remediates ONLY the Virtual Machine P0 controls selected in
                 VSMC_vSphere8_SCG_Controls_P0-P1, using VSMC "Suggested" values.
                 Each block is annotated with its SCG ID.
                 See docs/VSMC_P0-P1_Control_Mapping.md.
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
    [Parameter(Mandatory=$false)][switch]$NoSafetyChecks = $false,
    [Parameter(Mandatory=$false)][switch]$NoSafetyChecksExceptAppliances = $false,
    # vm-8.remove-unnecessary-devices (P0) - opt-in
    [Parameter(Mandatory=$false)][switch]$RemoveExtraDevices = $false,
    # guest-8.virtual-hardware (P0) - opt-in upgrade to vmx-21
    [Parameter(Mandatory=$false)][switch]$UpdateHardwareVersion = $false,
    # Take a snapshot before proceeding
    [Parameter(Mandatory=$false)][switch]$TakeSnapshot = $false
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
Log-Message "VSMC vSphere 8 Virtual Machine Security Settings Remediation Utility (P0-P1) vsmc-v1" -Level "INFO"
Log-Message "Remediation of $name started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

if ($false -eq $AcceptEULA) { Accept-EULA }
Log-Message "EULA accepted." -Level "INFO"
if ($false -eq $NoSafetyChecks) { Check-vCenter; Check-Hosts } else { Log-Message "Safety checks skipped." -Level "INFO" }

#####################
# By removing or commenting this section you accept any and all risk of running this script.
Log-Message "This script changes virtual machine settings and should be tested before production use." -Level "ERROR"
Log-Message "If you accept the risk, remove or comment the Exit on the next line (this safety block)." -Level "ERROR"
Exit

#####################
# Read the VM into objects and views once
$obj = Get-VM $name -ErrorAction Stop
$view = Get-View -VIObject $obj

# Do not modify VMware virtual appliances / vCLS containers
if (($NoSafetyChecks -eq $false) -or ($NoSafetyChecksExceptAppliances -eq $true)) {
    $flag = $false
    if ($obj | Select-Object -ExpandProperty Notes | Select-String -Pattern "VMware" -AllMatches) { $flag = $true }
    if ($obj | Select-Object -ExpandProperty Notes | Select-String -Pattern "vSphere Cluster Service" -AllMatches) { $flag = $true }
    if ($obj | Select-Object -ExpandProperty Name  | Select-String -Pattern "vCLS-" -AllMatches) { $flag = $true }
    if ($flag) {
        Log-Message "$name`: The specified object may be a VMware virtual appliance or vCLS container; skipping." -Level "ERROR"
        Exit
    }
}

#####################
# Optional snapshot before changes
if ($TakeSnapshot) {
    try {
        $obj | New-Snapshot -Name "VSMC SCG Remediation" -Description "Snapshot taken before VSMC P0-P1 remediation" -Confirm:$false | Out-Null
        Log-Message "$name`: Snapshot taken. Remember to remove it after verifying remediation." -Level "INFO"
    } catch { Log-Message "$name`: Failed to take snapshot: $_" -Level "ERROR"; Exit }
}

#####################
# vm-8.limit-console-connections (P0): RemoteDisplay.maxConnections = 1
try {
    $vmval = (Get-AdvancedSetting -Entity $obj 'RemoteDisplay.maxConnections').Value
    if ($vmval -eq 1) {
        Log-Message "$name`: RemoteDisplay.maxConnections configured correctly ($vmval)" -Level "PASS"
    } elseif ([string]::IsNullOrEmpty($vmval)) {
        New-AdvancedSetting -Entity $obj -Name 'RemoteDisplay.maxConnections' -Value 1 -Confirm:$false | Out-Null
        Log-Message "$name`: RemoteDisplay.maxConnections set (undefined -> 1)" -Level "UPDATE"
    } else {
        Get-AdvancedSetting -Entity $obj -Name 'RemoteDisplay.maxConnections' | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-Null
        Log-Message "$name`: RemoteDisplay.maxConnections updated ($vmval -> 1)" -Level "UPDATE"
    }
} catch { Log-Message "$name`: Error setting RemoteDisplay.maxConnections: $_" -Level "ERROR" }

#####################
# vm-8.vmrc-lock (P0): tools.guest.desktop.autolock = TRUE
try {
    $vmval = (Get-AdvancedSetting -Entity $obj 'tools.guest.desktop.autolock').Value
    if ($vmval -eq 'TRUE' -or $vmval -eq 'true') {
        Log-Message "$name`: tools.guest.desktop.autolock configured correctly ($vmval)" -Level "PASS"
    } elseif ([string]::IsNullOrEmpty($vmval)) {
        New-AdvancedSetting -Entity $obj -Name 'tools.guest.desktop.autolock' -Value $true -Confirm:$false | Out-Null
        Log-Message "$name`: tools.guest.desktop.autolock set (undefined -> TRUE)" -Level "UPDATE"
    } else {
        Get-AdvancedSetting -Entity $obj -Name 'tools.guest.desktop.autolock' | Set-AdvancedSetting -Value $true -Confirm:$false | Out-Null
        Log-Message "$name`: tools.guest.desktop.autolock updated ($vmval -> TRUE)" -Level "UPDATE"
    }
} catch { Log-Message "$name`: Error setting tools.guest.desktop.autolock: $_" -Level "ERROR" }

#####################
# vm-8.pci-passthrough (P0): audit-only. We do NOT auto-remove passthrough (e.g. GPUs).
$value = $obj | Get-PassthroughDevice
if ($null -eq $value) {
    Log-Message "$name`: No PCI passthrough devices configured" -Level "PASS"
} else {
    Log-Message "$name`: PCI passthrough present - NOT removed automatically. Verify business need ($($value.Name -join ', '))" -Level "WARNING"
}

#####################
# vm-8.remove-unnecessary-devices (P0): opt-in via -RemoveExtraDevices
if ($RemoveExtraDevices) {
    $ExtraHardware = "VirtualCdrom|VirtualUSBController|VirtualUSBXHCIController|VirtualParallelPort|VirtualFloppy|VirtualSerialPort|VirtualHdAudioCard|VirtualEnsoniq1371"
    $view.Config.Hardware.Device | Where-Object { $_.GetType().Name -match $ExtraHardware } | ForEach-Object {
        try {
            $devname = $_.GetType().Name
            $Config = New-Object VMware.Vim.VirtualMachineConfigSpec
            $Config.DeviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec
            $Config.DeviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec
            $Config.DeviceChange[0].Operation = "remove"
            $Config.DeviceChange[0].Device = $_
            $obj.ExtensionData.ReconfigVM($Config) | Out-Null
            Log-Message "$name`: Removed $devname device" -Level "UPDATE"
        } catch { Log-Message "$name`: Error removing device: $_" -Level "ERROR" }
    }
    # AHCI controller must be removed after the CD-ROM. Will fail if a disk is attached to it.
    $obj = Get-VM $name -ErrorAction Stop
    $view = Get-View -VIObject $obj
    $view.Config.Hardware.Device | Where-Object { $_.GetType().Name -match "VirtualAHCIController" } | ForEach-Object {
        try {
            $devname = $_.GetType().Name
            $Config = New-Object VMware.Vim.VirtualMachineConfigSpec
            $Config.DeviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec
            $Config.DeviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec
            $Config.DeviceChange[0].Operation = "remove"
            $Config.DeviceChange[0].Device = $_
            $obj.ExtensionData.ReconfigVM($Config) | Out-Null
            Log-Message "$name`: Removed $devname device" -Level "UPDATE"
        } catch { Log-Message "$name`: Error removing AHCI controller: $_" -Level "ERROR" }
    }
} else {
    Log-Message "$name`: Unnecessary-device removal skipped (re-run with -RemoveExtraDevices). vm-8.remove-unnecessary-devices" -Level "WARNING"
}

#####################
# guest-8.virtual-hardware (P0): opt-in upgrade to vmx-21
if ($UpdateHardwareVersion) {
    if ($obj.ExtensionData.Config.Version -ne 'vmx-21') {
        try {
            $obj | Set-VM -HardwareVersion vmx-21 -Confirm:$false | Out-Null
            Log-Message "$name`: VM hardware upgraded to vmx-21" -Level "UPDATE"
        } catch { Log-Message "$name`: Failed to upgrade VM hardware: $_" -Level "ERROR" }
    } else {
        Log-Message "$name`: VM hardware already vmx-21" -Level "PASS"
    }
} else {
    Log-Message "$name`: VM hardware upgrade skipped (re-run with -UpdateHardwareVersion). guest-8.virtual-hardware" -Level "WARNING"
}

Log-Message "Remediation of $name completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level "INFO"
Log-Message "Re-run audit-vm-8-vsmc-v1.ps1 to verify the remediation." -Level "INFO"
