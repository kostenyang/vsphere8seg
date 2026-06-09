<#
    Script Name: VSMC vSphere 8 Security Settings Audit Utility - Run All (P0-P1)
    Version:     vsmc-v1
    Based on:    Broadcom VCF SCG vSphere 8.0 audit-all.ps1 (8.0.3)
    Scope:       Runs the VSMC P0-P1 audit across every VM, ESXi host and the
                 connected vCenter, writing one report file per object.
                 Note: guest VMware Tools (guest-8.tools-*) controls are audited
                 INSIDE each guest by guest-tools-8-vsmc-v1.ps1 and are not run here.
    Copyright (C) 2026 Broadcom, Inc. All rights reserved.
#>

Param (
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$OutputDirName,
    [Parameter(Mandatory=$false)][switch]$AcceptEULA,
    [Parameter(Mandatory=$false)][switch]$NoSafetyChecks
)

Import-Module "$PSScriptRoot\scg-common.psm1" -Force

function Log-Message {
    param([string]$Message = "", [ValidateSet("INFO","WARNING","ERROR","EULA","PASS","FAIL","UPDATE")][string]$Level = "INFO")
    Write-Log -Message $Message -Level $Level
}

$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Log-Message "VSMC vSphere 8 Security Settings Audit Utility - Run All (P0-P1) vsmc-v1" -Level "INFO"
Log-Message "Audit started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

if ($global:DefaultVIServers.Count -ne 1) {
    Log-Message "Connect to exactly one vCenter Server before running (see connect.ps1)." -Level "ERROR"; exit 1
}
if (!(Test-Path -Path $OutputDirName -PathType Container)) {
    Log-Message "The directory '$OutputDirName' does not exist. Create it and try again." -Level "ERROR"; exit 1
}
if ((Get-ChildItem -Path $OutputDirName -Force | Measure-Object).Count -ne 0) {
    Log-Message "The directory '$OutputDirName' is not empty. Empty it and try again." -Level "ERROR"; exit 1
}

$eulaArg = @{}; if ($AcceptEULA) { $eulaArg['AcceptEULA'] = $true }

try { $vms = Get-VM -ErrorAction Stop | Sort-Object Name; Log-Message "Found $($vms.Count) VMs to audit." -Level "INFO" }
catch { Log-Message "Failed to retrieve VMs: $_" -Level "ERROR"; exit 1 }
try { $hosts = Get-VMHost -ErrorAction Stop | Sort-Object Name; Log-Message "Found $($hosts.Count) ESXi hosts to audit." -Level "INFO" }
catch { Log-Message "Failed to retrieve ESXi hosts: $_" -Level "ERROR"; exit 1 }

foreach ($vm in $vms) {
    try { & "$PSScriptRoot\audit-vm-8-vsmc-v1.ps1" -Name $vm -AcceptEULA -NoSafetyChecksExceptAppliances -OutputFileName "$OutputDirName\$($vm).txt" -ErrorAction Stop }
    catch { Log-Message "Failed to audit VM '$vm': $_" -Level "ERROR" }
}
foreach ($esxi in $hosts) {
    try { & "$PSScriptRoot\audit-esxi-8-vsmc-v1.ps1" -Name $esxi -AcceptEULA -NoSafetyChecks -OutputFileName "$OutputDirName\$($esxi).txt" -ErrorAction Stop }
    catch { Log-Message "Failed to audit ESXi host '$esxi': $_" -Level "ERROR" }
}
$vc = $global:DefaultVIServers.Name
try { & "$PSScriptRoot\audit-vcenter-8-vsmc-v1.ps1" -Name $vc -AcceptEULA -NoSafetyChecks -OutputFileName "$OutputDirName\$($vc).txt" -ErrorAction Stop }
catch { Log-Message "Failed to audit vCenter '$vc': $_" -Level "ERROR" }

Log-Message "VSMC P0-P1 audit completed. Reports written to $OutputDirName." -Level "INFO"
Log-Message "Remember: guest-8.tools-* and vsan-8.operations-reserve are audited separately (see README)." -Level "WARNING"
