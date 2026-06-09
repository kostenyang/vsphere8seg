<#
    Script Name: VSMC vSphere 8 ESXi Security Settings Audit Utility (P0-P1)
    Version:     vsmc-v1
    Based on:    Broadcom VCF Security Configuration & Hardening Guide vSphere 8.0
                 audit-esxi-8.ps1 (8.0.3)
    Scope:       Audits ONLY the ESXi P0/P1 controls selected in
                 VSMC_vSphere8_SCG_Controls_P0-P1. Each test block is annotated
                 with its SCG ID. See docs/VSMC_P0-P1_Control_Mapping.md.
    Copyright (C) 2026 Broadcom, Inc. All rights reserved.
#>

<#
    This software is provided as is and any express or implied warranties are
    disclaimed. The provider makes no claims, promises, or guarantees about the
    accuracy, completeness, or adequacy of this sample. Organizations should
    engage appropriate legal, business, technical, and audit expertise within
    their specific organization for review of requirements and effectiveness of
    implementations. This software is not supported by anyone.

    Make backups of all configurations and data before using this tool.
#>

Param (
    # ESX Host Name
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Name,
    # Output File Name
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFileName,
    # Accept-EULA
    [Parameter(Mandatory=$false)]
    [switch]$AcceptEULA,
    # Skip safety checks
    [Parameter(Mandatory=$false)]
    [switch]$NoSafetyChecks
)

# Import common functions
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
Log-Message "VSMC vSphere 8 ESXi Security Settings Audit Utility (P0-P1) vsmc-v1" -Level "INFO"
Log-Message "Audit of $name started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

if ($false -eq $AcceptEULA) { Accept-EULA }
Log-Message "EULA accepted." -Level "INFO"

if ($false -eq $NoSafetyChecks) {
    Check-vCenter
    Check-Hosts
} else {
    Log-Message "Safety checks skipped." -Level "INFO"
}

#####################
# Read the ESX host into objects and views once to save time & resources
$obj = Get-VMHost $name -ErrorAction Stop
$view = Get-View -VIObject $obj
$ESXcli = Get-EsxCli -VMHost $obj -V2

#####################
# Advanced parameters (P0/P1) selected from the VSMC control sheet.
# Comparators: eq = equal, ge = greater or equal (more secure), le = less or equal (more secure)
$scg_adv = @{
    # esxi-8.account-password-policies (P0)
    'Security.PasswordQualityControl'             = @{ Expected = 'similar=deny retry=3 min=disabled,disabled,disabled,disabled,15 max=64'; Comparator = 'eq' }
    # esxi-8.logs-audit-local (P0)
    'Syslog.global.auditRecord.storageEnable'     = @{ Expected = $true;  Comparator = 'eq' }
    # esxi-8.logs-audit-remote (P0)
    'Syslog.global.auditRecord.remoteEnable'      = @{ Expected = $true;  Comparator = 'eq' }
    # esxi-8.memeagerzero (P0)
    'Mem.MemEagerZero'                            = @{ Expected = 1;      Comparator = 'eq' }
    # esxi-8.shell-interactive-timeout (P0)
    'UserVars.ESXiShellInteractiveTimeOut'        = @{ Expected = 900;    Comparator = 'le' }
    # esxi-8.shell-timeout (P0)
    'UserVars.ESXiShellTimeOut'                   = @{ Expected = 600;    Comparator = 'le' }
    # esxi-8.vib-trusted-binaries (P0)
    'VMkernel.Boot.execInstalledOnly'             = @{ Expected = $true;  Comparator = 'eq' }
    # esxi-8.api-soap-timeout (P1)
    'Config.HostAgent.vmacore.soap.sessionTimeout'= @{ Expected = 10;     Comparator = 'le' }
    # esxi-8.logs-audit-local-capacity (P1)
    'Syslog.global.auditRecord.storageCapacity'   = @{ Expected = 100;    Comparator = 'ge' }
}

foreach ($param in $scg_adv.GetEnumerator()) {
    $vmval = (Get-AdvancedSetting -Entity $obj "$($param.Name)").Value
    $expected = $param.Value.Expected
    $pass = switch ($param.Value.Comparator) {
        'eq' { $vmval -eq $expected }
        'ge' { $vmval -ge $expected }
        'le' { $vmval -le $expected }
    }
    if ($pass) {
        Log-Message "$name`: $($param.Name) configured correctly ($vmval)" -Level "PASS"
    } else {
        Log-Message "$name`: $($param.Name) not configured correctly ($vmval, expected $($param.Value.Comparator) $expected)" -Level "FAIL"
    }
}

#####################
# Login banners (P1): esxi-8.annotations-welcomemessage, esxi-8.etc-issue
# A non-empty value is treated as configured (site-specific legal text).
$scg_banner = 'Annotations.WelcomeMessage', 'Config.Etc.Issue'
foreach ($p in $scg_banner) {
    $vmval = (Get-AdvancedSetting -Entity $obj $p).Value
    if ([string]::IsNullOrEmpty($vmval)) {
        Log-Message "$name`: $p login banner is not configured" -Level "FAIL"
    } else {
        Log-Message "$name`: $p login banner is configured" -Level "PASS"
    }
}

#####################
# esxi-8.logs-remote (P0): Syslog.global.logHost
$value = (Get-AdvancedSetting -Entity $obj 'Syslog.global.logHost').Value
if ([string]::IsNullOrEmpty($value)) {
    Log-Message "$name`: Remote syslog host (Syslog.global.logHost) is not configured" -Level "FAIL"
} else {
    Log-Message "$name`: Remote syslog host is configured ($value)" -Level "PASS"
}

#####################
# esxi-8.logs-persistent (P0) and esxi-8.logs-audit-persistent (P0)
$persistent    = $ESXcli.system.syslog.config.get.Invoke() | Select-Object -ExpandProperty LocalLogOutputIsPersistent
$localsyslog   = $ESXcli.system.syslog.config.get.Invoke() | Select-Object -ExpandProperty LocalLogOutput
$localauditlog = (Get-AdvancedSetting -Entity $obj 'Syslog.global.auditRecord.storageDirectory').Value

if ($persistent) {
    Log-Message "$name`: Local log location is persistent ($localsyslog)" -Level "PASS"
} else {
    Log-Message "$name`: Local log location is not persistent ($localsyslog)" -Level "FAIL"
}
if (($localsyslog -like "/scratch*") -and ($localauditlog -like "*scratch*") -and ($persistent)) {
    Log-Message "$name`: Local audit log location is persistent ($localsyslog, $localauditlog)" -Level "PASS"
} else {
    Log-Message "$name`: Local audit log location is not persistent ($localsyslog, $localauditlog)" -Level "FAIL"
}

#####################
# esxi-8.account-dcui (P0): dcui account shell access must be denied
$value = $ESXcli.system.account.list.Invoke() | Where-Object { $_.UserID -eq 'dcui' } | Select-Object -ExpandProperty Shellaccess
if ($value -eq 'false') {
    Log-Message "$name`: DCUI user has shell access deactivated ($value)" -Level "PASS"
} else {
    Log-Message "$name`: DCUI user has shell access enabled ($value)" -Level "FAIL"
}

#####################
# esxi-8.deactivate-cim (P0) / esxi-8.deactivate-snmp (P0) / esxi-8.timekeeping-services (P0)
$services_should_be_false = "sfcbd-watchdog", "snmpd"   # CIM, SNMP
foreach ($service in $services_should_be_false) {
    $running = $obj | Get-VMHostService | Where-Object {$_.Key -eq $service} | Select-Object -ExpandProperty Running
    $policy  = $obj | Get-VMHostService | Where-Object {$_.Key -eq $service} | Select-Object -ExpandProperty Policy
    if ($running -eq $false) {
        Log-Message "$name`: $service is not running ($running)" -Level "PASS"
    } else {
        Log-Message "$name`: $service is running ($running)" -Level "FAIL"
    }
    # VSMC suggested policy is "Start and stop manually" (= 'off')
    if ($policy -eq 'off') {
        Log-Message "$name`: $service start policy is manual ($policy)" -Level "PASS"
    } else {
        Log-Message "$name`: $service start policy is not manual ($policy)" -Level "FAIL"
    }
}

# esxi-8.timekeeping-services (P0): ntpd should be running and start with host
$running = $obj | Get-VMHostService | Where-Object {$_.Key -eq 'ntpd'} | Select-Object -ExpandProperty Running
$policy  = $obj | Get-VMHostService | Where-Object {$_.Key -eq 'ntpd'} | Select-Object -ExpandProperty Policy
if ($running -eq $true) {
    Log-Message "$name`: ntpd is running ($running)" -Level "PASS"
} else {
    Log-Message "$name`: ntpd is not running ($running)" -Level "FAIL"
}
if ($policy -eq 'on') {
    Log-Message "$name`: ntpd is configured to start with host ($policy)" -Level "PASS"
} else {
    Log-Message "$name`: ntpd is not configured to start with host ($policy)" -Level "FAIL"
}

#####################
# esxi-8.timekeeping-sources (P0): NTP servers must be defined
$value = $obj | Get-VMHostNtpServer
if ($null -eq $value) {
    Log-Message "$name`: NTP client not configured ($value)" -Level "FAIL"
} else {
    Log-Message "$name`: NTP client configured ($value)" -Level "PASS"
}

#####################
# esxi-8.lockdown-mode (P0): Normal lockdown mode should be enabled
$value = (Get-View ($view).ConfigManager.HostAccessManager).LockdownMode
if ($value -eq 'lockdownDisabled') {
    Log-Message "$name`: Lockdown Mode is not enabled ($value)" -Level "FAIL"
} else {
    Log-Message "$name`: Lockdown Mode is enabled ($value)" -Level "PASS"
}

#####################
# esxi-8.firewall-restrict-access (P1): firewall should not allow all networks for management rulesets
$ruleset = $ESXcli.network.firewall.ruleset.list.Invoke() | Where-Object { $_.Name -eq 'sshServer' }
if ($ruleset -and ($ruleset.AllowedIPAllOff -eq $false -or $ruleset.AllowedAll -eq $false)) {
    Log-Message "$name`: ESXi firewall sshServer ruleset restricts source networks (AllowedAll=$($ruleset.AllowedAll))" -Level "PASS"
} else {
    Log-Message "$name`: ESXi firewall sshServer ruleset allows all source networks - restrict to authorized networks" -Level "FAIL"
}

#####################
# esxi-8.supported (P0) and esxi-8.updates (P0): version / patch level are operational checks.
Log-Message "$name`: MANUAL - Confirm ESXi build $($obj.Build) is in General Support and fully patched (esxi-8.supported / esxi-8.updates)" -Level "WARNING"

Log-Message "$name`: Audit of $name completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level "INFO"
