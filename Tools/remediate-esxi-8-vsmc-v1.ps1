<#
    Script Name: VSMC vSphere 8 ESXi Security Settings Remediation Utility (P0-P1)
    Version:     vsmc-v1
    Based on:    Broadcom VCF Security Configuration & Hardening Guide vSphere 8.0
                 remediate-esxi-8.ps1 (8.0.3)
    Scope:       Remediates ONLY the ESXi P0/P1 controls selected in
                 VSMC_vSphere8_SCG_Controls_P0-P1, using the VSMC "Suggested"
                 values. Each block is annotated with its SCG ID.
                 See docs/VSMC_P0-P1_Control_Mapping.md.
    Copyright (C) 2026 Broadcom, Inc. All rights reserved.
#>

<#
    This software is provided as is and any express or implied warranties are
    disclaimed. The provider makes no claims, promises, or guarantees about the
    accuracy, completeness, or adequacy of this sample. This software is not
    supported by anyone. Make backups of all configurations and data before use.
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
    [switch]$NoSafetyChecks,
    # esxi-8.logs-remote (P0) - site-specific remote syslog target, e.g. "udp://loginsight.example.local:514"
    [Parameter(Mandatory=$false)]
    [string]$SyslogHost = "<log collector>",
    # esxi-8.logs-persistent (P0) - persistent local syslog directory
    [Parameter(Mandatory=$false)]
    [string]$SyslogDir = "[] /scratch/log",
    # esxi-8.logs-audit-persistent (P0) - persistent local audit record directory
    [Parameter(Mandatory=$false)]
    [string]$AuditLogDir = "[] /scratch/auditLog",
    # esxi-8.timekeeping-sources (P0) - NTP servers (override site-specifically)
    [Parameter(Mandatory=$false)]
    [string[]]$NtpServers = @("0.vmware.pool.ntp.org","1.vmware.pool.ntp.org","2.vmware.pool.ntp.org","3.vmware.pool.ntp.org"),
    # esxi-8.lockdown-mode (P0) - opt-in (risk of losing host access)
    [Parameter(Mandatory=$false)]
    [switch]$EnableLockdownMode = $false,
    # esxi-8.firewall-restrict-access (P1) - opt-in; restrict mgmt rulesets to $FirewallAllowedNetworks
    [Parameter(Mandatory=$false)]
    [switch]$RemediateFirewall = $false,
    [Parameter(Mandatory=$false)]
    [string]$FirewallAllowedNetworks = "192.168.0.0/16"
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
Log-Message "VSMC vSphere 8 ESXi Security Settings Remediation Utility (P0-P1) vsmc-v1" -Level "INFO"
Log-Message "Remediation of $name started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

if ($false -eq $AcceptEULA) { Accept-EULA }
Log-Message "EULA accepted." -Level "INFO"

if ($false -eq $NoSafetyChecks) {
    Check-vCenter
    Check-Hosts
} else {
    Log-Message "Safety checks skipped." -Level "INFO"
}

#####################
# By removing or commenting this section you accept any and all risk of running this script.
# Do not run this script in a production environment without review. It changes settings that
# may cause operational issues and may require host reboots. See the included documentation.
Log-Message "This script changes ESXi security settings and should be tested before production use." -Level "ERROR"
Log-Message "If you accept the risk, remove or comment the Exit on the next line (this safety block)." -Level "ERROR"
Exit

#####################
# Read the ESX host into objects and views once
$obj = Get-VMHost $name -ErrorAction Stop
$view = Get-View -VIObject $obj
$ESXcli = Get-EsxCli -VMHost $obj -V2

#####################
# Advanced parameters (P0/P1). Comparators: eq / ge / le (more secure side).
$scg_adv = @{
    'Security.PasswordQualityControl'             = @{ Expected = 'similar=deny retry=3 min=disabled,disabled,disabled,disabled,15 max=64'; Comparator = 'eq' }  # esxi-8.account-password-policies
    'Syslog.global.auditRecord.storageEnable'     = @{ Expected = $true;  Comparator = 'eq' }  # esxi-8.logs-audit-local
    'Syslog.global.auditRecord.remoteEnable'      = @{ Expected = $true;  Comparator = 'eq' }  # esxi-8.logs-audit-remote
    'Mem.MemEagerZero'                            = @{ Expected = 1;      Comparator = 'eq' }  # esxi-8.memeagerzero
    'UserVars.ESXiShellInteractiveTimeOut'        = @{ Expected = 900;    Comparator = 'le' }  # esxi-8.shell-interactive-timeout
    'UserVars.ESXiShellTimeOut'                   = @{ Expected = 600;    Comparator = 'le' }  # esxi-8.shell-timeout
    'VMkernel.Boot.execInstalledOnly'             = @{ Expected = $true;  Comparator = 'eq' }  # esxi-8.vib-trusted-binaries
    'Config.HostAgent.vmacore.soap.sessionTimeout'= @{ Expected = 10;     Comparator = 'le' }  # esxi-8.api-soap-timeout
    'Syslog.global.auditRecord.storageCapacity'   = @{ Expected = 100;    Comparator = 'ge' }  # esxi-8.logs-audit-local-capacity
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
        try {
            Get-AdvancedSetting -Entity $obj "$($param.Name)" | Set-AdvancedSetting -Value $expected -Confirm:$false -ErrorAction Stop | Out-Null
            Log-Message "$name`: $($param.Name) has been updated ($vmval -> $expected)" -Level "UPDATE"
        } catch {
            Log-Message "$name`: $($param.Name) could not be updated ($vmval)" -Level "FAIL"
        }
    }
}

#####################
# esxi-8.logs-remote (P0): Syslog.global.logHost (site-specific)
$value = (Get-AdvancedSetting -Entity $obj 'Syslog.global.logHost').Value
if (-not [string]::IsNullOrEmpty($value)) {
    Log-Message "$name`: Remote syslog host already configured ($value)" -Level "PASS"
} elseif ($SyslogHost -eq "<log collector>") {
    Log-Message "$name`: Remote syslog host not set - re-run with -SyslogHost '<udp://host:514>' (esxi-8.logs-remote)" -Level "WARNING"
} else {
    try {
        Get-AdvancedSetting -Entity $obj 'Syslog.global.logHost' | Set-AdvancedSetting -Value $SyslogHost -Confirm:$false -ErrorAction Stop | Out-Null
        Log-Message "$name`: Remote syslog host has been updated ( -> $SyslogHost)" -Level "UPDATE"
    } catch {
        Log-Message "$name`: Remote syslog host could not be updated" -Level "FAIL"
    }
}

#####################
# esxi-8.logs-persistent (P0): Syslog.global.logDir
try {
    Get-AdvancedSetting -Entity $obj 'Syslog.global.logDir' | Set-AdvancedSetting -Value $SyslogDir -Confirm:$false -ErrorAction Stop | Out-Null
    Log-Message "$name`: Persistent syslog directory set to $SyslogDir (esxi-8.logs-persistent)" -Level "UPDATE"
} catch {
    Log-Message "$name`: Could not set persistent syslog directory" -Level "FAIL"
}

#####################
# esxi-8.logs-audit-persistent (P0): Syslog.global.auditRecord.storageDirectory
try {
    Get-AdvancedSetting -Entity $obj 'Syslog.global.auditRecord.storageDirectory' | Set-AdvancedSetting -Value $AuditLogDir -Confirm:$false -ErrorAction Stop | Out-Null
    Log-Message "$name`: Persistent audit record directory set to $AuditLogDir (esxi-8.logs-audit-persistent)" -Level "UPDATE"
} catch {
    Log-Message "$name`: Could not set persistent audit record directory" -Level "FAIL"
}

#####################
# Login banners (P1): esxi-8.annotations-welcomemessage, esxi-8.etc-issue
# NOTE: Replace $sample_banner with your organization's legal text before production use.
$sample_banner = "****************************************************************************`n* Authorized users only. Actual or attempted unauthorized use of this      *`n* system is prohibited and may result in criminal, civil, security, or     *`n* administrative proceedings and/or penalties. Use of this information     *`n* system indicates consent to monitoring and recording, without notice     *`n* or permission. Users have no expectation of privacy. Any information     *`n* stored on or transiting this system, or obtained by monitoring and/or    *`n* recording, may be disclosed to law enforcement and/or used in accordance *`n* with Federal law, State statute, and organization policy. If you are not *`n* an authorized user of this system, exit the system at this time.         *`n****************************************************************************`n"

foreach ($p in 'Annotations.WelcomeMessage', 'Config.Etc.Issue') {
    $vmval = (Get-AdvancedSetting -Entity $obj $p).Value
    if ([string]::IsNullOrEmpty($vmval)) {
        try {
            Get-AdvancedSetting -Entity $obj $p | Set-AdvancedSetting -Value $sample_banner -Confirm:$false -ErrorAction Stop | Out-Null
            Log-Message "$name`: $p login banner has been configured" -Level "UPDATE"
        } catch {
            Log-Message "$name`: $p login banner could not be configured" -Level "FAIL"
        }
    } else {
        Log-Message "$name`: $p login banner already configured" -Level "PASS"
    }
}

#####################
# esxi-8.account-dcui (P0): deny shell access for the dcui account
$value = $ESXcli.system.account.list.Invoke() | Where-Object { $_.UserID -eq 'dcui' } | Select-Object -ExpandProperty Shellaccess
if ($value -eq 'false') {
    Log-Message "$name`: DCUI user shell access already deactivated ($value)" -Level "PASS"
} else {
    try {
        $arguments = $ESXcli.system.account.set.CreateArgs()
        $arguments.id = 'dcui'
        $arguments.shellaccess = "false"
        $ESXcli.system.account.set.Invoke($arguments) | Out-Null
        Log-Message "$name`: DCUI user shell access deactivated ($value -> false)" -Level "UPDATE"
    } catch {
        Log-Message "$name`: DCUI user could not be updated ($value)" -Level "FAIL"
    }
}

#####################
# esxi-8.deactivate-cim (P0) / esxi-8.deactivate-snmp (P0): stop and set policy to manual
$services_should_be_false = "sfcbd-watchdog", "snmpd"
foreach ($service in $services_should_be_false) {
    $running = $obj | Get-VMHostService | Where-Object {$_.Key -eq $service} | Select-Object -ExpandProperty Running
    if ($running -eq $false) {
        Log-Message "$name`: $service already stopped" -Level "PASS"
    } else {
        try {
            $obj | Get-VMHostService | Where-Object {$_.Key -eq $service} | Stop-VMHostService -Confirm:$false | Out-Null
            Log-Message "$name`: $service stopped" -Level "UPDATE"
        } catch { Log-Message "$name`: $service could not be stopped" -Level "FAIL" }
    }
    $policy = $obj | Get-VMHostService | Where-Object {$_.Key -eq $service} | Select-Object -ExpandProperty Policy
    if ($policy -eq 'off') {
        Log-Message "$name`: $service start policy already manual" -Level "PASS"
    } else {
        try {
            $obj | Get-VMHostService | Where-Object {$_.Key -eq $service} | Set-VMHostService -Policy "off" -Confirm:$false | Out-Null
            Log-Message "$name`: $service start policy set to manual ($policy -> off)" -Level "UPDATE"
        } catch { Log-Message "$name`: $service policy could not be configured" -Level "FAIL" }
    }
}

#####################
# esxi-8.timekeeping-sources (P0): add NTP servers if none configured
$value = $obj | Get-VMHostNtpServer
if ($null -eq $value) {
    try {
        $obj | Add-VMHostNTPServer -NtpServer $NtpServers -Confirm:$false | Out-Null
        Log-Message "$name`: NTP servers configured ($($NtpServers -join ', '))" -Level "UPDATE"
    } catch { Log-Message "$name`: NTP servers could not be configured" -Level "FAIL" }
} else {
    Log-Message "$name`: NTP servers already configured ($value)" -Level "PASS"
}

#####################
# esxi-8.timekeeping-services (P0): ntpd running and starts with host
$running = $obj | Get-VMHostService | Where-Object {$_.Key -eq 'ntpd'} | Select-Object -ExpandProperty Running
if ($running -ne $true) {
    try {
        $obj | Get-VMHostService | Where-Object {$_.Key -eq 'ntpd'} | Start-VMHostService -Confirm:$false | Out-Null
        Log-Message "$name`: ntpd started" -Level "UPDATE"
    } catch { Log-Message "$name`: ntpd could not be started" -Level "FAIL" }
} else { Log-Message "$name`: ntpd already running" -Level "PASS" }

$policy = $obj | Get-VMHostService | Where-Object {$_.Key -eq 'ntpd'} | Select-Object -ExpandProperty Policy
if ($policy -ne 'on') {
    try {
        $obj | Get-VMHostService | Where-Object {$_.Key -eq 'ntpd'} | Set-VMHostService -Policy "on" -Confirm:$false | Out-Null
        Log-Message "$name`: ntpd set to start with host ($policy -> on)" -Level "UPDATE"
    } catch { Log-Message "$name`: ntpd policy could not be configured" -Level "FAIL" }
} else { Log-Message "$name`: ntpd already starts with host" -Level "PASS" }

#####################
# esxi-8.lockdown-mode (P0): opt-in via -EnableLockdownMode
if ($EnableLockdownMode) {
    $value = (Get-View ($view).ConfigManager.HostAccessManager).LockdownMode
    if ($value -eq 'lockdownDisabled') {
        try {
            ((Get-View ($view).ConfigManager.HostAccessManager)).ChangeLockdownMode('lockdownNormal')
            Log-Message "$name`: Lockdown Mode enabled ($value -> lockdownNormal)" -Level "UPDATE"
        } catch { Log-Message "$name`: Lockdown Mode could not be configured ($value)" -Level "FAIL" }
    } else {
        Log-Message "$name`: Lockdown Mode already enabled ($value)" -Level "PASS"
    }
} else {
    Log-Message "$name`: Lockdown Mode remediation skipped (re-run with -EnableLockdownMode). esxi-8.lockdown-mode" -Level "WARNING"
}

#####################
# esxi-8.firewall-restrict-access (P1): opt-in. EXAMPLE - customize rulesets/networks for your site!
if ($RemediateFirewall) {
    try {
        $a = $ESXcli.network.firewall.set.CreateArgs(); $a.enabled = $false; $ESXcli.network.firewall.set.Invoke($a) | Out-Null
        $a = $ESXcli.network.firewall.ruleset.set.CreateArgs(); $a.allowedall = $false; $a.rulesetid = "sshServer"; $ESXcli.network.firewall.ruleset.set.Invoke($a) | Out-Null
        $a = $ESXcli.network.firewall.ruleset.allowedip.add.CreateArgs(); $a.ipaddress = $FirewallAllowedNetworks; $a.rulesetid = "sshServer"; $ESXcli.network.firewall.ruleset.allowedip.add.Invoke($a) | Out-Null
        $a = $ESXcli.network.firewall.set.CreateArgs(); $a.enabled = $true; $ESXcli.network.firewall.set.Invoke($a) | Out-Null
        Log-Message "$name`: Firewall sshServer ruleset restricted to $FirewallAllowedNetworks (EXAMPLE - extend to other rulesets as needed)" -Level "UPDATE"
    } catch { Log-Message "$name`: Firewall restriction could not be applied" -Level "FAIL" }
} else {
    Log-Message "$name`: Firewall restriction skipped (re-run with -RemediateFirewall). esxi-8.firewall-restrict-access" -Level "WARNING"
}

#####################
# esxi-8.supported (P0) / esxi-8.updates (P0): operational - cannot be auto-remediated here.
Log-Message "$name`: MANUAL - Confirm ESXi build $($obj.Build) is in General Support and fully patched (esxi-8.supported / esxi-8.updates)" -Level "WARNING"

Log-Message "Remediation of $name completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level "INFO"
Log-Message "Re-run audit-esxi-8-vsmc-v1.ps1 to verify the remediation." -Level "INFO"
