<#
    Script Name: VSMC vSphere 8 vCenter Security Settings Remediation Utility (P0-P1)
    Version:     vsmc-v1
    Based on:    Broadcom VCF Security Configuration & Hardening Guide vSphere 8.0
                 remediate-vcenter-8.ps1 (8.0.3)
    Scope:       Remediates ONLY the automatable vCenter P0/P1 controls selected
                 in VSMC_vSphere8_SCG_Controls_P0-P1, using VSMC "Suggested"
                 values. Each block is annotated with its SCG ID.
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
    # vcenter-8.vami-syslog (P0) - remote syslog target(s), e.g. "loginsight.example.local"
    [Parameter(Mandatory=$false)][string]$SyslogHost,
    [Parameter(Mandatory=$false)][int]$SyslogPort = 514,
    [Parameter(Mandatory=$false)][ValidateSet("udp","tcp","tls","relp")][string]$SyslogProtocol = "udp",
    # vcenter-8.vami-time (P0) - NTP servers
    [Parameter(Mandatory=$false)][string[]]$NtpServers = @("0.vmware.pool.ntp.org","1.vmware.pool.ntp.org","2.vmware.pool.ntp.org","3.vmware.pool.ntp.org")
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

#######################################################################################################

$currentDateTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Log-Message "VSMC vSphere 8 vCenter Security Settings Remediation Utility (P0-P1) vsmc-v1" -Level "INFO"
Log-Message "Remediation of $name started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

if ($false -eq $AcceptEULA) { Accept-EULA }
Log-Message "EULA accepted." -Level "INFO"
if ($false -eq $NoSafetyChecks) { Check-vCenter } else { Log-Message "Safety checks skipped." -Level "INFO" }

#####################
# By removing or commenting this section you accept any and all risk of running this script.
Log-Message "This script changes vCenter security settings and should be tested before production use." -Level "ERROR"
Log-Message "If you accept the risk, remove or comment the Exit on the next line (this safety block)." -Level "ERROR"
Exit

$VC = $Name

#####################
# vcenter-8.etc-issue (P1): replace default SSH banner. Customize legal text for your site!
$sample_banner = "****************************************************************************`n* Authorized users only. Actual or attempted unauthorized use of this      *`n* system is prohibited and may result in criminal, civil, security, or     *`n* administrative proceedings and/or penalties. Use of this information     *`n* system indicates consent to monitoring and recording, without notice     *`n* or permission. Users have no expectation of privacy. Any information     *`n* stored on or transiting this system, or obtained by monitoring and/or    *`n* recording, may be disclosed to law enforcement and/or used in accordance *`n* with Federal law, State statute, and organization policy. If you are not *`n* an authorized user of this system, exit the system at this time.         *`n****************************************************************************`n"
$value = (Get-AdvancedSetting -Entity $VC -Name 'etc.issue' | Select-Object -ExpandProperty Value)
$singleline = $value -replace '\r?\n', ' '
if ($value -match 'Platform Services Controller' -or [string]::IsNullOrEmpty($value)) {
    try {
        Get-AdvancedSetting -Entity $VC -Name 'etc.issue' | Set-AdvancedSetting -Value $sample_banner -Confirm:$false | Out-Null
        Log-Message "etc.issue banner updated ($singleline -> custom)" -Level "UPDATE"
    } catch { Log-Message "Failed to set etc.issue: $_" -Level "ERROR" }
} else {
    Log-Message "etc.issue already configured with custom content ($singleline)" -Level "PASS"
}

#####################
# SSO lockout policy
# vcenter-8.administration-sso-lockout-policy-unlock-time (P0): AutoUnlockIntervalSec = 0
# vcenter-8.administration-failed-login-interval (P1): FailedAttemptIntervalSec = 900
try {
    $lp = Get-SsoLockoutPolicy
    if ($lp.AutoUnlockIntervalSec -eq 0) {
        Log-Message "SSO AutoUnlockIntervalSec configured correctly ($($lp.AutoUnlockIntervalSec))" -Level "PASS"
    } else {
        Get-SsoLockoutPolicy | Set-SsoLockoutPolicy -AutoUnlockIntervalSec 0 | Out-Null
        Log-Message "SSO AutoUnlockIntervalSec updated ($($lp.AutoUnlockIntervalSec) -> 0)" -Level "UPDATE"
    }
    if ($lp.FailedAttemptIntervalSec -ge 900) {
        Log-Message "SSO FailedAttemptIntervalSec configured correctly ($($lp.FailedAttemptIntervalSec))" -Level "PASS"
    } else {
        Get-SsoLockoutPolicy | Set-SsoLockoutPolicy -FailedAttemptIntervalSec 900 | Out-Null
        Log-Message "SSO FailedAttemptIntervalSec updated ($($lp.FailedAttemptIntervalSec) -> 900)" -Level "UPDATE"
    }
} catch { Log-Message "Failed to set SSO Lockout Policy: $_" -Level "ERROR" }

#####################
# SSO password policy (P1): vcenter-8.administration-sso-password-lifetime / -sso-password-policy
try {
    Get-SsoPasswordPolicy | Set-SsoPasswordPolicy `
        -PasswordLifetimeDays 9999 `
        -MinLength 15 -MaxLength 64 `
        -MinNumericCount 1 -MinSpecialCharCount 1 -MinAlphabeticCount 2 `
        -MinUppercaseCount 1 -MinLowercaseCount 1 `
        -MaxIdenticalAdjacentCharacters 3 | Out-Null
    Log-Message "SSO password policy updated (lifetime 9999, min 15 / max 64, complexity per VSMC)" -Level "UPDATE"
} catch { Log-Message "Failed to set SSO Password Policy: $_" -Level "ERROR" }

#####################
# vcenter-8.vami-administration-password-expiration (P0): root password does not expire.
# VSMC remediation: set max_days = -1.
try {
    $value = (Get-CisService -Name "com.vmware.appliance.local_accounts.policy").get() | Select-Object -ExpandProperty max_days
    if ($value -eq -1) {
        Log-Message "vCenter appliance root password expiration already disabled (max_days=$value)" -Level "PASS"
    } else {
        (Get-CisService -Name "com.vmware.appliance.local_accounts.policy").set(@{max_days=-1}) | Out-Null
        Log-Message "vCenter appliance root password expiration disabled (max_days=$value -> -1)" -Level "UPDATE"
    }
} catch { Log-Message "Failed to set appliance root password expiration: $_" -Level "ERROR" }

#####################
# vcenter-8.vami-time (P0): configure NTP time synchronization
try {
    (Get-CisService -Name "com.vmware.appliance.ntp").set($NtpServers) | Out-Null
    (Get-CisService -Name "com.vmware.appliance.timesync").set("NTP") | Out-Null
    Log-Message "vCenter appliance NTP configured ($($NtpServers -join ', ')), time sync set to NTP" -Level "UPDATE"
} catch { Log-Message "Failed to configure appliance NTP: $_" -Level "ERROR" }

#####################
# vcenter-8.vami-syslog (P0): configure remote log forwarding (site-specific).
if ($PSBoundParameters.ContainsKey('SyslogHost') -and -not [string]::IsNullOrEmpty($SyslogHost)) {
    try {
        $cfg = @{ hostname = $SyslogHost; port = $SyslogPort; protocol = $SyslogProtocol }
        (Get-CisService -Name "com.vmware.appliance.logging.forwarding").set(@($cfg)) | Out-Null
        Log-Message "vCenter appliance log forwarding set to $SyslogProtocol`://$SyslogHost`:$SyslogPort" -Level "UPDATE"
    } catch { Log-Message "Failed to configure appliance log forwarding: $_" -Level "ERROR" }
} else {
    Log-Message "Remote syslog not set - re-run with -SyslogHost '<host>' to remediate vcenter-8.vami-syslog" -Level "WARNING"
}

#####################
# Controls with no public API / no PowerCLI - operational remediation required.
Log-Message "MANUAL - vSphere Client session timeout must be 15 minutes (vcenter-8.administration-client-session-timeout)" -Level "WARNING"
Log-Message "MANUAL - Separate authentication/authorization SSO groups for admins (vcenter-8.administration-sso-groups)" -Level "WARNING"
Log-Message "MANUAL - Login banner: use /opt/vmware/bin/sso-config.sh -set_logon_banner from appliance shell, then disable shell (vcenter-8.administration-login-message-*)" -Level "WARNING"
Log-Message "MANUAL - Configure File-Based Backup in VAMI (vcenter-8.vami-backup)" -Level "WARNING"
Log-Message "MANUAL - Restrict VAMI firewall to authorized networks (vcenter-8.vami-firewall-restrict-access)" -Level "WARNING"

Log-Message "Remediation of $name completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level "INFO"
Log-Message "Re-run audit-vcenter-8-vsmc-v1.ps1 to verify the remediation." -Level "INFO"
