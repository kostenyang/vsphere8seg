<#
    Script Name: VSMC vSphere 8 vCenter Security Settings Audit Utility (P0-P1)
    Version:     vsmc-v1
    Based on:    Broadcom VCF Security Configuration & Hardening Guide vSphere 8.0
                 audit-vcenter-8.ps1 (8.0.3)
    Scope:       Audits ONLY the vCenter P0/P1 controls selected in
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
    [Parameter(Mandatory=$false)][switch]$NoSafetyChecks = $false
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
Log-Message "VSMC vSphere 8 vCenter Security Settings Audit Utility (P0-P1) vsmc-v1" -Level "INFO"
Log-Message "Audit of $name started at $currentDateTime from $env:COMPUTERNAME by $env:USERNAME" -Level "INFO"

if ($false -eq $AcceptEULA) { Accept-EULA }
Log-Message "EULA accepted." -Level "INFO"
if ($false -eq $NoSafetyChecks) { Check-vCenter } else { Log-Message "Safety checks skipped." -Level "INFO" }

$VC = $global:DefaultVIServers.Name

#####################
# vcenter-8.etc-issue (P1): SSH login banner must not be the default appliance message
$value = (Get-AdvancedSetting -Entity $VC -Name 'etc.issue' | Select-Object -ExpandProperty Value)
$singleline = $value -replace '\r?\n', ' '
if ($value -match 'Platform Services Controller' -or [string]::IsNullOrEmpty($value)) {
    Log-Message "etc.issue contains the default/empty message ($singleline)" -Level "FAIL"
} else {
    Log-Message "etc.issue configured with custom banner ($singleline)" -Level "PASS"
}

#####################
# SSO lockout policy
# vcenter-8.administration-sso-lockout-policy-unlock-time (P0): AutoUnlockIntervalSec = 0
# vcenter-8.administration-failed-login-interval (P1): FailedAttemptIntervalSec >= 900
try {
    $lp = Get-SsoLockoutPolicy
    if ($lp.AutoUnlockIntervalSec -eq 0) {
        Log-Message "SSO AutoUnlockIntervalSec configured correctly ($($lp.AutoUnlockIntervalSec))" -Level "PASS"
    } else {
        Log-Message "SSO AutoUnlockIntervalSec not configured correctly ($($lp.AutoUnlockIntervalSec), expected 0)" -Level "FAIL"
    }
    if ($lp.FailedAttemptIntervalSec -ge 900) {
        Log-Message "SSO FailedAttemptIntervalSec configured correctly ($($lp.FailedAttemptIntervalSec))" -Level "PASS"
    } else {
        Log-Message "SSO FailedAttemptIntervalSec not configured correctly ($($lp.FailedAttemptIntervalSec), expected >= 900)" -Level "FAIL"
    }
} catch { Log-Message "Failed to check SSO Lockout Policy: $_" -Level "ERROR" }

#####################
# SSO password policy
# vcenter-8.administration-sso-password-lifetime (P1): PasswordLifetimeDays = 9999
# vcenter-8.administration-sso-password-policy (P1): complexity
try {
    $pp = Get-SsoPasswordPolicy
    $checks = @{
        'PasswordLifetimeDays'         = @{ Expected = 9999; Comparator = 'eq' }
        'MinLength'                    = @{ Expected = 15;   Comparator = 'ge' }
        'MaxLength'                    = @{ Expected = 64;   Comparator = 'ge' }
        'MinNumericCount'              = @{ Expected = 1;    Comparator = 'ge' }
        'MinSpecialCharCount'          = @{ Expected = 1;    Comparator = 'ge' }
        'MinAlphabeticCount'           = @{ Expected = 2;    Comparator = 'ge' }
        'MinUppercaseCount'            = @{ Expected = 1;    Comparator = 'ge' }
        'MinLowercaseCount'            = @{ Expected = 1;    Comparator = 'ge' }
        'MaxIdenticalAdjacentCharacters' = @{ Expected = 3; Comparator = 'le' }
    }
    foreach ($c in $checks.GetEnumerator()) {
        $actual = $pp.$($c.Name)
        $pass = switch ($c.Value.Comparator) {
            'eq' { $actual -eq $c.Value.Expected }
            'ge' { $actual -ge $c.Value.Expected }
            'le' { $actual -le $c.Value.Expected }
        }
        if ($pass) {
            Log-Message "SSO $($c.Name) configured correctly ($actual)" -Level "PASS"
        } else {
            Log-Message "SSO $($c.Name) not configured correctly ($actual, expected $($c.Value.Comparator) $($c.Value.Expected))" -Level "FAIL"
        }
    }
} catch { Log-Message "Failed to check SSO Password Policy: $_" -Level "ERROR" }

#####################
# vcenter-8.vami-administration-password-expiration (P0): root account password expiration
try {
    $value = (Get-CisService -Name "com.vmware.appliance.local_accounts.policy").get() | Select-Object -ExpandProperty max_days
    # VSMC suggested: root password does not expire (-1). Upstream SCG tool uses 9999; either is "no expiry".
    if ($value -eq -1 -or $value -eq 9999) {
        Log-Message "vCenter appliance root password expiration disabled (max_days=$value)" -Level "PASS"
    } else {
        Log-Message "vCenter appliance root password expiration enabled (max_days=$value, expected -1)" -Level "FAIL"
    }
} catch { Log-Message "Failed to check appliance local_accounts policy: $_" -Level "ERROR" }

#####################
# vcenter-8.vami-syslog (P0): remote log forwarding must be configured
try {
    $value = (Get-CisService -Name "com.vmware.appliance.logging.forwarding").get()
    if ($value.Count -eq 0) {
        Log-Message "vCenter appliance is not forwarding logs to a remote server" -Level "FAIL"
    } else {
        Log-Message "vCenter appliance is forwarding logs ($($value.Hostname -join ', '))" -Level "PASS"
    }
} catch { Log-Message "Failed to check appliance log forwarding: $_" -Level "ERROR" }

#####################
# vcenter-8.vami-time (P0): NTP time synchronization
try {
    $value = (Get-CisService -Name "com.vmware.appliance.timesync").get()
    if ($value -ne "NTP") {
        Log-Message "vCenter appliance time sync is not NTP ($value)" -Level "FAIL"
    } else {
        Log-Message "vCenter appliance time sync is NTP ($value)" -Level "PASS"
    }
    $value = (Get-CisService -Name "com.vmware.appliance.ntp").get()
    if ($null -eq $value) {
        Log-Message "vCenter appliance NTP has no servers defined" -Level "FAIL"
    } else {
        Log-Message "vCenter appliance NTP servers defined ($($value -join ', '))" -Level "PASS"
    }
} catch { Log-Message "Failed to check appliance NTP settings: $_" -Level "ERROR" }

#####################
# Controls with no public API / no PowerCLI - operational verification required.
Log-Message "MANUAL - vSphere Client session timeout must be 15 minutes (vcenter-8.administration-client-session-timeout)" -Level "WARNING"
Log-Message "MANUAL - Separate authentication/authorization SSO groups for admins (vcenter-8.administration-sso-groups)" -Level "WARNING"
Log-Message "MANUAL - Enable + configure vSphere Client login banner Show/Details/Text (vcenter-8.administration-login-message-enable/details/text)" -Level "WARNING"
Log-Message "MANUAL - File-Based Backup must be configured in VAMI (vcenter-8.vami-backup)" -Level "WARNING"
Log-Message "MANUAL - VAMI firewall must restrict to authorized networks (vcenter-8.vami-firewall-restrict-access)" -Level "WARNING"
Log-Message "MANUAL - Confirm vCenter is fully patched (vcenter-8.vami-updates)" -Level "WARNING"

Log-Message "Audit of $name completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" -Level "INFO"
