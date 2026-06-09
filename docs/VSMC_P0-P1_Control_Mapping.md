# VSMC vSphere 8 SCG — P0/P1 Control Mapping

This table maps every control selected in the **VSMC_vSphere8_SCG_Controls_P0-P1**
worksheet to the script, function, and value that implements it in this repo.
Values are the worksheet's **Suggested** column (placeholders shown as `<...>`
must be set per site).

Legend for **How**:
`AUTO` = audited & remediated by script · `AUDIT` = audited only (no safe auto-fix)
· `OPT-IN` = remediated only when an explicit switch is passed · `MANUAL` = no public
API / operational task, reported as a WARNING so it is not silently dropped.

## VMware ESXi

| SCG ID | Pri | Setting / Value | Script | How |
|---|---|---|---|---|
| esxi-8.account-dcui | P0 | dcui `shellaccess=false` | esxi | AUTO |
| esxi-8.account-password-policies | P0 | `Security.PasswordQualityControl=similar=deny retry=3 min=disabled,disabled,disabled,disabled,15 max=64` | esxi | AUTO |
| esxi-8.deactivate-cim | P0 | `sfcbd-watchdog` stopped + policy manual | esxi | AUTO |
| esxi-8.deactivate-snmp | P0 | `snmpd` stopped + policy manual | esxi | AUTO |
| esxi-8.lockdown-mode | P0 | `lockdownNormal` | esxi | OPT-IN `-EnableLockdownMode` |
| esxi-8.logs-audit-local | P0 | `Syslog.global.auditRecord.storageEnable=YES` | esxi | AUTO |
| esxi-8.logs-audit-persistent | P0 | `Syslog.global.auditRecord.storageDirectory=<persistent>` | esxi | AUTO (`-AuditLogDir`) |
| esxi-8.logs-audit-remote | P0 | `Syslog.global.auditRecord.remoteEnable=YES` | esxi | AUTO |
| esxi-8.logs-persistent | P0 | `Syslog.global.logDir=<persistent>` | esxi | AUTO (`-SyslogDir`) |
| esxi-8.logs-remote | P0 | `Syslog.global.logHost=<log collector>` | esxi | AUTO (`-SyslogHost`) |
| esxi-8.memeagerzero | P0 | `Mem.MemEagerZero=1` | esxi | AUTO |
| esxi-8.shell-interactive-timeout | P0 | `UserVars.ESXiShellInteractiveTimeOut=900` | esxi | AUTO |
| esxi-8.shell-timeout | P0 | `UserVars.ESXiShellTimeOut=600` | esxi | AUTO |
| esxi-8.supported | P0 | Build in General Support | esxi | MANUAL |
| esxi-8.timekeeping-services | P0 | `ntpd` running + start with host | esxi | AUTO |
| esxi-8.timekeeping-sources | P0 | NTP servers defined | esxi | AUTO (`-NtpServers`) |
| esxi-8.updates | P0 | Fully patched | esxi | MANUAL |
| esxi-8.vib-trusted-binaries | P0 | `VMkernel.Boot.execInstalledOnly=True` | esxi | AUTO |
| esxi-8.annotations-welcomemessage | P1 | `Annotations.WelcomeMessage=<banner>` | esxi | AUTO |
| esxi-8.api-soap-timeout | P1 | `Config.HostAgent.vmacore.soap.sessionTimeout=10` | esxi | AUTO |
| esxi-8.etc-issue | P1 | `Config.Etc.issue=<banner>` | esxi | AUTO |
| esxi-8.firewall-restrict-access | P1 | Restrict mgmt rulesets to authorized nets | esxi | OPT-IN `-RemediateFirewall` |
| esxi-8.logs-audit-local-capacity | P1 | `Syslog.global.auditRecord.storageCapacity=100` | esxi | AUTO |

`esxi` = `audit-esxi-8-vsmc-v1.ps1` / `remediate-esxi-8-vsmc-v1.ps1`

## Guest VMware Tools (run inside each Windows guest)

| SCG ID | Pri | tools.conf value | Script | How |
|---|---|---|---|---|
| guest-8.tools-add-feature | P0 | `autoupgrade allow-add-feature=false` | guest | AUTO (`-Remediate`) |
| guest-8.tools-remove-feature | P0 | `autoupgrade allow-remove-feature=false` | guest | AUTO (`-Remediate`) |
| guest-8.tools-deactivate-appinfo | P0 | `appinfo disabled=true` | guest | AUTO (`-Remediate`) |
| guest-8.tools-deactivate-containerinfo | P0 | `containerinfo poll-interval=0` | guest | AUTO (`-Remediate`) |
| guest-8.tools-deactivate-gueststoreupgrade | P0 | `gueststoreupgrade policy=off` | guest | AUTO (`-Remediate`) |
| guest-8.tools-deactivate-servicediscovery | P0 | `servicediscovery disabled=true` | guest | AUTO (`-Remediate`) |
| guest-8.tools-enable-syslog | P0 | `logging *.handler=syslog` (4 handlers) | guest | AUTO (`-Remediate`) |
| guest-8.tools-prevent-recustomization | P0 | `deployPkg enable-customization=false` (NOT on templates) | guest | AUTO (`-Remediate`, skip `-IsTemplate`) |
| guest-8.tools-upgrade | P0 | `autoupgrade allow-upgrade=true` | guest | AUDIT |
| guest-8.tools-updates | P0 | Keep Tools current | guest | MANUAL |

`guest` = `guest-tools-8-vsmc-v1.ps1`

## Virtual Machine

| SCG ID | Pri | Setting / Value | Script | How |
|---|---|---|---|---|
| guest-8.virtual-hardware | P0 | VM hardware `vmx-21` (min vmx-19) | vm | OPT-IN `-UpdateHardwareVersion` |
| vm-8.limit-console-connections | P0 | `RemoteDisplay.maxConnections=1` | vm | AUTO |
| vm-8.pci-passthrough | P0 | No undocumented passthrough | vm | AUDIT (never auto-removes GPUs) |
| vm-8.remove-unnecessary-devices | P0 | Remove CD-ROM/USB/serial/etc. | vm | OPT-IN `-RemoveExtraDevices` |
| vm-8.vmrc-lock | P0 | `tools.guest.desktop.autolock=TRUE` | vm | AUTO |

`vm` = `audit-vm-8-vsmc-v1.ps1` / `remediate-vm-8-vsmc-v1.ps1`

## VMware vCenter

| SCG ID | Pri | Setting / Value | Script | How |
|---|---|---|---|---|
| vcenter-8.administration-client-session-timeout | P0 | vSphere Client timeout 15 min | vcenter | MANUAL (no public API) |
| vcenter-8.administration-sso-groups | P0 | Separate authN/authZ admin groups | vcenter | MANUAL |
| vcenter-8.administration-sso-lockout-policy-unlock-time | P0 | `AutoUnlockIntervalSec=0` | vcenter | AUTO |
| vcenter-8.vami-administration-password-expiration | P0 | root `max_days=-1` (no expiry) | vcenter | AUTO |
| vcenter-8.vami-backup | P0 | File-based backup configured | vcenter | MANUAL |
| vcenter-8.vami-firewall-restrict-access | P0 | Restrict VAMI to authorized nets | vcenter | MANUAL |
| vcenter-8.vami-syslog | P0 | Remote log forwarding | vcenter | AUTO (`-SyslogHost`) |
| vcenter-8.vami-time | P0 | NTP time sync + servers | vcenter | AUTO (`-NtpServers`) |
| vcenter-8.vami-updates | P0 | Fully patched | vcenter | MANUAL |
| vcenter-8.administration-failed-login-interval | P1 | `FailedAttemptIntervalSec=900` | vcenter | AUTO |
| vcenter-8.administration-login-message-enable | P1 | Show login banner | vcenter | MANUAL (sso-config.sh) |
| vcenter-8.administration-login-message-details | P1 | Banner details | vcenter | MANUAL (sso-config.sh) |
| vcenter-8.administration-login-message-text | P1 | Banner text | vcenter | MANUAL (sso-config.sh) |
| vcenter-8.administration-sso-password-lifetime | P1 | `PasswordLifetimeDays=9999` | vcenter | AUTO |
| vcenter-8.administration-sso-password-policy | P1 | min 15 / max 64 + complexity | vcenter | AUTO |
| vcenter-8.etc-issue | P1 | `etc.issue=<banner>` | vcenter | AUTO |

`vcenter` = `audit-vcenter-8-vsmc-v1.ps1` / `remediate-vcenter-8-vsmc-v1.ps1`

## VMware vSAN

| SCG ID | Pri | Setting / Value | Script | How |
|---|---|---|---|---|
| vsan-8.operations-reserve | P0 | Enable operations reserve (Reservations and Alerts) | — | MANUAL — no public PowerCLI; set in vSphere Client → Cluster → Configure → vSAN → Services → Reservations and Alerts → enable **Operations reserve** |

---

### Note on `vami-administration-password-expiration`
The VSMC worksheet specifies `max_days=-1` (root password never expires). The
upstream Broadcom tool uses `9999` for the same intent; the VSMC audit accepts
either value as compliant, while remediation applies the VSMC value `-1`.
