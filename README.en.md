# vsphere8seg — VSMC vSphere 8 SCG P0/P1 Hardening Tools

*English | [繁體中文](README.md)*

PowerCLI / PowerShell tooling to **audit** and **remediate** the VMware vSphere 8
Security Configuration & Hardening Guide (SCG) controls that were selected as
**P0 / P1** for the VSMC project (worksheet `VSMC_vSphere8_SCG_Controls_P0-P1`).

These scripts are tailored versions of the Broadcom VCF Security & Compliance
Guidelines tools. The original, full-scope Broadcom scripts are preserved
alongside them so nothing is lost — the VSMC variants carry a `-vsmc-v1` suffix.

> Source baseline: <https://github.com/vmware/vcf-security-and-compliance-guidelines>
> → `security-configuration-hardening-guide/vsphere/8.0/Tools`

---

## What's different from the upstream Broadcom tools

| | Upstream | This repo (`-vsmc-v1`) |
|---|---|---|
| Scope | Entire vSphere 8 SCG | **Only the ~55 P0/P1 controls in the VSMC sheet** |
| Values | SCG defaults | VSMC **Suggested** values |
| Annotation | — | Every check is tagged with its **SCG ID** |
| Guest Tools | not covered | `guest-tools-8-vsmc-v1.ps1` adds `tools.conf` (`guest-8.tools-*`) |
| Site values | hardcoded samples | parameters (`-SyslogHost`, `-NtpServers`, `-AuditLogDir`, …) |
| Not-automatable | silently absent | reported as `WARNING` (`MANUAL`) so nothing is dropped |

See **[docs/VSMC_P0-P1_Control_Mapping.md](docs/VSMC_P0-P1_Control_Mapping.md)** for
the full per-control mapping.

---

## Contents

```
Tools/
  scg-common.psm1                  shared logging / safety helpers (unchanged)
  connect.ps1                      connect to vCenter + CIS + SSO (unchanged)

  audit-esxi-8-vsmc-v1.ps1         ESXi      P0/P1 audit
  remediate-esxi-8-vsmc-v1.ps1     ESXi      P0/P1 remediation
  audit-vcenter-8-vsmc-v1.ps1      vCenter   P0/P1 audit
  remediate-vcenter-8-vsmc-v1.ps1  vCenter   P0/P1 remediation
  audit-vm-8-vsmc-v1.ps1           VM        P0 audit
  remediate-vm-8-vsmc-v1.ps1       VM        P0 remediation
  guest-tools-8-vsmc-v1.ps1        Guest VMware Tools P0 (run INSIDE the guest)
  audit-all-vsmc-v1.ps1            run all audits, one report per object

  audit-esxi-8.ps1 … remediate-vm-8.ps1   ORIGINAL Broadcom scripts (reference)
docs/
  VSMC_P0-P1_Control_Mapping.md    control-by-control mapping table
```

---

## Requirements

- PowerShell 7.x (Windows/macOS/Linux) or Windows PowerShell 5.1
- VMware PowerCLI 13+ (`Install-Module VMware.PowerCLI`)
- For SSO checks: the `VMware.vSphere.SsoAdmin` module
- A read-only account is enough for the **audit** scripts; remediation needs
  appropriate write privileges.

---

## Usage

### 1. Connect

```powershell
# prompts for password; connects VI + CIS + SSO
./Tools/connect.ps1 -vCenter vcsa.example.local -User administrator@vsphere.local
```

### 2. Audit

```powershell
# audit everything into an (empty) output directory
mkdir .\report
./Tools/audit-all-vsmc-v1.ps1 -OutputDirName .\report -AcceptEULA

# …or audit a single object
./Tools/audit-esxi-8-vsmc-v1.ps1    -Name esx01.example.local -AcceptEULA
./Tools/audit-vcenter-8-vsmc-v1.ps1 -Name vcsa.example.local  -AcceptEULA
./Tools/audit-vm-8-vsmc-v1.ps1      -Name web01              -AcceptEULA
```

Report levels: `PASS` (compliant), `FAIL` (non-compliant), `WARNING`
(manual / MANUAL action required).

### 3. Remediation

> ⚠️ Each remediate script has a **safety block that `Exit`s before making any
> change**. Read it, then comment/remove the indicated `Exit` line to opt in.
> **Always test outside production and take backups/snapshots first.**

```powershell
# ESXi — site values as parameters; risky controls are opt-in switches
./Tools/remediate-esxi-8-vsmc-v1.ps1 -Name esx01.example.local -AcceptEULA `
    -SyslogHost "udp://loginsight.example.local:514" `
    -NtpServers "ntp1.example.local","ntp2.example.local" `
    -EnableLockdownMode -RemediateFirewall -FirewallAllowedNetworks "10.0.0.0/8"

# vCenter
./Tools/remediate-vcenter-8-vsmc-v1.ps1 -Name vcsa.example.local -AcceptEULA `
    -SyslogHost loginsight.example.local -NtpServers "ntp1.example.local"

# VM (opt-in switches for disruptive changes)
./Tools/remediate-vm-8-vsmc-v1.ps1 -Name web01 -AcceptEULA `
    -TakeSnapshot -RemoveExtraDevices -UpdateHardwareVersion
```

### 4. Guest VMware Tools (`guest-8.tools-*`)

These are guest-OS settings and **cannot be set over PowerCLI**. Run the script
inside each Windows guest (audit by default, `-Remediate` to apply):

```powershell
# inside the guest
.\guest-tools-8-vsmc-v1.ps1                # audit
.\guest-tools-8-vsmc-v1.ps1 -Remediate     # apply (use -IsTemplate on golden images)
```

To push it from the vCenter side to many guests at once, wrap it with
`Invoke-VMScript` (see the script header).

---

## Manual / out-of-band controls

Some P0/P1 controls have **no public API** (vSphere Client session timeout, SSO
login banner, VAMI backup/firewall, **vSAN operations reserve**, version/patch
levels). The scripts emit a `WARNING` line for each so they appear in the report
and are not forgotten. See the mapping doc for exactly how to set them.

---

## Disclaimer

Provided "AS IS", without warranty, and **not supported by anyone** (carried over
from the Broadcom sample license, see `Tools/LICENSE`). Engage your own legal,
business, technical, and audit expertise. Test before using in production.
