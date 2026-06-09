# Changelog

## vsmc-v1 — 2026-06-09

Initial VSMC tailoring of the Broadcom VCF vSphere 8.0 SCG Tools, scoped to the
**P0/P1** controls in worksheet `VSMC_vSphere8_SCG_Controls_P0-P1`.

Added (alongside the preserved original Broadcom scripts):

- `Tools/audit-esxi-8-vsmc-v1.ps1`, `Tools/remediate-esxi-8-vsmc-v1.ps1`
- `Tools/audit-vcenter-8-vsmc-v1.ps1`, `Tools/remediate-vcenter-8-vsmc-v1.ps1`
- `Tools/audit-vm-8-vsmc-v1.ps1`, `Tools/remediate-vm-8-vsmc-v1.ps1`
- `Tools/guest-tools-8-vsmc-v1.ps1` — new: guest VMware Tools (`guest-8.tools-*`)
- `Tools/audit-all-vsmc-v1.ps1`
- `docs/VSMC_P0-P1_Control_Mapping.md`

Changes vs. upstream:

- Restricted every check to the selected P0/P1 SCG IDs; each block is annotated
  with its SCG ID.
- Applied the worksheet's **Suggested** values (e.g. ESXi password policy
  `min=…,15 max=64`, audit storage capacity `100`, SOAP timeout `10`,
  shell timeouts `900`/`600`, `Mem.MemEagerZero=1`, `execInstalledOnly=True`).
- Site-specific values are now parameters: `-SyslogHost`, `-SyslogDir`,
  `-AuditLogDir`, `-NtpServers`, `-FirewallAllowedNetworks`.
- Disruptive controls are opt-in switches: `-EnableLockdownMode`,
  `-RemediateFirewall`, `-RemoveExtraDevices`, `-UpdateHardwareVersion`.
- vCenter root password expiration uses the VSMC value `max_days=-1` (audit
  accepts `-1` or `9999`).
- Controls with no public API or that are operational are reported as `WARNING`
  (`MANUAL`) instead of being dropped.

Original Broadcom scripts (`audit-esxi-8.ps1`, etc.) are retained unmodified for
reference.
