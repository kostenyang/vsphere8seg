# vsphere8seg — VSMC vSphere 8 SCG P0/P1 強化工具

針對 **VSMC 專案**所挑選的 **P0 / P1** vSphere 8 安全強化控制項（工作表
`VSMC_vSphere8_SCG_Controls_P0-P1`），提供 PowerCLI / PowerShell 的
**稽核（audit）** 與 **修復（remediate）** 腳本。

這些腳本是 Broadcom 官方 VCF Security & Compliance Guidelines 工具的客製版本。
原始、全範圍的 Broadcom 腳本一併保留（不刪除任何檔案），VSMC 客製版以
`-vsmc-v1` 字尾區別。

> 來源基準：<https://github.com/vmware/vcf-security-and-compliance-guidelines>
> → `security-configuration-hardening-guide/vsphere/8.0/Tools`

---

## 與官方 Broadcom 工具的差異

| 項目 | 官方版 | 本 repo（`-vsmc-v1`） |
|---|---|---|
| 範圍 | 整份 vSphere 8 SCG | **只含 VSMC 表中約 55 條 P0/P1 控制項** |
| 數值 | SCG 預設 | VSMC 的 **Suggested** 建議值 |
| 標註 | 無 | 每個檢查都標上對應 **SCG ID** |
| Guest Tools | 未涵蓋 | 新增 `guest-tools-8-vsmc-v1.ps1`（`guest-8.tools-*`） |
| 站點數值 | 寫死範例 | 改為參數（`-SyslogHost`、`-NtpServers`、`-AuditLogDir`…） |
| 無法自動化的項目 | 直接省略 | 以 `WARNING`（`MANUAL`）回報，不會被默默丟掉 |

完整逐條對照見 **[docs/VSMC_P0-P1_Control_Mapping.md](docs/VSMC_P0-P1_Control_Mapping.md)**。

---

## 檔案結構

```
Tools/
  scg-common.psm1                  共用 logging／安全檢查（未改動）
  connect.ps1                      連線 vCenter + CIS + SSO（未改動）

  audit-esxi-8-vsmc-v1.ps1         ESXi      P0/P1 稽核
  remediate-esxi-8-vsmc-v1.ps1     ESXi      P0/P1 修復
  audit-vcenter-8-vsmc-v1.ps1      vCenter   P0/P1 稽核
  remediate-vcenter-8-vsmc-v1.ps1  vCenter   P0/P1 修復
  audit-vm-8-vsmc-v1.ps1           VM        P0 稽核
  remediate-vm-8-vsmc-v1.ps1       VM        P0 修復
  guest-tools-8-vsmc-v1.ps1        Guest VMware Tools P0（須在「guest 內」執行）
  audit-all-vsmc-v1.ps1            一次稽核全部，每個物件輸出一份報告

  audit-esxi-8.ps1 … remediate-vm-8.ps1   原始 Broadcom 腳本（保留作參考）
docs/
  VSMC_P0-P1_Control_Mapping.md    逐條控制項對照表
```

---

## 環境需求

- PowerShell 7.x（Windows/macOS/Linux）或 Windows PowerShell 5.1
- VMware PowerCLI 13+（`Install-Module VMware.PowerCLI`）
- SSO 檢查另需 `VMware.vSphere.SsoAdmin` 模組
- **稽核**用唯讀帳號即可；**修復**需相對應的寫入權限

---

## 使用方式

### 1. 連線

```powershell
# 會提示輸入密碼，同時連 VI + CIS + SSO
./Tools/connect.ps1 -vCenter vcsa.example.local -User administrator@vsphere.local
```

### 2. 稽核

```powershell
# 一次稽核全部，輸出到一個「空的」目錄
mkdir .\report
./Tools/audit-all-vsmc-v1.ps1 -OutputDirName .\report -AcceptEULA

# 或單一物件
./Tools/audit-esxi-8-vsmc-v1.ps1    -Name esx01.example.local -AcceptEULA
./Tools/audit-vcenter-8-vsmc-v1.ps1 -Name vcsa.example.local  -AcceptEULA
./Tools/audit-vm-8-vsmc-v1.ps1      -Name web01              -AcceptEULA
```

報告中的等級：`PASS`（符合）、`FAIL`（不符合）、`WARNING`（需人工/MANUAL 處理）。

### 3. 修復

> ⚠️ 每個 remediate 腳本內都有一段**安全區塊，會在做任何變更前先 `Exit`**。
> 請先看過，再把指定的那行 `Exit` 註解／移除才會實際執行。
> **務必先在非正式環境測試、並先做好備份／快照。**

```powershell
# ESXi —— 站點數值用參數帶入；高風險項用 opt-in 開關
./Tools/remediate-esxi-8-vsmc-v1.ps1 -Name esx01.example.local -AcceptEULA `
    -SyslogHost "udp://loginsight.example.local:514" `
    -NtpServers "ntp1.example.local","ntp2.example.local" `
    -EnableLockdownMode -RemediateFirewall -FirewallAllowedNetworks "10.0.0.0/8"

# vCenter
./Tools/remediate-vcenter-8-vsmc-v1.ps1 -Name vcsa.example.local -AcceptEULA `
    -SyslogHost loginsight.example.local -NtpServers "ntp1.example.local"

# VM（破壞性變更用 opt-in 開關）
./Tools/remediate-vm-8-vsmc-v1.ps1 -Name web01 -AcceptEULA `
    -TakeSnapshot -RemoveExtraDevices -UpdateHardwareVersion
```

### 4. Guest VMware Tools（`guest-8.tools-*`）

這些是 guest OS 的設定，**無法透過 PowerCLI 設定**，須在每台 Windows guest
內執行（預設只稽核，加 `-Remediate` 才套用）：

```powershell
# 在 guest 內
.\guest-tools-8-vsmc-v1.ps1                # 稽核
.\guest-tools-8-vsmc-v1.ps1 -Remediate     # 套用（黃金範本請加 -IsTemplate）
```

要從 vCenter 端一次推送到多台 guest，可用 `Invoke-VMScript`（範例見腳本標頭）。

---

## 人工 / 帶外（MANUAL）控制項

部分 P0/P1 控制項**沒有公開 API**（vSphere Client session timeout、SSO 登入橫幅、
VAMI backup/firewall、**vSAN operations reserve**、版本/修補等級）。腳本會為每一項
輸出一行 `WARNING`，確保出現在報告中、不被遺漏。詳細設定方式見對照表。

---

## 免責聲明

本工具沿用 Broadcom 範例授權，以「現狀（AS IS）」提供、不含任何擔保，且
**不受任何人支援**（見 `Tools/LICENSE`）。請自行尋求法律、業務、技術與稽核專業
意見，並務必在正式環境前完成測試。
