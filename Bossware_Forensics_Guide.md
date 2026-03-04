# Bossware Forensics Guide: LotL Threat Actor Abuse of Employee Monitoring Tools

**Last Updated:** 2026-03-04
**Sources:** Huntress Threat Report (February 2026), The Register (February 2026)

---

## Overview

Threat actors are increasingly leveraging legitimate employee monitoring software — colloquially known as "bossware" — to maintain persistence and bypass EDR solutions. Because these tools are:

- **Legally code-signed** by reputable vendors
- **Allowlisted** by many EDR configurations
- **Using encrypted, "trusted" communication channels** (HTTPS to known SaaS endpoints)

...they are highly effective for **Living off the Land (LotL)** style attacks. The attacker deploys a tool that looks indistinguishable from an authorized enterprise deployment, achieving persistent remote access, screen capture, keystroke logging, and even TLS interception with minimal detection risk.

---

## Tools Covered

| Tool | Vendor | Primary Abuse Vector | Detail Document |
|---|---|---|---|
| [Net Monitor for Employees](#1-net-monitor-for-employees-networklookout) | NetworkLookout | Remote shell + file manager for post-exploitation | [RMM/NetMonitorForEmployees/](RMM/NetMonitorForEmployees/RMM_Summary_NetMonitorForEmployees.md) |
| [SimpleHelp](#2-simplehelp) | SimpleHelp Ltd | Java RMM tunneled to attacker-controlled server | [RMM/SimpleHelp/](RMM/SimpleHelp/RMM_Summary_SimpleHelp.md) |
| [ActivTrak](#3-activtrak) | ActivTrak Inc. | Silent agent for screenshot/keystroke exfil | [RMM/ActivTrak/](RMM/ActivTrak/RMM_Summary_ActivTrak.md) |
| [Teramind](#4-teramind) | Teramind Inc. | Stealth agent + TLS interception for credential theft | [RMM/Teramind/](RMM/Teramind/RMM_Summary_Teramind.md) |
| [Hubstaff](#5-hubstaff) | Netsoft-Online LLC | Low-noise persistent user activity monitoring | [RMM/Hubstaff/](RMM/Hubstaff/RMM_Summary_Hubstaff.md) |

---

## Quick Detection Reference

| Tool | Service Name | Key Binary | Suspicious Alias / IoC |
|---|---|---|---|
| Net Monitor for Employees | `Net Monitor For Employees` | `nmep_ctrlagentsvc.exe` | `OneDriveSvc`, `lsa.exe`, `winpty-agent.exe` |
| SimpleHelp | `SimpleHelp RAS` | `JWrapper-Remote Access` | `aaa.exe`, `bbb.exe` (Medusa/Arctic Wolf) |
| ActivTrak | `SVCTCOM` | `SCTHOST.exe` | `ActivityMonitor.exe`, `ActivTrakAgent.exe` |
| Teramind | `Teramind Agent` | `tmagentsvc.exe` | `System Monitoring`, `tmhost.exe`, `svc.exe` |
| Hubstaff | *(no service; Run key)* | `Hubstaff.exe` | UserAssist ROT13: `Uhofgnss.rkr` |

---

## 1. Net Monitor for Employees (NetworkLookout)

**Why Attackers Use It:** Built-in remote shell (`winpty-agent.exe`) and file manager provide full interactive access without deploying custom C2 tooling. Used by VoidCrypt ransomware group.

### Key Forensic Artifacts

| Artifact Type | Value |
|---|---|
| Registry | `HKLM\SOFTWARE\NetworkLookout` |
| File Path | `C:\Windows\SysWOW64\dr\` |
| Network | `dronemaker[.]org` / `104.145.210.13` |
| Masquerade Service | `OneDriveSvc` |
| Pseudo-terminal binary | `winpty-agent.exe` |

### IR Checklist
- [ ] Check for `OneDriveSvc` service registered from non-Microsoft binary paths
- [ ] Inspect `C:\Windows\SysWOW64\dr\` for recordings/logs
- [ ] Query `HKLM\SOFTWARE\NetworkLookout`
- [ ] Block/alert on `dronemaker[.]org` and `104.145.210.13`

---

## 2. SimpleHelp

**Why Attackers Use It:** Java-based, signed binary with encrypted comms. Config file (`serviceconfig.xml`) can be trivially redirected to attacker infrastructure. Observed in Medusa ransomware and Arctic Wolf response contexts.

### Key Forensic Artifacts

| Artifact Type | Value |
|---|---|
| Install Path | `%APPDATA%\JWrapper-Remote Access\` |
| Config File | `JWAppsSharedConfig\serviceconfig.xml` → `<ConnectTo>` element |
| Network | `telesupportgroup[.]com`, `microuptime[.]com` |
| Renamed Binaries | `aaa.exe`, `bbb.exe` |

### IR Checklist
- [ ] Read `serviceconfig.xml` and extract `<ConnectTo>` server address
- [ ] Compare `<ConnectTo>` against known-good `*.simple-help.com` domains
- [ ] Alert on JWrapper processes connecting to non-SimpleHelp endpoints
- [ ] Block/alert on `telesupportgroup[.]com` and `microuptime[.]com`

---

## 3. ActivTrak

**Why Attackers Use It:** Agent runs as a disguised Windows service (`SVCTCOM` / `SCTHOST.exe`) and silently captures screenshots, keystrokes, and application usage, uploading to cloud.

### Key Forensic Artifacts

| Artifact Type | Value |
|---|---|
| Service | `SVCTCOM` (presence = agent active) |
| Registry | `HKLM\SYSTEM\CurrentControlSet\Services\SVCTCOM` |
| File Paths | `C:\Program Files\ActivTrak\`, `C:\Windows\SysWOW64\aamdata\` |
| Install Log | `%TEMP%\atinstall.log` |

### IR Checklist
- [ ] Query `sc query SVCTCOM` — if running, agent is active
- [ ] Review `%TEMP%\atinstall.log` for install timestamp and parameters
- [ ] Inspect `C:\Windows\SysWOW64\aamdata\` for captured data
- [ ] Check `HKLM\SYSTEM\CurrentControlSet\Services\SVCTCOM\ImagePath` for non-standard paths

---

## 4. Teramind

**Why Attackers Use It:** "Stealth" agent mode hides from users. TLS interception via custom root certificate allows capture of credentials transmitted over HTTPS. Most dangerous of the five tools for credential theft scenarios.

### Key Forensic Artifacts

| Artifact Type | Value |
|---|---|
| Install Path | `C:\ProgramData\Teramind Agent\<version>\<guid>\` |
| TLS Cert | Root cert named `"Teramind"` or `"Quick Proxy"` in `Cert:\LocalMachine\Root` |
| Diagnostics | `tmdiag.exe`, `issue.zip` in temp directories |
| Key Binaries | `tmagentsvc.exe`, `tmhost.exe`, `svc.exe` |

### IR Checklist
- [ ] **Priority:** Enumerate `Cert:\LocalMachine\Root` for `"Teramind"` or `"Quick Proxy"` certificates
- [ ] Inspect `C:\ProgramData\Teramind Agent\` for version/GUID subdirectories
- [ ] Search temp directories for `tmdiag.exe` and `issue.zip`
- [ ] Alert on `tmagentsvc.exe` / `tmhost.exe` outside authorized deployments
- [ ] If TLS cert found: assume all HTTPS traffic on host was potentially intercepted; rotate credentials

---

## 5. Hubstaff

**Why Attackers Use It:** Standard-looking productivity tool with lighter footprint; runs as user-space tray app. Local SQLite database stores historical screenshots and activity data useful for attacker reconnaissance.

### Key Forensic Artifacts

| Artifact Type | Value |
|---|---|
| File Paths | `%AppData%\Roaming\Hubstaff\`, `%AppData%\Hubstaff\db\` |
| Registry | `HKCU\Software\Hubstaff` |
| UserAssist (ROT13) | `Uhofgnss.rkr` (decodes to `Hubstaff.exe`) — provides last-run timestamp |
| Local DB | SQLite at `%AppData%\Hubstaff\db\` — contains activity/screenshot history |

### IR Checklist
- [ ] Check `HKCU\Software\Hubstaff` and `%AppData%\Roaming\Hubstaff\`
- [ ] Decode UserAssist ROT13 entries to identify execution timeline
- [ ] Collect and preserve `%AppData%\Hubstaff\db\` SQLite files for analysis
- [ ] Review captured screenshots/activity data for attacker reconnaissance indicators

---

## Recommended Hunting Priorities

1. **Teramind root certificate** — highest impact; indicates TLS interception was active. Any host with this cert should trigger credential rotation.
2. **Net Monitor `winpty-agent.exe` + `OneDriveSvc`** — strong indicator of post-exploitation access (VoidCrypt pattern).
3. **SimpleHelp `serviceconfig.xml` `<ConnectTo>`** — quick pivot to attacker infrastructure identification.
4. **ActivTrak `SVCTCOM` service** — binary presence check is fast and definitive.
5. **Hubstaff UserAssist timeline** — useful for establishing attacker dwell time.

---

## References

- Huntress Threat Intelligence Report, February 2026
- The Register: "Bossware being weaponized for corporate espionage and ransomware", February 2026
- CISA Advisory on Remote Monitoring and Management Tools: https://www.cisa.gov/remm
- Individual tool documentation: see `RMM/` subdirectories in this repository
