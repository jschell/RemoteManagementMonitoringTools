# Remote Monitoring and Management (RMM) Tool Summary for ActivTrak

### Company / Project website:
- https://www.activtrak.com

### Historical context and detail
- Cloud-based employee productivity and monitoring platform with a hidden system agent.
- Marketed to enterprises for workforce analytics; the agent runs silently and is not visible in standard application listings.
- Flagged in February 2026 Huntress / The Register reporting as a bossware tool leveraged by threat actors for LotL-style persistence due to its signed, stealthy agent and cloud-based exfiltration of screenshots and activity data.

### Process Indicators
- `SCTHOST.exe` — primary monitoring process (disguised to resemble `svchost.exe`)
- `ActivTrakAgent.exe` — agent installer / launcher binary

### Service Indicators
- Legitimate service name: `SVCTCOM`
  - **Critical indicator**: presence of this running service confirms the ActivTrak agent is active on the host.
- Attacker-observed alias: `ActivityMonitor.exe`

### Network Indicators
- Cloud telemetry uploads to ActivTrak SaaS infrastructure (varies by tenant configuration)
- Monitor for outbound HTTPS to `*.activtrak.com`

### File & Registry Artifacts
- Install paths:
  - `C:\Program Files\ActivTrak\`
  - `C:\Windows\SysWOW64\aamdata\` (agent data and local logs)
- Installation log: `%TEMP%\atinstall.log` — useful for determining install timestamp and parameters
- Registry key: `HKLM\SYSTEM\CurrentControlSet\Services\SVCTCOM`

### File Signature Indicators
- Signed by: ActivTrak Inc. (legitimate certificate)
- Agent distributed via enterprise deployment packages or silent MSI installers

### Attacker TTPs
- Agent deployed to silently capture screenshots, keystrokes, and application usage, exfiltrating data to attacker-controlled or shared cloud tenant.
- `SCTHOST.exe` naming chosen to blend with legitimate Windows `svchost.exe` process names.
- Persistence achieved via registered Windows service (`SVCTCOM`) surviving reboots.

### Detection Notes
- Hunt for `SVCTCOM` service registered from non-standard paths (outside `C:\Program Files\ActivTrak\`).
- Alert on `SCTHOST.exe` processes not correlated with legitimate ActivTrak enterprise deployments.
- Review `%TEMP%\atinstall.log` to determine if installation was authorized and by whom.
- Query `HKLM\SYSTEM\CurrentControlSet\Services\SVCTCOM` for unexpected `ImagePath` values.
