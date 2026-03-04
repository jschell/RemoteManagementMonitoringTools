# Remote Monitoring and Management (RMM) Tool Summary for Hubstaff

### Company / Project website:
- https://hubstaff.com

### Historical context and detail
- Time-tracking and employee monitoring SaaS platform; captures screenshots, activity levels, and GPS data.
- Lighter forensic footprint compared to stealth-focused tools like Teramind or ActivTrak, but still provides persistent remote visibility into user activity.
- Flagged in February 2026 Huntress / The Register reporting as a bossware tool abused by threat actors for low-noise persistent monitoring due to its standard productivity tool appearance and signed binaries.

### Process Indicators
- `Hubstaff.exe` — primary application binary

### Service Indicators
- No dedicated Windows service in default configuration; runs as a user-space tray application.
- Persistence typically achieved via Run key or startup folder rather than a system service.

### Network Indicators
- Outbound connections to Hubstaff SaaS infrastructure (`*.hubstaff.com`)
- Screenshot and activity data uploaded periodically over HTTPS

### File & Registry Artifacts
- Primary data paths:
  - `%AppData%\Roaming\Hubstaff\` — application data, configurations, cached screenshots
  - `%AppData%\Hubstaff\db\` — local SQLite database storing activity records, timestamps, and captured data
- Registry keys:
  - `HKCU\Software\Hubstaff` — user-level configuration and settings
  - **UserAssist**: Check `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\` for ROT13-encoded entries corresponding to `Hubstaff.exe`
    - ROT13 of `Hubstaff.exe` → `Uhofgnss.rkr`
    - UserAssist entries provide last run time and run count — valuable for establishing timeline of when monitoring was active.

### File Signature Indicators
- Signed by: Netsoft-Online LLC (Hubstaff parent company)
- Distributed as a standard Windows installer

### Attacker TTPs
- Used for persistent, low-noise user activity monitoring without triggering EDR behavioral rules.
- Local SQLite database (`db\`) may contain historical screenshots and activity data useful for attacker reconnaissance of victim workflows.
- Relatively simple deployment makes it accessible even to lower-sophistication threat actors.

### Detection Notes
- Query `HKCU\Software\Hubstaff` and `%AppData%\Roaming\Hubstaff\` for unexpected presence.
- Decode UserAssist ROT13 entries to identify Hubstaff execution history and timing.
- Inspect `%AppData%\Hubstaff\db\` SQLite files for captured activity data during IR.
- Alert on `Hubstaff.exe` network connections outside of authorized HR/productivity contexts.
