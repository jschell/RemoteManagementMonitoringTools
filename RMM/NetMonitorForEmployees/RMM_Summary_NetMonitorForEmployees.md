# Remote Monitoring and Management (RMM) Tool Summary for Net Monitor for Employees

### Company / Project website:
- https://www.networklookout.com

### Historical context and detail
- Developed by NetworkLookout; marketed as an employee productivity and monitoring solution.
- Frequently abused by threat actors (e.g., VoidCrypt ransomware group) due to its built-in remote shell, file manager, and pseudo-terminal capabilities.
- Observed being deployed under masquerade service names (e.g., `OneDriveSvc`) to blend with legitimate Windows services.
- Flagged in February 2026 Huntress / The Register reporting as a prominent "bossware" tool exploited for Living off the Land (LotL) persistence.

### Process Indicators
- `nmep_ctrlagentsvc.exe` — primary control agent service binary
- `lsa.exe` — common masquerade binary name used by attackers
- `winpty-agent.exe` — pseudo-terminal agent (enables interactive remote shell sessions)

### Service Indicators
- Legitimate service name: `Net Monitor For Employees`
- Attacker-observed masquerade: `OneDriveSvc`, `svchost.exe` (process hollowing)

### Network Indicators
- C2 / licensing domain: `dronemaker[.]org`
- C2 IP (observed): `104.145.210.13`

### File & Registry Artifacts
- Install path: `C:\Windows\SysWOW64\dr\` (recordings, logs, and session data stored here)
- Registry key: `HKLM\SOFTWARE\NetworkLookout`

### File Signature Indicators
- Signed by: NetworkLookout (legitimate certificate; bypass EDR allowlisting)
- Installer binary: typically distributed as `NetMonitorForEmployees_setup.exe`

### Attacker TTPs
- Deployed post-compromise to maintain persistent remote access without triggering EDR.
- Remote shell used to execute ransomware payloads and exfiltrate data.
- Masquerade service name chosen to mimic Microsoft services and evade casual inspection.

### Detection Notes
- Alert on `winpty-agent.exe` spawned outside expected IT management contexts.
- Monitor for `OneDriveSvc` service registered from non-Microsoft paths.
- Correlate outbound connections to `dronemaker[.]org` or `104.145.210.13`.
- Inspect `HKLM\SOFTWARE\NetworkLookout` for unexpected installations.
