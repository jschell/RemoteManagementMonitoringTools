# Remote Monitoring and Management (RMM) Tool Summary for SimpleHelp

### Company / Project website:
- https://simple-help.com

### Historical context and detail
- Java-based RMM tooling developed as a legitimate remote support platform.
- Frequently bundled with bossware deployments for deep system access; also observed in Medusa ransomware and Arctic Wolf incident-response tooling contexts.
- Flagged in February 2026 Huntress / The Register reporting as a prominent tool exploited for Living off the Land (LotL) persistence due to its signed binaries and encrypted communication channels.

### Process Indicators
- `JWrapper-Remote Access` — primary remote access wrapper binary (Java-based)
- `aaa.exe`, `bbb.exe` — attacker-observed renamed copies (Medusa / Arctic Wolf intrusions)

### Service Indicators
- Legitimate service name: `SimpleHelp RAS`

### Network Indicators
- Legitimate operator domains: `*.simple-help.com`
- Attacker-observed C2 domains: `telesupportgroup[.]com`, `microuptime[.]com`

### File & Registry Artifacts
- Install path: `%APPDATA%\JWrapper-Remote Access\`
- Configuration file: `JWAppsSharedConfig\serviceconfig.xml`
  - Contains `<ConnectTo>` element specifying the operator server address — pivotal artifact for identifying attacker-controlled infrastructure.

### File Signature Indicators
- Signed by: SimpleHelp Ltd (legitimate Java-wrapped binary)
- Installer typically distributed as a self-extracting Java wrapper

### Attacker TTPs
- Renamed to generic filenames (`aaa.exe`, `bbb.exe`) to evade process-name-based detection.
- `serviceconfig.xml` modified post-deployment to redirect connections to attacker infrastructure.
- Used as a secondary persistence mechanism alongside other RMM tools.

### Detection Notes
- Parse `serviceconfig.xml` for unexpected `<ConnectTo>` domains during incident response.
- Alert on `JWrapper-Remote Access` processes connecting to non-`simple-help.com` endpoints.
- Hunt for JWrapper process trees spawning unusual child processes (cmd.exe, powershell.exe).
- Correlate outbound connections to `telesupportgroup[.]com` or `microuptime[.]com`.
