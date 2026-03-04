# Remote Monitoring and Management (RMM) Tool Summary for Teramind

### Company / Project website:
- https://www.teramind.co

### Historical context and detail
- Enterprise insider threat detection and employee monitoring platform.
- Offers a "Stealth" agent mode that hides from users and standard process listings.
- Uniquely capable of intercepting SSL/TLS encrypted traffic by installing a custom root certificate into the Windows trust store — enabling full decryption of HTTPS sessions for monitoring purposes.
- Flagged in February 2026 Huntress / The Register reporting as a bossware tool exploited by threat actors due to its stealth capabilities and ability to capture encrypted communications.

### Process Indicators
- `tmagentsvc.exe` — primary Teramind agent service process
- `tmhost.exe` — host process for monitoring engine
- `svc.exe` — generic-named service wrapper used by Teramind
- `tmdiag.exe` — diagnostics utility; presence indicates active or recently active Teramind deployment

### Service Indicators
- Legitimate service name: `Teramind Agent`
- Attacker-observed alias: `System Monitoring`

### Network Indicators
- Outbound connections to Teramind cloud infrastructure (`*.teramind.co`)
- On-premise deployments may beacon to internal or attacker-controlled Teramind servers

### File & Registry Artifacts
- Install path: `C:\ProgramData\Teramind Agent\<version>\<guid>\`
  - The GUID subfolder is unique per deployment — useful for timeline correlation across hosts.
- Diagnostics / evidence artifacts:
  - `tmdiag.exe` in temp directories
  - `issue.zip` files in temp directories (diagnostic bundles; may contain screenshots or activity logs)

### SSL/TLS Interception Indicators
- **Root certificate**: Look for a certificate named `"Teramind"` or `"Quick Proxy"` installed in the Windows local machine certificate store (`Cert:\LocalMachine\Root`).
  - This certificate is the primary artifact indicating Teramind's TLS inspection capability is active.
  - Its presence allows the agent to decrypt and capture HTTPS session content (credentials, data in transit).

### File Signature Indicators
- Signed by: Teramind Inc. (legitimate certificate)
- Stealth installer distributed as silent enterprise deployment package

### Attacker TTPs
- Stealth agent mode used to avoid user awareness and evade endpoint detection.
- TLS interception certificate installed to capture credentials transmitted over encrypted channels.
- Diagnostic bundles (`issue.zip`) may contain screenshots or captured session data useful for attacker exfiltration.

### Detection Notes
- **Highest-priority check**: Enumerate `Cert:\LocalMachine\Root` for certificates with Subject containing `"Teramind"` or `"Quick Proxy"`.
- Alert on `tmagentsvc.exe` or `tmhost.exe` outside of authorized IT monitoring deployments.
- Search temp directories for `tmdiag.exe` or `issue.zip` artifacts.
- Inspect `C:\ProgramData\Teramind Agent\` for unexpected version/GUID subdirectories.
