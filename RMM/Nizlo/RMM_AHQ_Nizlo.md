# Advanced Hunting Query for Nizlo

These queries identify Nizlo activity for investigation. Nizlo is legitimate RMM software, so detections should be validated against authorized IT or MSP use before remediation.

### Create Process
```
let Time_start = now(-5d);
let Time_end = now();
//
let rmmProcess =
DeviceProcessEvents
| where Timestamp between (Time_start..Time_end)
| where FileName in~ (
        "Nizlo.Agent.exe",
        "Nizlo.Agent.Updater.exe",
        "Nizlo.RemoteBridge.exe"
    )
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName, AccountUpn,
    FileName, FolderPath
| extend rmmProcessName = 'Nizlo'
;
rmmProcess
```

### Network Connection
```
let Time_start = now(-5d);
let Time_end = now();
//
let rmmNetwork =
DeviceNetworkEvents
| where Timestamp between (Time_start..Time_end)
| where RemoteUrl =~ "app.nizlo.com"
    and InitiatingProcessFileName in~ (
        "Nizlo.Agent.exe",
        "Nizlo.Agent.Updater.exe",
        "Nizlo.RemoteBridge.exe"
    )
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    Report=make_set(ReportId), Count=count() by DeviceId, DeviceName,
    AccountUpn, RemoteUrl, InitiatingProcessFileName
| extend rmmNetworkName = 'Nizlo'
;
rmmNetwork
```
