let ReadBursts = DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "SensitiveFileRead"
| where isnotempty(AccountSid)
| summarize ReadCount = count() by DeviceId, AccountSid, TimeBin = bin(Timestamp, 30m);
let CreateBursts = DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| summarize CreateCount = count(), CreateProcesses = make_set(InitiatingProcessFileName, 10)
    by DeviceId, AccountSid = InitiatingProcessAccountSid, TimeBin = bin(Timestamp, 30m);
ReadBursts
| where ReadCount >= 5
| join kind=inner (CreateBursts | where CreateCount >= 10) on DeviceId, AccountSid, TimeBin
| mv-expand CreateProcesses
| summarize Count = count() by tostring(CreateProcesses)
| top 20 by Count desc
