DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| summarize CreateCount = count() by DeviceId, AccountSid = InitiatingProcessAccountSid, bin(Timestamp, 30m)
| summarize P50 = percentile(CreateCount, 50), P95 = percentile(CreateCount, 95), P99 = percentile(CreateCount, 99), Max = max(CreateCount)


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
| summarize JointInstances = count(), DistinctDevices = dcount(DeviceId), DistinctAccounts = dcount(AccountSid)
    by bin(TimeBin, 1d)
| extend TopNote = "run query 2b below if JointInstances is non-trivial"
