let Lookback = 30d;
let WindowMin = 30;
let ReadBursts = DeviceEvents
| where Timestamp > ago(Lookback)
| where ActionType == "SensitiveFileRead"
| summarize ReadCount = count() by DeviceId, AccountSid, AccountName, TimeBin = bin(Timestamp, WindowMin * 1m);
let CreateBursts = DeviceFileEvents
| where Timestamp > ago(Lookback)
| where ActionType == "FileCreated"
| summarize CreateCount = count(), CreateProcesses = make_set(InitiatingProcessFileName, 10)
    by DeviceId, AccountSid, AccountName, TimeBin = bin(Timestamp, WindowMin * 1m);
ReadBursts
| where ReadCount >= 5
| join kind=inner (CreateBursts | where CreateCount >= 5) on DeviceId, AccountSid, TimeBin
| summarize
    JointInstances = count(),
    DistinctDevices = dcount(DeviceId),
    DistinctAccounts = dcount(AccountName),
    TopCreateProcesses = make_set(CreateProcesses, 20)
