let Lookback = 1h;
let JoinWindowMinutes = 30;
let MinReadCount = 5;          // tune this
let MinCreateCount = 10;       // tune this
let ArchiveExtensions = dynamic(["zip","7z","rar","cab","iso"]);

// Add your own exclusions here
let ExcludedReadProcesses = dynamic([]);
let ExcludedCreateProcesses = dynamic([]);

let Reads = DeviceEvents
| where Timestamp > ago(Lookback)
| where ActionType == "SensitiveFileRead"
| where isnotempty(AccountSid)
| where tolower(InitiatingProcessFileName) !in (ExcludedReadProcesses)
| project ReadReportId = ReportId, ReadTime = Timestamp, DeviceId, DeviceName, AccountSid,
    AccountName = InitiatingProcessAccountName, ReadFileName = FileName;

let Creates = DeviceFileEvents
| where Timestamp > ago(Lookback)
| where ActionType == "FileCreated"
| where tolower(InitiatingProcessFileName) !in (ExcludedCreateProcesses)
| extend FileExt = tolower(tostring(split(FileName, ".")[-1]))
| extend IsArchive = FileExt in (ArchiveExtensions)
| project CreateReportId = ReportId, CreateTime = Timestamp, DeviceId,
    AccountSid = InitiatingProcessAccountSid, CreateFileName = FileName, IsArchive;

Reads
| join kind=inner (Creates) on DeviceId, AccountSid
| where CreateTime >= ReadTime
| where datetime_diff('minute', CreateTime, ReadTime) between (0 .. JoinWindowMinutes)
| summarize
    ReadCount = dcount(ReadReportId),
    CreateCount = dcount(CreateReportId),
    ReadFiles = make_set(ReadFileName, 100),
    CreateFiles = make_set(CreateFileName, 100),
    ArchivePresent = countif(IsArchive) > 0,
    ArchiveNames = make_set_if(CreateFileName, IsArchive, 10),
    FirstRead = min(ReadTime),
    LastCreate = max(CreateTime)
  by DeviceId, DeviceName, AccountSid, AccountName
| where ReadCount >= MinReadCount and CreateCount >= MinCreateCount
| sort by ReadCount desc
