let Lookback = 2d;
let JoinWindowMinutes = 30;
let MinReadCount = 5;
let MinDistinctRoots = 2;
let ArchiveExtensions = dynamic(["zip","7z","rar"]);
let ExcludedReadProcesses = dynamic(["msmpeng.exe","searchindexer.exe","imanage.exe","ndoffice.exe"]);

let Reads = DeviceEvents
| where Timestamp > ago(Lookback)
| where ActionType == "SensitiveFileRead"
| where isnotempty(AccountSid)
| where tolower(InitiatingProcessFileName) !in (ExcludedReadProcesses)
| extend DirPath = trim_end(@"\\", FolderPath)
| extend DirPathNoUNC = iff(DirPath startswith @"\\", substring(DirPath, 2), DirPath)
| extend StrippedPath = extract(@"^[A-Za-z]:\\Users\\[^\\]+\\(.*)$", 1, DirPathNoUNC)
| extend NormalizedPath = iff(isempty(StrippedPath), DirPathNoUNC, StrippedPath)
| extend PathSegments = split(NormalizedPath, @"\")
| extend FolderRoot = iff(array_length(PathSegments) > 1,
                          strcat_array(array_slice(PathSegments, 0, 1), @"\"),
                          NormalizedPath)
| project ReadReportId = ReportId, ReadTime = Timestamp, DeviceId, DeviceName, AccountSid,
    AccountName = InitiatingProcessAccountName, ReadFileName = FileName, FolderRoot;

let Creates = DeviceFileEvents
| where Timestamp > ago(Lookback)
| where ActionType == "FileCreated"
| where FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| extend FileExt = tolower(tostring(split(FileName, ".")[-1]))
| where FileExt in (ArchiveExtensions)
| project CreateReportId = ReportId, CreateTime = Timestamp, DeviceId,
    AccountSid = InitiatingProcessAccountSid, CreateFileName = FileName, FileExt,
    CreateProcess = InitiatingProcessFileName;

Reads
| join kind=inner (Creates) on DeviceId, AccountSid
| where CreateTime >= ReadTime
| where datetime_diff('minute', CreateTime, ReadTime) between (0 .. JoinWindowMinutes)
| summarize ReadCount = dcount(ReadReportId), DistinctRoots = dcount(FolderRoot)
  by DeviceId, DeviceName, AccountSid, AccountName, CreateReportId, CreateFileName, CreateProcess
| where ReadCount >= MinReadCount and DistinctRoots >= MinDistinctRoots
| summarize QualifyingArchives = count(), DistinctDevices = dcount(DeviceId), SampleDevice = any(DeviceName)
  by CreateProcess, CreateFileName
| sort by QualifyingArchives desc
| take 30
