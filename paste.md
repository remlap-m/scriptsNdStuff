let Lookback = 7d;
let JoinWindowMinutes = 30;
let MinReadCount = 5;
let MinDistinctRoots = 2;
let ArchiveExtensions = dynamic(["zip","7z","rar","cab","iso"]);

let ExcludedReadProcesses = dynamic(["msmpeng.exe","searchindexer.exe","imanage.exe","ndoffice.exe"]);
let ExcludedArchiveProcesses = dynamic(["veeam.exe","backup.exe","backupexec.exe","arcserve.exe",
    "wbengine.exe","ntbackup.exe","ccmexec.exe","makecab.exe","imanage.exe"]);

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
| project
    ReadReportId = ReportId,
    ReadTime = Timestamp,
    DeviceId,
    DeviceName,
    AccountSid,
    AccountName = InitiatingProcessAccountName,
    ReadFileName = FileName,
    FolderRoot,
    ReadInitiatingProcessId = InitiatingProcessId,
    ReadInitiatingProcessCreationTime = InitiatingProcessCreationTime;

let Creates = DeviceFileEvents
| where Timestamp > ago(Lookback)
| where ActionType == "FileCreated"
| where tolower(InitiatingProcessFileName) !in (ExcludedArchiveProcesses)
| extend FileExt = tolower(tostring(split(FileName, ".")[-1]))
| extend IsArchive = FileExt in (ArchiveExtensions)
| project
    CreateReportId = ReportId,
    CreateTime = Timestamp,
    DeviceId,
    AccountSid = InitiatingProcessAccountSid,
    CreateFileName = FileName,
    IsArchive,
    CreateInitiatingProcessId = InitiatingProcessId,
    CreateInitiatingProcessCreationTime = InitiatingProcessCreationTime;

let Hits = Reads
| join kind=inner (Creates) on DeviceId, AccountSid
| where CreateTime >= ReadTime
| where datetime_diff('minute', CreateTime, ReadTime) between (0 .. JoinWindowMinutes)
| summarize
    ReadCount = dcount(ReadReportId),
    DistinctRoots = dcount(FolderRoot),
    Roots = make_set(FolderRoot, 25),
    ReadFiles = make_set(ReadFileName, 100),
    FirstRead = min(ReadTime),
    ArchivePresent = countif(IsArchive) > 0,
    ArchiveNames = make_set_if(CreateFileName, IsArchive, 10),
    LastArchiveTime = maxif(CreateTime, IsArchive),
    OtherCreateCount = dcountif(CreateReportId, not(IsArchive)),
    ProcessLinked = countif(IsArchive
                             and ReadInitiatingProcessId == CreateInitiatingProcessId
                             and ReadInitiatingProcessCreationTime == CreateInitiatingProcessCreationTime) > 0
  by DeviceId, DeviceName, AccountSid, AccountName
| where ReadCount >= MinReadCount and DistinctRoots >= MinDistinctRoots
| where ArchivePresent
| extend ProcessLinkScore = iff(ProcessLinked, 25, 0)
| extend RootDiversityScore = case(DistinctRoots >= 4, 20, DistinctRoots >= 2, 10, 0)
| extend TotalScore = ProcessLinkScore + RootDiversityScore
| extend Confidence = case(TotalScore >= 35, "High", TotalScore >= 10, "Medium", "Low");
Hits
| summarize TotalHits = count(), DistinctDevices = dcount(DeviceId), DistinctAccounts = dcount(AccountName),
    HighConf = countif(Confidence == "High"), MedConf = countif(Confidence == "Medium"), LowConf = countif(Confidence == "Low")
