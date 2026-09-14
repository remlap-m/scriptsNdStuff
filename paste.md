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
| where Timestamp >
