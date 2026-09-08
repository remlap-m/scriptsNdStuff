// Mass file creation / data staging - DeviceFileEvents (MDE via Defender XDR connector)
// Sentinel scheduled rule. Frequency 30m, Lookup period 2h (MUST set in the UI).

let StepMin        = 5;
let BucketMin      = 20;
let Bucket         = BucketMin * 1m;
let Offsets        = range(0, BucketMin - StepMin, StepMin);   // 0,5,10,15
let Lookback       = 90m;
let Skew           = 30m;
let Liveness       = 35m;                      // rule frequency + buffer
let Threshold      = 200;
let DistinctRatio  = 0.75;
let ConcentrationHint = 50.0;
let ExcludedAccounts  = dynamic([]);
let ExcludedProcesses = dynamic(["REMOVED.exe"]);
let ExcludedFolders   = dynamic([
    @"\AppData\Local\Temp\",
    @"\AppData\Local\Microsoft\Windows\INetCache\",
    @"\AppData\Local\Microsoft\Windows\WebCache\",
    @"\AppData\Local\Packages\",
    @"\AppData\Roaming\Microsoft\Windows\Recent\",
    @"\Google\Chrome\User Data\",
    @"\Microsoft\Edge\User Data\",
    @"\OneDriveTemp\",
    @"$Recycle.Bin"
]);
let SystemPaths     = dynamic([@"C:\Windows\", @"C:\Program Files", @"C:\ProgramData\"]);
let SystemCarveOuts = dynamic([
    @"C:\Windows\Temp\", @"C:\Windows\Tasks\", @"C:\Windows\System32\Tasks\",
    @"C:\Windows\Debug\", @"C:\Windows\Registration\", @"C:\Windows\Media\",
    @"C:\ProgramData\Microsoft\Windows\Start Menu\"
]);
let InterestingExt  = dynamic([
    "doc", "docx", "docm", "dot", "dotx",
    "xls", "xlsx", "xlsm", "ppt", "pptx",
    "pdf", "msg", "eml", "rtf", "txt", "csv",
    "zip", "7z", "rar", "pst", "ost"
]);
DeviceFileEvents
| where TimeGenerated > ago(Lookback + Skew)
| where Timestamp     > ago(Lookback)
| where ActionType == "FileCreated"
| where isnotempty(FileName)
| where InitiatingProcessFileName !in~ (ExcludedProcesses)
| where not(FolderPath has_any (ExcludedFolders))
| where not(FolderPath has_any (SystemPaths)) or FolderPath has_any (SystemCarveOuts)
| where not(InitiatingProcessCommandLine has_any ("/systemstartup", "Quarantine"))
| where not(FileName startswith "~$")
| where not(FileName startswith "PowerShell_transcript")
// KQL has no negative array indexing - split(FileName,".")[-1] returns null
| extend NameParts = split(FileName, ".")
| extend Ext       = tolower(tostring(NameParts[array_length(NameParts) - 1]))
| where array_length(NameParts) > 1
| where Ext in (InterestingExt)
| extend Actor = tolower(iff(isnotempty(InitiatingProcessAccountUpn),
                             InitiatingProcessAccountUpn,
                             strcat(InitiatingProcessAccountDomain, @"\", InitiatingProcessAccountName)))
| where isnotempty(Actor) and Actor != @"\"
| where Actor !endswith "$"
| where Actor !in~ (ExcludedAccounts)
| extend IngestAt = ingestion_time()
// Self-adapting: strip the filename only when FolderPath actually contains it
| extend DirPath = iff(FolderPath endswith FileName,
                       tostring(parse_path(FolderPath).DirectoryPath),
                       FolderPath)
| extend Off = Offsets
| mv-expand Off to typeof(long)
| extend WindowStart = bin(Timestamp - Off * 1m, Bucket) + Off * 1m
| summarize
    FilesCreated    = count(),
    DistinctFiles   = dcount(strcat(DirPath, "|", FileName)),
    DistinctFolders = dcount(DirPath),
    TotalBytes      = sum(FileSize),
    NetworkPathHits = countif(FolderPath startswith @"\\"),
    OtherDriveHits  = countif(not(FolderPath startswith "C:\\")
                              and not(FolderPath startswith @"\\")),
    RemoteSession   = countif(IsInitiatingProcessRemoteSession == true),
    InboundSmbHits  = countif(isnotempty(ShareName)),
    FileSample      = make_set(FileName, 10),
    FolderSample    = make_set(DirPath, 10),
    Processes       = make_set(InitiatingProcessFileName, 5),
    OriginUrls      = make_set(FileOriginUrl, 5),
    Labels          = make_set(SensitivityLabel, 5),
    FirstEvent      = min(Timestamp),
    LastEvent       = max(Timestamp),
    IngestLast      = max(IngestAt),
    (LastFileTime, SampleFile, SampleFolder) = arg_max(Timestamp, FileName, FolderPath),
    take_any(DeviceName,
             InitiatingProcessAccountName,
             InitiatingProcessAccountDomain,
             InitiatingProcessFileName,
             InitiatingProcessSHA256,
             InitiatingProcessFolderPath,
             InitiatingProcessParentFileName,
             InitiatingProcessCommandLine)
  by Actor, DeviceId, WindowStart
| where FilesCreated  >= Threshold
| where DistinctFiles >= toint(Threshold * DistinctRatio)
| where IngestLast > ago(Liveness)
| summarize arg_max(FilesCreated, *) by Actor, DeviceId
| extend WindowEnd      = WindowStart + Bucket
| extend BurstSeconds   = datetime_diff('second', LastEvent, FirstEvent)
| extend FilesPerMin    = round(todouble(FilesCreated) / max_of(todouble(BurstSeconds) / 60.0, 0.5), 1)
| extend TotalMB        = round(todouble(TotalBytes) / 1048576.0, 1)
| extend FilesPerFolder = round(todouble(FilesCreated) / todouble(max_of(DistinctFolders, 1)), 1)
// NOISE CUT - uncomment to alert only on the staging shape (few dest folders,
// many files) rather than all high-volume writes. Biggest single lever.
//| where FilesPerFolder >= ConcentrationHint or NetworkPathHits > 0 or OtherDriveHits > 0
| extend BurstShape = case(
      FilesPerFolder >= ConcentrationHint, "Concentrated (staging-like)",
      DistinctFolders >= 50,               "Dispersed (mass-write / encryption-like)",
      "Mixed")
| extend Destination = case(
      OtherDriveHits  > 0, "SecondaryOrRemovableDrive",
      NetworkPathHits > 0, "RemoteShare",
      "LocalSystemDrive")
| extend AlertSeverity = case(
      OtherDriveHits > 0 or NetworkPathHits > 0, "High",
      "Medium")
| project
    WindowStart, WindowEnd,
    Actor,
    InitiatingProcessAccountName, InitiatingProcessAccountDomain,
    DeviceName, DeviceId,
    FilesCreated, DistinctFiles, DistinctFolders,
    FilesPerFolder, FilesPerMin, BurstSeconds, TotalMB,
    BurstShape, Destination, AlertSeverity,
    NetworkPathHits, OtherDriveHits, RemoteSession, InboundSmbHits,
    FirstEvent, LastEvent,
    InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessFolderPath,
    InitiatingProcessParentFileName, InitiatingProcessCommandLine,
    SampleFile, SampleFolder,
    FileSample, FolderSample, Processes, OriginUrls, Labels
