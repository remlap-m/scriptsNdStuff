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
let MaxRoots       = 2;                        // PRIMARY NOISE GATE - see notes
let ConcentrationHint = 50.0;                  // files-per-folder = staging-like
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
// Destination tree root. Staging converges on one root even when it preserves
// subfolder structure; sync clients and backup agents scatter across many.
// VERIFY the slice depths against your own paths - see notes below.
| extend PathParts = split(DirPath, @"\")
| extend DestRoot  = case(
      DirPath startswith @"\\" and array_length(PathParts) > 4,
          strcat_array(array_slice(PathParts, 0, 4), @"\"),   // \\server\share\top
      array_length(PathParts) > 3,
          strcat_array(array_slice(PathParts, 0, 3), @"\"),   // C:\Users\john\Desktop
      DirPath)
| extend Off = Offsets
| mv-expand Off to typeof(long)
| extend WindowStart = bin(Timestamp - Off * 1m, Bucket) + Off * 1m
| summarize
    FilesCreated    = count(),
    DistinctFiles   = dcount(strcat(DirPath, "|", FileName)),
    DistinctFolders = dcount(DirPath),
    DistinctRoots   = dcount(DestRoot),
    RootSample      = make_set(DestRoot, 5),
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
// --- concentration gate: the main noise reduction ---
| where DistinctRoots <= MaxRoots
| where IngestLast > ago(Liveness)
| summarize arg_max(FilesCreated, *) by Actor, DeviceId
| extend WindowEnd      = WindowStart + Bucket
| extend BurstSeconds   = datetime_diff('second', LastEvent, FirstEvent)
| extend FilesPerMin    = round(todouble(FilesCreated) / max_of(todouble(BurstSeconds) / 60.0, 0.5), 1)
| extend TotalMB        = round(todouble(TotalBytes) / 1048576.0, 1)
| extend FilesPerFolder = round(todouble(FilesCreated) / todouble(max_of(DistinctFolders, 1)), 1)
| extend BurstShape = case(
      DistinctFolders <= 3,                "Flat (single-folder staging)",
      FilesPerFolder >= ConcentrationHint, "Concentrated",
      "Tree copy (structure preserved)")
| extend Destination = case(
      OtherDriveHits  > 0, "SecondaryOrRemovableDrive",
      NetworkPathHits > 0, "RemoteShare",
      "LocalSystemDrive")
| extend AlertSeverity = case(
      OtherDriveHits > 0 or NetworkPathHits > 0, "High",
      "Medium")
| project
    // triage-first ordering
    WindowStart,
    Actor,
    DeviceName,
    FilesCreated,
    DistinctRoots,
    RootSample,
    BurstShape,
    Destination,
    InitiatingProcessFileName,
    FilesPerFolder,
    DistinctFolders,
    DistinctFiles,
    TotalMB,
    FilesPerMin,
    BurstSeconds,
    AlertSeverity,
    // supporting detail
    WindowEnd,
    InitiatingProcessAccountName, InitiatingProcessAccountDomain,
    DeviceId,
    NetworkPathHits, OtherDriveHits, RemoteSession, InboundSmbHits,
    FirstEvent, LastEvent,
    InitiatingProcessSHA256, InitiatingProcessFolderPath,
    InitiatingProcessParentFileName, InitiatingProcessCommandLine,
    SampleFile, SampleFolder,
    FileSample, FolderSample, Processes, OriginUrls, Labels
