// =============================================================================
// Mass file creation in unusual location
// Table   : DeviceFileEvents (MDE via the Defender XDR connector)
// Platform: Microsoft Sentinel scheduled analytics rule
//
// Fires on: one account, on one device, creating >= 100 document-type files
//           within a 20-minute window, outside UNC/network share paths.
//
// REQUIRED RULE CONFIG:
//   Frequency     : 30 minutes
//   Lookup period : 90 minutes (or 60m if Skew confirmed as 0 in your environment)
// =============================================================================

// ---- window / scheduling maths ----------------------------------------------
let StepMin        = 5;
let BucketMin      = 20;
let Bucket         = BucketMin * 1m;
let Offsets        = range(0, BucketMin - StepMin, StepMin);   // 0,5,10,15
let Lookback       = 60m;
let Skew           = 30m;
let Liveness       = 35m;

// ---- thresholds -------------------------------------------------------------
let Threshold      = 100;

// ---- exclusions -------------------------------------------------------------
// Accounts: matched against Actor (lowercase UPN or DOMAIN\sam)
let ExcludedAccounts = dynamic([
    // "user@domain.com"
]);

// Processes: add known-noisy initiating process filenames here.
// Where possible, scope these by folder path in the query below rather than
// excluding the process globally - e.g. exclude Outlook only when writing to
// its known temp paths, not everywhere.
// Examples: "7zG.exe", "7zFM.exe", "curl.exe", "OUTLOOK.EXE"
let ExcludedProcesses = dynamic([
    // "example.exe"
]);

// File names: specific filenames to exclude regardless of location.
// Examples: "desktop.ini", "thumbs.db"
let ExcludedFileNames = dynamic([
    // "example.txt"
]);

// Folder paths: excluded via has_any (term-based, not anchored).
// Combine with process where possible to avoid over-exclusion.
// Examples: @"\AppData\Local\Microsoft\Outlook\", @"\Downloads\"
let ExcludedFolders = dynamic([
    // @"\ExampleFolder\"
]);

// ---- file types -------------------------------------------------------------
let InterestingExt = dynamic([
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
// --- primary location filter: exclude UNC/network share paths ----------------
| where not(FolderPath startswith @"\\")
| where not(FolderPath matches regex @"(?i)C:\\Users\\[^\\]+\\(Documents|Downloads|Desktop|OneDrive - ACE CLOUD TECHNOLOGIES)(\\|$)")
// --- cheap filters first -----------------------------------------------------
| where InitiatingProcessFileName !in~ (ExcludedProcesses)
| where FileName !in~ (ExcludedFileNames)
| where not(FolderPath has_any (ExcludedFolders))
| where not(FileName startswith "~$")
| where not(FileName startswith "PowerShell_transcript")
| where not(InitiatingProcessCommandLine has_any ("/systemstartup", "Quarantine"))
// --- extension derivation ----------------------------------------------------
// KQL does not support negative array indexing - split(FileName,".")[-1] returns null
| extend NameParts = split(FileName, ".")
| extend Ext       = tolower(tostring(NameParts[array_length(NameParts) - 1]))
| where array_length(NameParts) > 1
| where Ext in (InterestingExt)
// --- actor identity ----------------------------------------------------------
// Prefer UPN, fall back to DOMAIN\sam to avoid blind spots on local/non-hybrid accounts
| extend Actor = tolower(iff(isnotempty(InitiatingProcessAccountUpn),
                             InitiatingProcessAccountUpn,
                             strcat(InitiatingProcessAccountDomain, @"\", InitiatingProcessAccountName)))
| where isnotempty(Actor) and Actor != @"\"
| where Actor !endswith "$"
| where Actor !in~ (ExcludedAccounts)
| extend IngestAt = ingestion_time()
// Strip filename from FolderPath only when it actually contains it
| extend DirPath = iff(FolderPath endswith FileName,
                       tostring(parse_path(FolderPath).DirectoryPath),
                       FolderPath)
// --- sliding window grid: 4 overlapping 20m windows spaced 5m apart ----------
| extend Off = Offsets
| mv-expand Off to typeof(long)
| extend WindowStart = bin(Timestamp - Off * 1m, Bucket) + Off * 1m
| summarize
    FilesCreated    = count(),
    DistinctFiles   = dcount(strcat(DirPath, "|", FileName)),
    DistinctFolders = dcount(DirPath),
    TotalBytes      = sum(FileSize),
    OtherDriveHits  = countif(not(FolderPath startswith "C:\\")
                              and not(FolderPath startswith @"\\")),
    RemoteSession   = countif(IsInitiatingProcessRemoteSession == true),
    InboundSmbHits  = countif(isnotempty(ShareName)),
    DistinctExt     = dcount(Ext),
    FileSample      = make_set(FileName, 10),
    FolderSample    = make_set(DirPath, 10),
    ExtSample       = make_set(Ext, 10),
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
| where FilesCreated >= Threshold
| where IngestLast > ago(Liveness)
| summarize arg_max(FilesCreated, *) by Actor, DeviceId
| extend WindowEnd      = WindowStart + Bucket
| extend BurstSeconds   = datetime_diff('second', LastEvent, FirstEvent)
| extend FilesPerMin    = round(todouble(FilesCreated) / max_of(todouble(BurstSeconds) / 60.0, 0.5), 1)
| extend TotalMB        = round(todouble(TotalBytes) / 1048576.0, 1)
| extend FilesPerFolder = round(todouble(FilesCreated) / todouble(max_of(DistinctFolders, 1)), 1)
| extend OutsideHours   = hourofday(FirstEvent) < 8 or hourofday(FirstEvent) > 18
| extend Destination    = case(
      OtherDriveHits > 0, "SecondaryOrRemovableDrive",
      "LocalSystemDrive")
| project
    WindowStart, WindowEnd,
    Actor,
    DeviceName, DeviceId,
    InitiatingProcessAccountName, InitiatingProcessAccountDomain,
    FilesCreated, DistinctFiles, DistinctFolders, DistinctExt,
    FilesPerFolder, FilesPerMin, BurstSeconds, TotalMB,
    OutsideHours, Destination,
    OtherDriveHits, RemoteSession, InboundSmbHits,
    FirstEvent, LastEvent,
    InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessFolderPath,
    InitiatingProcessParentFileName, InitiatingProcessCommandLine,
    SampleFile, SampleFolder,
    FileSample, FolderSample, ExtSample, Processes, OriginUrls, Labels



















    HUNT VERSION



    // =============================================================================
// HUNTING VERSION - Mass file creation in unusual location
// Same logic as the detection rule, but:
//   - Lookback extended to 7 days
//   - Liveness gate removed (no dedup against previous runs)
//   - Final arg_max dedup removed (shows every qualifying window)
//   - TimeGenerated/Skew filter simplified
// Not suitable for deployment as a scheduled rule.
// =============================================================================

let StepMin        = 5;
let BucketMin      = 20;
let Bucket         = BucketMin * 1m;
let Offsets        = range(0, BucketMin - StepMin, StepMin);   // 0,5,10,15
let Lookback       = 7d;
let Threshold      = 100;

let ExcludedAccounts = dynamic([
    // "user@domain.com"
]);
let ExcludedProcesses = dynamic([
    // "example.exe"
]);
let ExcludedFileNames = dynamic([
    // "example.txt"
]);
let ExcludedFolders = dynamic([
    // @"\ExampleFolder\"
]);
let InterestingExt = dynamic([
    "doc", "docx", "docm", "dot", "dotx",
    "xls", "xlsx", "xlsm", "ppt", "pptx",
    "pdf", "msg", "eml", "rtf", "txt", "csv",
    "zip", "7z", "rar", "pst", "ost"
]);

DeviceFileEvents
| where TimeGenerated > ago(Lookback)
| where ActionType == "FileCreated"
| where isnotempty(FileName)
| where not(FolderPath startswith @"\\")
| where not(FolderPath matches regex @"(?i)C:\\Users\\[^\\]+\\(Documents|Downloads|Desktop|OneDrive - TENANTNAME)(\\|$)")
| where InitiatingProcessFileName !in~ (ExcludedProcesses)
| where FileName !in~ (ExcludedFileNames)
| where not(FolderPath has_any (ExcludedFolders))
| where not(FileName startswith "~$")
| where not(FileName startswith "PowerShell_transcript")
| where not(InitiatingProcessCommandLine has_any ("/systemstartup", "Quarantine"))
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
    DistinctExt     = dcount(Ext),
    TotalBytes      = sum(FileSize),
    OtherDriveHits  = countif(not(FolderPath startswith "C:\\")
                              and not(FolderPath startswith @"\\")),
    RemoteSession   = countif(IsInitiatingProcessRemoteSession == true),
    FileSample      = make_set(FileName, 10),
    FolderSample    = make_set(DirPath, 10),
    ExtSample       = make_set(Ext, 10),
    Processes       = make_set(InitiatingProcessFileName, 5),
    OriginUrls      = make_set(FileOriginUrl, 5),
    Labels          = make_set(SensitivityLabel, 5),
    FirstEvent      = min(Timestamp),
    LastEvent       = max(Timestamp),
    take_any(DeviceName,
             InitiatingProcessFileName,
             InitiatingProcessFolderPath,
             InitiatingProcessCommandLine)
  by Actor, DeviceId, WindowStart
| where FilesCreated >= Threshold
| extend WindowEnd      = WindowStart + Bucket
| extend BurstSeconds   = datetime_diff('second', LastEvent, FirstEvent)
| extend FilesPerMin    = round(todouble(FilesCreated) / max_of(todouble(BurstSeconds) / 60.0, 0.5), 1)
| extend TotalMB        = round(todouble(TotalBytes) / 1048576.0, 1)
| extend FilesPerFolder = round(todouble(FilesCreated) / todouble(max_of(DistinctFolders, 1)), 1)
| project
    WindowStart, WindowEnd,
    Actor, DeviceName,
    FilesCreated, DistinctFolders, DistinctExt, FilesPerFolder,
    InitiatingProcessFileName,
    FolderSample, ExtSample, Processes,
    DistinctFiles, TotalMB, FilesPerMin, BurstSeconds,
    OtherDriveHits, RemoteSession,
    FirstEvent, LastEvent,
    FileSample, OriginUrls, Labels,
    InitiatingProcessFolderPath, InitiatingProcessCommandLine,
    DeviceId
| order by FilesCreated desc




| where not(FolderPath matches regex @"(?i)\\AppData\\Local\\Temp\\\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?\\")
