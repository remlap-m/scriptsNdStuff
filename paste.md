//=====================================================================
// SIMULATION HARNESS v2 — FolderPath normalisation applied
// Retrospective backtest. NOT an analytics rule.
//=====================================================================

let Lookback                = 7d;
let SimBucket               = 30m;
let StagingWindow           = 30m;
let StagingFileThreshold    = 200;   // TUNE — see distribution output first
let ArchiveMinSizeBytes     = 0;     // size gate disabled

let DocExtensions = dynamic([
    "doc","docx","docm","dot","dotx","xls","xlsx","xlsm","xlsb",
    "ppt","pptx","pptm","pdf","csv","txt","rtf","odt","ods","odp",
    "msg","eml","one","vsd","vsdx"
]);
let ArchiveExtensions = dynamic([
    "zip","zipx","7z","rar","tar","gz","tgz","bz2","xz","cab","iso","arj","lzh"
]);

// ---------- YOUR EXCLUSIONS — populate these ----------
// Lowercase. Leave empty for the first baselining pass.
let ExcludedInitiatingProcesses = dynamic([]);  // e.g. "onedrive.exe"
let ExcludedFolderPathFragments = dynamic([]);  // substring, e.g. "\\appdata\\local\\packages\\"
let ExcludedAccountSids         = dynamic([]);
let ExcludedDeviceNames         = dynamic([]);

let DecompressionProcesses = dynamic([
    "7z.exe","7zg.exe","7zfm.exe","7za.exe","winrar.exe","rar.exe","unrar.exe",
    "tar.exe","peazip.exe","bandizip.exe","wzzip.exe","winzip32.exe","winzip64.exe",
    "zip.exe","unzip.exe"
]);

// ---------- BLOCK 1: archive anchors ----------
let ArchiveAnchors =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType in ("FileCreated", "FileRenamed")
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (ArchiveExtensions)
    | extend AccountSid = tostring(InitiatingProcessAccountSid)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | where AccountSid !in (ExcludedAccountSids)
    | where DeviceName !in~ (ExcludedDeviceNames)
    | where ArchiveMinSizeBytes == 0 or tolong(FileSize) >= ArchiveMinSizeBytes
    // normalise: strip filename if present, then trailing separators
    | extend ArchiveFolderNorm = tolower(iff(
          tolower(FolderPath) endswith tolower(FileName),
          substring(FolderPath, 0, strlen(FolderPath) - strlen(FileName) - 1),
          FolderPath))
    | extend ArchiveFolderNorm = trim_end(@"\\+", ArchiveFolderNorm)
    | project ArchiveTime = TimeGenerated, DeviceId, DeviceName, AccountSid,
              AccountUpn            = InitiatingProcessAccountUpn,
              ArchiveName           = FileName,
              ArchiveFullPath       = FolderPath,
              ArchiveFolderNorm,
              ArchiveSizeBytes      = tolong(FileSize),
              ArchiveAction         = ActionType,
              ArchiveProcess        = InitiatingProcessFileName,
              ArchiveProcessCmdLine = InitiatingProcessCommandLine,
              ArchiveSha256         = SHA256;

// ---------- BLOCK 2: bucket keys to bound the join ----------
let ArchiveKeyed =
    ArchiveAnchors
    | mv-expand JoinBucket = pack_array(
          bin(ArchiveTime, StagingWindow),
          bin(ArchiveTime, StagingWindow) - StagingWindow
      ) to typeof(datetime);

// ---------- BLOCK 3: staging candidates ----------
let StagingEvents =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (DocExtensions)
    | extend AccountSid = tostring(InitiatingProcessAccountSid),
             InitProc   = tolower(InitiatingProcessFileName)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | where InitProc !in (DecompressionProcesses)
    | where InitProc !in (ExcludedInitiatingProcesses)
    | where array_length(ExcludedFolderPathFragments) == 0
         or not(tolower(FolderPath) has_any (ExcludedFolderPathFragments))
    | extend StageFolderNorm = tolower(iff(
          tolower(FolderPath) endswith tolower(FileName),
          substring(FolderPath, 0, strlen(FolderPath) - strlen(FileName) - 1),
          FolderPath))
    | extend StageFolderNorm = trim_end(@"\\+", StageFolderNorm)
    | project StageTime    = TimeGenerated,
              DeviceId, AccountSid,
              StageFolderNorm,
              StagePath    = FolderPath,        // already unique per file
              StageProcess = InitiatingProcessFileName,
              JoinBucket   = bin(TimeGenerated, StagingWindow);

// ---------- BLOCK 4: correlate, ordered ----------
let Correlated =
    ArchiveKeyed
    | join kind=inner hint.shufflekey=DeviceId (StagingEvents)
        on DeviceId, AccountSid, JoinBucket
    | where StageTime < ArchiveTime
    | where StageTime >= ArchiveTime - StagingWindow
    | extend SameTree = iff(
          ArchiveFolderNorm startswith StageFolderNorm
       or StageFolderNorm  startswith ArchiveFolderNorm, 1, 0)
    | summarize StagedFileCount      = count_distinct(StagePath),
                StagingFolderCount   = count_distinct(StageFolderNorm),
                StagingFolderSample  = make_set(StageFolderNorm, 5),
                StagingProcessSample = make_set(StageProcess, 5),
                FirstStagedFile      = min(StageTime),
                LastStagedFile       = max(StageTime),
                ArchiveInStagingTree = max(SameTree)
        by ArchiveTime, DeviceId, DeviceName, AccountSid, AccountUpn,
           ArchiveName, ArchiveFullPath, ArchiveFolderNorm, ArchiveSizeBytes,
           ArchiveAction, ArchiveProcess, ArchiveProcessCmdLine, ArchiveSha256
    | extend FilesPerFolder      = round(StagedFileCount * 1.0 / StagingFolderCount, 1),
             StagingDurationMin  = round(datetime_diff('second', LastStagedFile, FirstStagedFile) / 60.0, 1),
             GapToArchiveSeconds = datetime_diff('second', ArchiveTime, LastStagedFile),
             ArchiveSizeMB       = round(ArchiveSizeBytes / 1048576.0, 1);

// ---------- BLOCK 5: distribution — RUN THIS FIRST ----------
Correlated
| summarize CorrelatedPairs = count(),
            Devices         = dcount(DeviceId),
            MaxStaged       = max(StagedFileCount),
            P99Staged       = percentile(StagedFileCount, 99),
            P95Staged       = percentile(StagedFileCount, 95),
            P50Staged       = percentile(StagedFileCount, 50),
            MinFolders      = min(StagingFolderCount),
            P50Ratio        = percentile(FilesPerFolder, 50),
            MaxRatio        = max(FilesPerFolder),
            Over50          = countif(StagedFileCount >= 50),
            Over100         = countif(StagedFileCount >= 100),
            Over200         = countif(StagedFileCount >= 200),
            Over500         = countif(StagedFileCount >= 500)




Correlated
| where StagedFileCount >= StagingFileThreshold
| summarize AlertRows        = count(),
            DistinctDevices  = dcount(DeviceId),
            DistinctAccounts = dcount(AccountSid)
    by SimulatedRunWindow = bin(ArchiveTime, SimBucket)
| order by SimulatedRunWindow asc




Correlated
| where StagedFileCount >= StagingFileThreshold
| project ArchiveTime, DeviceName, AccountUpn, ArchiveName, ArchiveFolderNorm,
          ArchiveSizeMB, ArchiveAction, ArchiveProcess, StagedFileCount,
          StagingFolderCount, FilesPerFolder, StagingFolderSample,
          StagingProcessSample, StagingDurationMin, GapToArchiveSeconds,
          ArchiveInStagingTree, ArchiveProcessCmdLine
| order by ArchiveTime desc



let Deduped = Correlated
    | where StagedFileCount >= 100
    | summarize ArchivesInWindow = count(),
                MaxStaged        = max(StagedFileCount),
                TopArchiveProc   = tolower(any(ArchiveProcess))
        by DeviceId, DeviceName, AccountSid, AccountUpn,
           RunWindow = bin(ArchiveTime, 30m);
Deduped
| summarize Alerts       = count(),
            Devices      = dcount(DeviceId),
            Accounts     = dcount(AccountSid),
            MaxStaged    = max(MaxStaged),
            SampleDevice = any(DeviceName),
            SampleUser   = any(AccountUpn)
    by ArchiveProcess = TopArchiveProc
| order by Alerts desc
| extend RunningTotal = row_cumsum(Alerts)




Correlated
| where StagedFileCount >= 100
| mv-expand StagingProcessSample to typeof(string)
| summarize Rows       = count(),
            Devices    = dcount(DeviceId),
            Accounts   = dcount(AccountSid),
            MaxStaged  = max(StagedFileCount),
            SampleArc  = any(ArchiveName),
            SampleFldr = any(ArchiveFolderNorm)
    by StagingProcess = tolower(tostring(StagingProcessSample)),
       ArchiveProcess = tolower(ArchiveProcess)
| order by Rows desc
| take 30








DeviceFileEvents
| where TimeGenerated > ago(7d)
| where ActionType in ("FileCreated","FileRenamed")
| extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
| where Ext in ("zip","7z","rar","zipx")
| extend SizeBucket = case(
      isempty(FileSize), "null",
      tolong(FileSize) == 0, "zero",
      tolong(FileSize) < 1048576, "under 1MB",
      tolong(FileSize) < 52428800, "1-50MB",
      tolong(FileSize) < 262144000, "50-250MB",
      "250MB+")
| summarize Events = count() by SizeBucket, ActionType
| order by Events desc






DeviceFileEvents
| where TimeGenerated > ago(7d)
| where ActionType == "FileCreated"
| extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
| where Ext in ("zip","7z","rar","zipx")
| where tolong(FileSize) between (52428800 .. 262144000)
| summarize Events = count(),
            Devices = dcount(DeviceId),
            DistinctFiles = dcount(strcat(DeviceId, "|", FolderPath))
| extend EventsPerFile = round(Events * 1.0 / DistinctFiles, 1)





























            //=====================================================================
// VIABILITY TEST — staging followed by archiving
// Backtest only. NOT an analytics rule. No exclusions applied.
// Returns 3 numbers: DedupedAlerts / Devices / Accounts
//=====================================================================

let Lookback             = 7d;
let StagingWindow        = 30m;
let StagingFileThreshold = 100;
let ArchiveMinSizeBytes  = 0;

let DocExtensions = dynamic([
    "doc","docx","docm","dot","dotx","xls","xlsx","xlsm","xlsb",
    "ppt","pptx","pptm","pdf","csv","txt","rtf","odt","ods","odp",
    "msg","eml","one","vsd","vsdx"
]);
let ArchiveExtensions = dynamic([
    "zip","zipx","7z","rar","tar","gz","tgz","bz2","xz","cab","iso","arj","lzh"
]);
let ArchiverProcesses = dynamic([
    "7z.exe","7zg.exe","7zfm.exe","7za.exe","winrar.exe","rar.exe",
    "peazip.exe","bandizip.exe","wzzip.exe","winzip32.exe","winzip64.exe",
    "tar.exe","zip.exe","makecab.exe","explorer.exe",
    "powershell.exe","pwsh.exe","cmd.exe","python.exe","wscript.exe","cscript.exe"
]);
let DecompressionProcesses = dynamic([
    "7z.exe","7zg.exe","7zfm.exe","7za.exe","winrar.exe","rar.exe","unrar.exe",
    "tar.exe","peazip.exe","bandizip.exe","wzzip.exe","winzip32.exe","winzip64.exe",
    "zip.exe","unzip.exe"
]);
// ---- Exclusions: populate later, leave empty for baseline ----
let ExcludedInitiatingProcesses = dynamic([]);
let ExcludedFolderPathFragments = dynamic([]);
let ExcludedAccountSids         = dynamic([]);
let ExcludedDeviceNames         = dynamic([]);

let ArchiveAnchors =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (ArchiveExtensions)
    | where tolower(InitiatingProcessFileName) in (ArchiverProcesses)
    | extend AccountSid = tostring(InitiatingProcessAccountSid)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | where AccountSid !in (ExcludedAccountSids)
    | where DeviceName !in~ (ExcludedDeviceNames)
    | where ArchiveMinSizeBytes == 0 or tolong(FileSize) >= ArchiveMinSizeBytes
    | project ArchiveTime = TimeGenerated, DeviceId, DeviceName, AccountSid,
              AccountUpn     = InitiatingProcessAccountUpn,
              ArchiveName    = FileName,
              ArchiveProcess = InitiatingProcessFileName;

let ArchiveKeyed =
    ArchiveAnchors
    | mv-expand JoinBucket = pack_array(
          bin(ArchiveTime, StagingWindow),
          bin(ArchiveTime, StagingWindow) - StagingWindow
      ) to typeof(datetime);

let StagingEvents =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (DocExtensions)
    | extend AccountSid = tostring(InitiatingProcessAccountSid),
             InitProc   = tolower(InitiatingProcessFileName)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | where InitProc !in (DecompressionProcesses)
    | where InitProc !in (ExcludedInitiatingProcesses)
    | where array_length(ExcludedFolderPathFragments) == 0
         or not(tolower(FolderPath) has_any (ExcludedFolderPathFragments))
    | project StageTime  = TimeGenerated,
              DeviceId, AccountSid,
              StagePath  = FolderPath,
              JoinBucket = bin(TimeGenerated, StagingWindow);

let Correlated =
    ArchiveKeyed
    | join kind=inner hint.shufflekey=DeviceId (StagingEvents)
        on DeviceId, AccountSid, JoinBucket
    | where StageTime < ArchiveTime
    | where StageTime >= ArchiveTime - StagingWindow
    | summarize StagedFileCount = count_distinct(StagePath)
        by ArchiveTime, DeviceId, DeviceName, AccountSid, AccountUpn,
           ArchiveName, ArchiveProcess;

Correlated
| where StagedFileCount >= StagingFileThreshold
| summarize MaxStaged = max(StagedFileCount)
    by DeviceId, DeviceName, AccountSid, AccountUpn,
       RunWindow = bin(ArchiveTime, 30m)
| summarize DedupedAlerts = count(),
            Devices       = dcount(DeviceId),
            Accounts      = dcount(AccountSid)








Correlated
| where StagedFileCount >= StagingFileThreshold
| summarize MaxStaged = max(StagedFileCount)
    by DeviceId, DeviceName, AccountSid, AccountUpn,
       ArchiveProcess = tolower(ArchiveProcess),
       RunWindow = bin(ArchiveTime, 30m)
| summarize Alerts = count(), Devices = dcount(DeviceId), Accounts = dcount(AccountSid)
    by ArchiveProcess
| order by Alerts desc


















//=====================================================================
// ALERT PREVIEW — staging followed by archiving
// One row = one incident. 7-day backtest, 30-min windows.
// NOT an analytics rule. No exclusions applied.
//=====================================================================

let Lookback             = 7d;
let StagingWindow        = 30m;
let StagingFileThreshold = 100;
let ArchiveMinSizeBytes  = 0;

let DocExtensions = dynamic([
    "doc","docx","docm","dot","dotx","xls","xlsx","xlsm","xlsb",
    "ppt","pptx","pptm","pdf","csv","txt","rtf","odt","ods","odp",
    "msg","eml","one","vsd","vsdx"
]);
let ArchiveExtensions = dynamic([
    "zip","zipx","7z","rar","tar","gz","tgz","bz2","xz","cab","iso","arj","lzh"
]);
let ArchiverProcesses = dynamic([
    "7z.exe","7zg.exe","7zfm.exe","7za.exe","winrar.exe","rar.exe",
    "peazip.exe","bandizip.exe","wzzip.exe","winzip32.exe","winzip64.exe",
    "tar.exe","zip.exe","makecab.exe","explorer.exe",
    "powershell.exe","pwsh.exe","cmd.exe","python.exe","wscript.exe","cscript.exe"
]);
let DecompressionProcesses = dynamic([
    "7z.exe","7zg.exe","7zfm.exe","7za.exe","winrar.exe","rar.exe","unrar.exe",
    "tar.exe","peazip.exe","bandizip.exe","wzzip.exe","winzip32.exe","winzip64.exe",
    "zip.exe","unzip.exe"
]);
// ---- Exclusions: populate
