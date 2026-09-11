//=====================================================================
// SIMULATION HARNESS: staging-then-archiving correlation
// Retrospective backtest. NOT an analytics rule. Do not deploy as-is.
//=====================================================================

// ---------- Simulation controls ----------
let Lookback                = 7d;      // backtest period
let SimBucket               = 30m;     // simulated rule frequency

// ---------- Detection tunables (ALL environment-specific) ----------
let StagingWindow           = 30m;     // how far back from an archive we look
let StagingFileThreshold    = 200;     // min distinct staged files
let MaxDestinationFolders   = 5;       // staging concentration
let ArchiveMinSizeBytes     = 0;       // 0 = size gate DISABLED (see caveats)

let DocExtensions = dynamic([
    "doc","docx","docm","dot","dotx","xls","xlsx","xlsm","xlsb",
    "ppt","pptx","pptm","pdf","csv","txt","rtf","odt","ods","odp",
    "msg","eml","one","vsd","vsdx"
]);

let ArchiveExtensions = dynamic([
    "zip","zipx","7z","rar","tar","gz","tgz","bz2","xz","cab","iso","arj","lzh"
]);

// ---------- YOUR EXCLUSIONS — populate these ----------
// Lowercase. Leave empty to run unfiltered for baselining (recommended first pass).
let ExcludedInitiatingProcesses = dynamic([]);  // e.g. "onedrive.exe","backupagent.exe"
let ExcludedFolderPathFragments = dynamic([]);  // substring match, e.g. "\\appdata\\local\\packages\\"
let ExcludedAccountSids         = dynamic([]);  // service account SIDs
let ExcludedDeviceNames         = dynamic([]);  // known-noisy hosts, file servers

// ---------- Structural exclusion: unpack, not stage ----------
// Files created BY an archiver are decompression output, not staging.
// NOTE: explorer.exe deliberately omitted — see caveats before adding it.
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
    | where FileName has_any (ArchiveExtensions)               // cheap prefilter
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (ArchiveExtensions)                         // exact match
    | extend AccountSid = tostring(InitiatingProcessAccountSid)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | where AccountSid !in (ExcludedAccountSids)
    | where DeviceName !in~ (ExcludedDeviceNames)
    | where ArchiveMinSizeBytes == 0 or tolong(FileSize) >= ArchiveMinSizeBytes
    | project ArchiveTime = TimeGenerated, DeviceId, DeviceName, AccountSid,
              AccountUpn            = InitiatingProcessAccountUpn,
              ArchiveName           = FileName,
              ArchiveFolder         = FolderPath,
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

// ---------- BLOCK 3: candidate staging events ----------
let StagingEvents =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | where FileName has_any (DocExtensions)                   // cheap prefilter
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (DocExtensions)
    | extend AccountSid = tostring(InitiatingProcessAccountSid),
             InitProc   = tolower(InitiatingProcessFileName)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | where InitProc !in (DecompressionProcesses)
    | where InitProc !in (ExcludedInitiatingProcesses)
    | where array_length(ExcludedFolderPathFragments) == 0
         or not(tolower(FolderPath) has_any (ExcludedFolderPathFragments))
    | project StageTime    = TimeGenerated,
              DeviceId, AccountSid,
              StageFolder  = FolderPath,
              StagePath    = strcat(FolderPath, "\\", FileName),
              StageProcess = InitiatingProcessFileName,
              JoinBucket   = bin(TimeGenerated, StagingWindow);

// ---------- BLOCK 4: correlate, ordered ----------
let Correlated =
    ArchiveKeyed
    | join kind=inner hint.shufflekey=DeviceId (StagingEvents)
        on DeviceId, AccountSid, JoinBucket
    | where StageTime < ArchiveTime                            // strict ordering
    | where StageTime >= ArchiveTime - StagingWindow
    | extend SameTree = iff(
          tolower(ArchiveFolder) startswith tolower(StageFolder)
       or tolower(StageFolder)  startswith tolower(ArchiveFolder), 1, 0)
    | summarize StagedFileCount       = count_distinct(StagePath),
                StagingFolderCount    = count_distinct(StageFolder),
                StagingFolderSample   = make_set(StageFolder, 5),
                StagingProcessSample  = make_set(StageProcess, 5),
                FirstStagedFile       = min(StageTime),
                LastStagedFile        = max(StageTime),
                ArchiveInStagingTree  = max(SameTree)
        by ArchiveTime, DeviceId, DeviceName, AccountSid, AccountUpn,
           ArchiveName, ArchiveFolder, ArchiveSizeBytes, ArchiveAction,
           ArchiveProcess, ArchiveProcessCmdLine, ArchiveSha256
    | extend StagingDurationMin  = round(datetime_diff('second', LastStagedFile, FirstStagedFile) / 60.0, 1),
             GapToArchiveSeconds = datetime_diff('second', ArchiveTime, LastStagedFile),
             ArchiveSizeMB       = round(ArchiveSizeBytes / 1048576.0, 1);

// ---------- BLOCK 5: OUTPUT — noise profile per simulated run ----------
Correlated
| where StagedFileCount    >= StagingFileThreshold
| where StagingFolderCount <= MaxDestinationFolders
| summarize AlertRows       = count(),
            DistinctDevices = dcount(DeviceId),
            DistinctAccounts= dcount(AccountSid),
            SampleDevice    = any(DeviceName)
    by SimulatedRunWindow = bin(ArchiveTime, SimBucket)
| order by SimulatedRunWindow asc
