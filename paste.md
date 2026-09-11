let ArchiveExtensions = dynamic(["zip","zipx","7z","rar","tar","gz","tgz","bz2","xz","cab","iso","arj","lzh"]);
let ArchiverProcesses = dynamic([
    "7z.exe","7zg.exe","7zfm.exe","7za.exe","winrar.exe","rar.exe",
    "peazip.exe","bandizip.exe","wzzip.exe","winzip32.exe","winzip64.exe",
    "tar.exe","zip.exe","makecab.exe","explorer.exe",
    "powershell.exe","pwsh.exe","cmd.exe","python.exe","wscript.exe","cscript.exe"]);
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where ActionType == "FileCreated"
| extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
| where Ext in (ArchiveExtensions)
| where InitiatingProcessFileName in~ (ArchiverProcesses)
| where tolong(FileSize) >= 10485760
| extend FolderNorm = tolower(iff(
      tolower(FolderPath) endswith tolower(FileName),
      substring(FolderPath, 0, strlen(FolderPath) - strlen(FileName) - 1),
      FolderPath))
// generalise user paths so they aggregate
| extend PathClass = replace_regex(FolderNorm, @"^c:\\users\\[^\\]+\\", @"c:\users\<user>\")
| summarize Events = count(), Devices = dcount(DeviceId), Accounts = dcount(InitiatingProcessAccountSid)
    by PathClass, InitiatingProcessFileName
| order by Events desc
| take 50






//=====================================================================
// REVERSE VARIANT HARNESS — staging anywhere, archiving in odd location
// 7-day backtest. NOT an analytics rule. No archive-location exclusions.
//=====================================================================

let Lookback             = 7d;
let StagingWindow        = 30m;
let StagingFileThreshold = 100;
let ArchiveMinSizeBytes  = 10485760;   // 10 MB

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

// ---- Archive-location allow-list: POPULATE FROM THE BASELINE QUERY ----
// Leave empty for the first pass. Use <user> placeholder form, e.g.
//   @"c:\users\<user>\documents", @"c:\users\<user>\downloads"
let NormalArchiveLocations = dynamic([]);

//---------------------------------------------------------------------
// BLOCK 1 — Archive anchors. Location constraint lives HERE now.
//---------------------------------------------------------------------
let ArchiveAnchors =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (ArchiveExtensions)
    | where InitiatingProcessFileName in~ (ArchiverProcesses)
    | where ArchiveMinSizeBytes == 0 or tolong(FileSize) >= ArchiveMinSizeBytes
    // OneDrive "download as zip" multipart extraction — keep this one
    | where not(InitiatingProcessFileName in~ ("explorer.exe","onedrive.exe")
            and FolderPath has @"\appdata\local\temp\"
            and FolderPath matches regex @"\.zip\.[0-9a-f]{3}\\")
    | extend AccountSid = tostring(InitiatingProcessAccountSid)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | extend ArchiveFolderNorm = tolower(iff(
          tolower(FolderPath) endswith tolower(FileName),
          substring(FolderPath, 0, strlen(FolderPath) - strlen(FileName) - 1),
          FolderPath))
    | extend ArchiveFolderNorm = trim_end(@"\\+", ArchiveFolderNorm)
    // generalised form for allow-list matching across users
    | extend ArchivePathClass = replace_regex(ArchiveFolderNorm, @"^c:\\users\\[^\\]+\\", @"c:\users\<user>\")
    | where array_length(NormalArchiveLocations) == 0
         or not(ArchivePathClass has_any (NormalArchiveLocations))
    | project ArchiveTime      = TimeGenerated,
              DeviceId, DeviceName, AccountSid,
              AccountUpn       = InitiatingProcessAccountUpn,
              ArchiveName      = FileName,
              ArchiveFolderNorm, ArchivePathClass,
              ArchiveSizeBytes = tolong(FileSize),
              ArchiveProcess   = InitiatingProcessFileName,
              ArchiveCmdLine   = InitiatingProcessCommandLine;

let ArchiveKeyed =
    ArchiveAnchors
    | mv-expand JoinBucket = pack_array(
          bin(ArchiveTime, StagingWindow),
          bin(ArchiveTime, StagingWindow) - StagingWindow
      ) to typeof(datetime);

//---------------------------------------------------------------------
// BLOCK 2 — Staging. NO path exclusions: staging anywhere counts.
//---------------------------------------------------------------------
let StagingEvents =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (DocExtensions)
    | extend InitProc = tolower(InitiatingProcessFileName)
    | where InitProc !in (DecompressionProcesses)
    | extend AccountSid = tostring(InitiatingProcessAccountSid)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | extend StageFolderNorm = tolower(iff(
          tolower(FolderPath) endswith tolower(FileName),
          substring(FolderPath, 0, strlen(FolderPath) - strlen(FileName) - 1),
          FolderPath))
    | extend StageFolderNorm = trim_end(@"\\+", StageFolderNorm)
    | project StageTime    = TimeGenerated,
              DeviceId, AccountSid,
              StagePath    = FolderPath,
              StageFolderNorm,
              StageProcess = InitiatingProcessFileName,
              StageExt     = Ext,
              JoinBucket   = bin(TimeGenerated, StagingWindow);

//---------------------------------------------------------------------
// BLOCK 3 — Correlate
//---------------------------------------------------------------------
let Correlated =
    ArchiveKeyed
    | join kind=inner hint.shufflekey=DeviceId (StagingEvents)
        on DeviceId, AccountSid, JoinBucket
    | where StageTime < ArchiveTime
    | where StageTime >= ArchiveTime - StagingWindow
    | extend ArchiveUnderStaging = iff(ArchiveFolderNorm startswith StageFolderNorm, 1, 0),
             StagingUnderArchive = iff(StageFolderNorm startswith ArchiveFolderNorm, 1, 0)
    | summarize StagedFileCount      = count_distinct(StagePath),
                StagingFolderCount   = count_distinct(StageFolderNorm),
                StagingFolders       = make_set(StageFolderNorm, 5),
                StagingProcesses     = make_set(StageProcess, 5),
                StagingExtensions    = make_set(StageExt, 6),
                FirstStagedFile      = min(StageTime),
                LastStagedFile       = max(StageTime),
                ArchiveUnderStaging  = max(ArchiveUnderStaging),
                StagingUnderArchive  = max(StagingUnderArchive)
        by ArchiveTime, DeviceId, DeviceName, AccountSid, AccountUpn,
           ArchiveName, ArchiveFolderNorm, ArchivePathClass, ArchiveSizeBytes,
           ArchiveProcess, ArchiveCmdLine;

//---------------------------------------------------------------------
// BLOCK 4 — VOLUME. Swap this out for the other views below.
//---------------------------------------------------------------------
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
    by DeviceId, AccountSid, ArchivePathClass,
       ArchiveProcess = tolower(ArchiveProcess),
       RunWindow = bin(ArchiveTime, 30m)
| summarize Alerts = count(), Devices = dcount(DeviceId), Accounts = dcount(AccountSid)
    by ArchivePathClass, ArchiveProcess
| order by Alerts desc
| extend RunningTotal = row_cumsum(Alerts)





Correlated
| where StagedFileCount >= StagingFileThreshold
| summarize StagedFileCount    = max(StagedFileCount),
            StagingFolderCount = max(StagingFolderCount),
            StagingFolders     = take_any(StagingFolders),
            StagingProcesses   = take_any(StagingProcesses),
            ArchiveCount       = dcount(ArchiveName),
            ArchiveNames       = make_set(ArchiveName, 5),
            ArchiveFolders     = make_set(ArchiveFolderNorm, 3),
            ArchiveProcesses   = make_set(ArchiveProcess, 3),
            ArchiveCmdLines    = make_set(ArchiveCmdLine, 3),
            LargestArchiveMB   = round(max(ArchiveSizeBytes) / 1048576.0, 1),
            FirstArchive       = min(ArchiveTime),
            LastStagedFile     = max(LastStagedFile),
            StagingUnderArchive = max(StagingUnderArchive)
    by DeviceId, DeviceName, AccountSid, AccountUpn,
       RunWindow = bin(ArchiveTime, 30m)
| extend GapToArchiveSeconds = datetime_diff('second', FirstArchive, LastStagedFile)
| project RunWindow, DeviceName, AccountUpn, StagedFileCount, StagingFolderCount,
          StagingFolders   = tostring(StagingFolders),
          StagingProcesses = tostring(StagingProcesses),
          GapToArchiveSeconds, ArchiveCount, LargestArchiveMB,
          ArchiveFolders   = tostring(ArchiveFolders),
          ArchiveProcesses = tostring(ArchiveProcesses),
          ArchiveNames     = tostring(ArchiveNames),
          ArchiveCmdLines  = tostring(ArchiveCmdLines),
          StagingUnderArchive
| order by RunWindow desc









            
