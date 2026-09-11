//=====================================================================
// MERGED HARNESS — staging + archiving, unusual on either side
// 7-day backtest. NOT an analytics rule.
// Fires when: staging in unusual location OR archiving in unusual location
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

// Normal user-document locations. Used on BOTH sides now — staging in
// these is "normal location", archiving into these is "normal destination".
let UserDocRegex = @"(?i)C:\\Users\\[^\\]+\\(Documents|Downloads|Desktop|OneDrive - ORG NAME HERE|OneDrive - ORG NAME|ORG NAME)(\\|$)";

//---------------------------------------------------------------------
// BLOCK 1 — Archive anchors. Location is now a FLAG, not a filter.
//---------------------------------------------------------------------
let ArchiveAnchors =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (ArchiveExtensions)
    | where InitiatingProcessFileName in~ (ArchiverProcesses)
    | where ArchiveMinSizeBytes == 0 or tolong(FileSize) >= ArchiveMinSizeBytes
    // OneDrive "download as zip" multipart extraction — noise, stays a filter
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
    | extend ArchiveUnusual = iff(FolderPath matches regex UserDocRegex, 0, 1)
    | project ArchiveTime      = TimeGenerated,
              DeviceId, DeviceName, AccountSid,
              AccountUpn       = InitiatingProcessAccountUpn,
              ArchiveName      = FileName,
              ArchiveFolderNorm, ArchiveUnusual,
              ArchiveSizeBytes = tolong(FileSize),
              ArchiveSha256    = SHA256,
              ArchiveProcess   = InitiatingProcessFileName,
              ArchiveCmdLine   = InitiatingProcessCommandLine;

let ArchiveKeyed =
    ArchiveAnchors
    | mv-expand JoinBucket = pack_array(
          bin(ArchiveTime, StagingWindow),
          bin(ArchiveTime, StagingWindow) - StagingWindow
      ) to typeof(datetime);

//---------------------------------------------------------------------
// BLOCK 2 — Staging. App-specific exclusions stay as FILTERS.
// User-doc location becomes a FLAG.
//---------------------------------------------------------------------
let StagingEvents =
    DeviceFileEvents
    | where TimeGenerated between (ago(Lookback) .. now())
    | where ActionType == "FileCreated"
    | extend Ext = tolower(extract(@"\.([A-Za-z0-9]{1,8})$", 1, FileName))
    | where Ext in (DocExtensions)
    | extend InitProc = tolower(InitiatingProcessFileName)
    | where InitProc !in (DecompressionProcesses)
    | where FolderPath startswith "C:\\"
    | where not(FolderPath startswith "C:\\$Recycle.Bin")
    // --- Application noise exclusions (keep as filters) ---
    | where not(FolderPath has @"\appdata\local\microsoft\windows\inetcache"
            and InitiatingProcessFileName in~ ("outlook.exe","winword.exe","msedge.exe"))
    | where not(FolderPath has @"\appdata\local\temp\scrub"
            and InitiatingProcessFileName =~ "outlook.exe")
    | where not(FolderPath has @"\appdata\local\microsoft\capture\logs"
            and InitiatingProcessFileName =~ "capture.exe")
    | where not(FolderPath startswith "C:\\programdata\\APPNAME3\\APP NAME FOLDER.NAME"
            and InitiatingProcessFileName =~ "APP.NAME3.SERVICE.app.exe")
    | where not(FolderPath matches regex @"(?i)C:\\Users\\[^\\]+\\FOLDER NAME1(\\|$)"
            and InitiatingProcessFileName =~ "APPNAME2.exe")
    | where not((FolderPath matches regex @"(?i)C:\\Users\\[^\\]+\\APPNAME1(\\|$)"
                 or FolderPath startswith "C:\\Temp\\")
            and InitiatingProcessFileName =~ "APPNAME1.exe")
    | where not(FolderPath startswith "C:\\programdata\\templateupdates"
            and InitiatingProcessFileName =~ "powershell.exe")
    | where not(InitiatingProcessFileName in~ ("explorer.exe","onedrive.exe")
            and FolderPath has @"\appdata\local\temp\"
            and FolderPath matches regex @"\.zip\.[0-9a-f]{3}\\")
    | extend AccountSid = tostring(InitiatingProcessAccountSid)
    | where isnotempty(DeviceId) and isnotempty(AccountSid)
    | extend StageFolderNorm = tolower(iff(
          tolower(FolderPath) endswith tolower(FileName),
          substring(FolderPath, 0, strlen(FolderPath) - strlen(FileName) - 1),
          FolderPath))
    | extend StageFolderNorm = trim_end(@"\\+", StageFolderNorm)
    | extend StageUnusual = iff(FolderPath matches regex UserDocRegex, 0, 1)
    | project StageTime    = TimeGenerated,
              DeviceId, AccountSid,
              StagePath    = FolderPath,
              StageFolderNorm, StageUnusual,
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
    | summarize StagedFileCount       = count_distinct(StagePath),
                StagedUnusualCount    = count_distinctif(StagePath, StageUnusual == 1),
                StagingFolderCount    = count_distinct(StageFolderNorm),
                StagingFolders        = make_set(StageFolderNorm, 5),
                StagingUnusualFolders = make_setif(StageFolderNorm, StageUnusual == 1, 5),
                StagingProcesses      = make_set(StageProcess, 5),
                StagingExtensions     = make_set(StageExt, 6),
                FirstStagedFile       = min(StageTime),
                LastStagedFile        = max(StageTime),
                ArchiveUnderStaging   = max(ArchiveUnderStaging),
                StagingUnderArchive   = max(StagingUnderArchive)
        by ArchiveTime, DeviceId, DeviceName, AccountSid, AccountUpn,
           ArchiveName, ArchiveFolderNorm, ArchiveUnusual, ArchiveSizeBytes,
           ArchiveSha256, ArchiveProcess, ArchiveCmdLine;

//---------------------------------------------------------------------
// BLOCK 4 — Union of both rules. Nothing looser.
//---------------------------------------------------------------------
let Alerts =
    Correlated
    // Branch A (forward): enough files staged in UNUSUAL locations
    // Branch B (reverse): enough files staged ANYWHERE + archive unusual
    | where StagedUnusualCount >= StagingFileThreshold
         or (ArchiveUnusual == 1 and StagedFileCount >= StagingFileThreshold)
    | extend MatchReason = case(
          StagedUnusualCount >= StagingFileThreshold and ArchiveUnusual == 1, "Both",
          StagedUnusualCount >= StagingFileThreshold,                         "StagingUnusual",
                                                                              "ArchiveUnusual");

//---------------------------------------------------------------------
// BLOCK 5 — VOLUME. Swap for the views below.
//---------------------------------------------------------------------
Alerts
| summarize MatchReasons = make_set(MatchReason)
    by DeviceId, DeviceName, AccountSid, AccountUpn, RunWindow = bin(ArchiveTime, 30m)
| summarize DedupedAlerts = count(), Devices = dcount(DeviceId), Accounts = dcount(AccountSid)
